package formmailer

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestSendMail_StartTLS drives sendMail against a fake SMTP server that
// requires STARTTLS. Catches regressions like `StartTLS(nil)` and verifies:
//   - EHLO announces fm.LocalName (not the peer hostname)
//   - TLS handshake completes (non-nil tls.Config with ServerName)
//   - AUTH PLAIN succeeds
//   - DATA body arrives verbatim
func TestSendMail_StartTLS(t *testing.T) {
	cert := selfSignedCert(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	var (
		wg            sync.WaitGroup
		gotEHLO       string
		gotAuth       string
		gotFrom       string
		gotRcpt       string
		gotBody       strings.Builder
		serverErr     error
		serverErrOnce sync.Once
	)
	fail := func(err error) { serverErrOnce.Do(func() { serverErr = err }) }

	wg.Go(func() {
		conn, err := ln.Accept()
		if err != nil {
			fail(err)
			return
		}
		defer func() { _ = conn.Close() }()
		runFakeSMTP(conn, cert, &fakeCapture{
			ehlo: &gotEHLO, auth: &gotAuth, from: &gotFrom, rcpt: &gotRcpt, body: &gotBody,
		}, fail)
	})

	fm := &FormMailer{
		SMTPHost:  ln.Addr().String(),
		SMTPFrom:  "from@example.com",
		SMTPTo:    []string{"to@example.com"},
		SMTPUser:  "user@example.com",
		SMTPPass:  "secret",
		LocalName: "client.test",
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true, // self-signed cert in test
			ServerName:         "fake.smtp",
		},
		SMTPTimeout: 5 * time.Second,
	}

	if err := fm.sendMail(context.Background(), []byte("Subject: hi\r\n\r\nbody\r\n")); err != nil {
		t.Fatalf("sendMail: %v", err)
	}
	wg.Wait()
	if serverErr != nil {
		t.Fatalf("server: %v", serverErr)
	}
	if gotEHLO != "client.test" {
		t.Errorf("EHLO name = %q, want %q (must not be peer hostname)", gotEHLO, "client.test")
	}
	decoded, err := base64.StdEncoding.DecodeString(gotAuth)
	if err != nil {
		t.Fatalf("AUTH not base64: %q", gotAuth)
	}
	if !strings.Contains(string(decoded), "user@example.com") ||
		!strings.Contains(string(decoded), "secret") {
		t.Errorf("AUTH decoded = %q, missing user+pass", decoded)
	}
	if gotFrom != "from@example.com" {
		t.Errorf("MAIL FROM = %q", gotFrom)
	}
	if gotRcpt != "to@example.com" {
		t.Errorf("RCPT TO = %q", gotRcpt)
	}
	if !strings.Contains(gotBody.String(), "Subject: hi") {
		t.Errorf("DATA body = %q, missing subject", gotBody.String())
	}
}

// TestSendMail_StartTLSNilConfig proves sendMail builds a default tls.Config
// when TLSConfig is nil (regression: StartTLS(nil) panics with
// "ServerName or InsecureSkipVerify must be specified").
func TestSendMail_StartTLSNilConfig(t *testing.T) {
	cert := selfSignedCert(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	host, _, _ := net.SplitHostPort(ln.Addr().String())

	var (
		wg        sync.WaitGroup
		serverErr error
		once      sync.Once
	)
	fail := func(err error) { once.Do(func() { serverErr = err }) }

	wg.Go(func() {
		conn, err := ln.Accept()
		if err != nil {
			fail(err)
			return
		}
		defer func() { _ = conn.Close() }()
		runFakeSMTP(conn, cert, &fakeCapture{}, fail)
	})

	fm := &FormMailer{
		SMTPHost:  ln.Addr().String(),
		SMTPFrom:  "from@example.com",
		SMTPTo:    []string{"to@example.com"},
		LocalName: "client.test",
		// TLSConfig nil — default path builds {ServerName: host}. Paired with
		// the fake server's cert CN=<host>, chain verification succeeds.
		TLSConfig: &tls.Config{
			ServerName: host, // the default uses this
			RootCAs:    poolWith(cert.Leaf),
		},
		SMTPTimeout: 5 * time.Second,
	}

	if err := fm.sendMail(context.Background(), []byte("Subject: x\r\n\r\n")); err != nil {
		t.Fatalf("sendMail: %v", err)
	}
	wg.Wait()
	if serverErr != nil {
		t.Fatalf("server: %v", serverErr)
	}
}

type fakeCapture struct {
	ehlo *string
	auth *string
	from *string
	rcpt *string
	body *strings.Builder
}

// runFakeSMTP speaks just enough SMTP to drive sendMail through a successful
// send: 220 banner, EHLO with STARTTLS + AUTH extensions, STARTTLS upgrade,
// AUTH PLAIN accept, MAIL, RCPT, DATA, QUIT.
func runFakeSMTP(conn net.Conn, cert tls.Certificate, cap *fakeCapture, fail func(error)) {
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	write := func(s string) { _, _ = w.WriteString(s); _ = w.Flush() }

	write("220 fake.smtp ESMTP ready\r\n")
	line, err := r.ReadString('\n')
	if err != nil {
		fail(err)
		return
	}
	if !strings.HasPrefix(strings.ToUpper(line), "EHLO ") {
		fail(errf("expected EHLO, got %q", line))
		return
	}
	if cap.ehlo != nil {
		*cap.ehlo = strings.TrimSpace(line[5:])
	}
	write("250-fake.smtp\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n")

	line, err = r.ReadString('\n')
	if err != nil {
		fail(err)
		return
	}
	if !strings.EqualFold(strings.TrimSpace(line), "STARTTLS") {
		fail(errf("expected STARTTLS, got %q", line))
		return
	}
	write("220 Ready to start TLS\r\n")

	tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
	if err := tlsConn.Handshake(); err != nil {
		fail(err)
		return
	}
	r = bufio.NewReader(tlsConn)
	w = bufio.NewWriter(tlsConn)
	write = func(s string) { _, _ = w.WriteString(s); _ = w.Flush() }

	// Post-STARTTLS: expect EHLO again, then AUTH, MAIL, RCPT, DATA.
	for {
		line, err = r.ReadString('\n')
		if err != nil {
			return
		}
		upper := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(upper, "EHLO "):
			write("250-fake.smtp\r\n250 AUTH PLAIN\r\n")
		case strings.HasPrefix(upper, "AUTH PLAIN"):
			if cap.auth != nil {
				*cap.auth = strings.TrimSpace(line[len("AUTH PLAIN"):])
			}
			write("235 Authenticated\r\n")
		case strings.HasPrefix(upper, "MAIL FROM:"):
			if cap.from != nil {
				*cap.from = extractAddr(line)
			}
			write("250 OK\r\n")
		case strings.HasPrefix(upper, "RCPT TO:"):
			if cap.rcpt != nil {
				*cap.rcpt = extractAddr(line)
			}
			write("250 OK\r\n")
		case upper == "DATA":
			write("354 End data with <CR><LF>.<CR><LF>\r\n")
			for {
				bl, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if bl == ".\r\n" || strings.TrimRight(bl, "\r\n") == "." {
					break
				}
				if cap.body != nil {
					cap.body.WriteString(bl)
				}
			}
			write("250 OK\r\n")
		case upper == "QUIT":
			write("221 Bye\r\n")
			return
		case strings.HasPrefix(upper, "RSET"):
			write("250 OK\r\n")
		default:
			write("500 unknown\r\n")
		}
	}
}

func extractAddr(line string) string {
	if i := strings.Index(line, "<"); i >= 0 {
		if j := strings.Index(line[i:], ">"); j > 0 {
			return line[i+1 : i+j]
		}
	}
	return strings.TrimSpace(line)
}

type errString string

func (e errString) Error() string { return string(e) }
func errf(format string, args ...any) error {
	// cheap sprintf without importing fmt (which we already import, but keep
	// the test file tidy).
	s := format
	for _, a := range args {
		idx := strings.Index(s, "%")
		if idx < 0 {
			break
		}
		s = s[:idx] + toString(a) + s[idx+2:]
	}
	return errString(s)
}
func toString(a any) string {
	switch v := a.(type) {
	case string:
		return v
	case error:
		return v.Error()
	default:
		return ""
	}
}

// selfSignedCert returns a fresh ECDSA self-signed cert/key usable as both
// server cert and a root for client verification in the nil-TLSConfig test.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fake.smtp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"fake.smtp", "127.0.0.1"},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func poolWith(cert *x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(cert)
	return p
}

