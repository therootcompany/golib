package formmailer

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// captureStdout runs fn while capturing everything written to os.Stdout,
// returning the captured text.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	_ = w.Close()
	os.Stdout = orig
	return <-done
}

// runOnce starts a FormMailer with a context that expires quickly so Run
// returns immediately after selecting and logging its GeoIP mode. It must not
// require network (BlocklistRepo is empty) and binds an ephemeral port.
func runOnce(t *testing.T, fm *FormMailer) string {
	t.Helper()
	fm.ListenAddr = "127.0.0.1:0"
	fm.RefreshInterval = time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return captureStdout(t, func() {
		_ = fm.Run(ctx)
	})
}

// TestRunGeoModeSelection sanity-checks the hybrid GeoIP mode selection:
//   - conf present            -> download mode
//   - conf absent + populated -> poll mode
//   - conf absent + empty dir -> disabled
func TestRunGeoModeSelection(t *testing.T) {
	t.Run("download", func(t *testing.T) {
		dir := t.TempDir()
		conf := filepath.Join(dir, "GeoIP.conf")
		if err := os.WriteFile(conf, []byte(
			"AccountID   123456\nLicenseKey  testkey\nEditionIDs  GeoLite2-City GeoLite2-ASN\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		// 500 server so the owned download loop fails fast; the mode is
		// selected and logged before serving regardless.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "nope", http.StatusInternalServerError)
		}))
		defer srv.Close()

		out := runOnce(t, &FormMailer{
			CacheDir:      dir,
			GeoIPConfPath: conf,
			GeoIPBaseURL:  srv.URL,
			SMTPHost:      "localhost:25",
			SMTPFrom:      "a@example.com",
			SMTPTo:        []string{"b@example.com"},
		})
		if !strings.Contains(out, "GeoIP: download mode") {
			t.Fatalf("missing download mode line; stdout:\n%s", out)
		}
	})

	t.Run("poll", func(t *testing.T) {
		// Point HOME at a temp dir so the default conf discovery can't find a
		// real ~/.config/maxmind/GeoIP.conf.
		home := t.TempDir()
		t.Setenv("HOME", home)

		archive := filepath.Join(t.TempDir(), "maxmind")
		if err := os.MkdirAll(archive, 0o755); err != nil {
			t.Fatal(err)
		}
		// Any entry makes the dir "populated" -> poll mode.
		if err := os.WriteFile(filepath.Join(archive, "keep"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}

		out := runOnce(t, &FormMailer{
			CacheDir: home,
			GeoIPDir: archive,
			SMTPHost: "localhost:25",
			SMTPFrom: "a@example.com",
			SMTPTo:   []string{"b@example.com"},
		})
		if !strings.Contains(out, "GeoIP: poll mode") {
			t.Fatalf("missing poll mode line; stdout:\n%s", out)
		}
	})

	t.Run("disabled", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		empty := filepath.Join(home, "maxmind")
		if err := os.MkdirAll(empty, 0o755); err != nil {
			t.Fatal(err)
		}

		out := runOnce(t, &FormMailer{
			CacheDir: home,
			GeoIPDir: empty,
			SMTPHost: "localhost:25",
			SMTPFrom: "a@example.com",
			SMTPTo:   []string{"b@example.com"},
		})
		if strings.Contains(out, "GeoIP:") {
			t.Fatalf("expected GeoIP disabled; stdout:\n%s", out)
		}
	})
}
