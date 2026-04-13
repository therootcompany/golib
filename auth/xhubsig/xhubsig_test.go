package xhubsig

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var testSecret = "It's a Secret to Everybody"
var testBody = []byte("Hello, World!")

func TestSignSHA256(t *testing.T) {
	sig := Sign(SHA256, testSecret, testBody)
	expected := "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"
	if sig != expected {
		t.Errorf("Sign SHA256 = %q, want %q", sig, expected)
	}
}

func TestSignSHA1(t *testing.T) {
	mac := hmac.New(sha1.New, []byte(testSecret))
	mac.Write(testBody)
	want := "sha1=" + hex.EncodeToString(mac.Sum(nil))
	sig := Sign(SHA1, testSecret, testBody)
	if sig != want {
		t.Errorf("Sign SHA1 = %q, want %q", sig, want)
	}
}

func TestVerifySHA256(t *testing.T) {
	sig := Sign(SHA256, testSecret, testBody)
	if err := Verify(SHA256, testSecret, testBody, sig); err != nil {
		t.Errorf("Verify SHA256 should succeed: %v", err)
	}
	if err := Verify(SHA256, testSecret, testBody, "sha256=deadbeef"); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("Verify SHA256 with wrong sig = %v, want ErrInvalidSignature", err)
	}
	if err := Verify(SHA256, testSecret, testBody, ""); !errors.Is(err, ErrMissingSignature) {
		t.Errorf("Verify SHA256 with empty sig = %v, want ErrMissingSignature", err)
	}
}

func TestVerifySHA1(t *testing.T) {
	sig := Sign(SHA1, testSecret, testBody)
	if err := Verify(SHA1, testSecret, testBody, sig); err != nil {
		t.Errorf("Verify SHA1 should succeed: %v", err)
	}
	if err := Verify(SHA1, "wrong-secret", testBody, sig); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("Verify SHA1 with wrong secret = %v, want ErrInvalidSignature", err)
	}
}

func TestHashConstants(t *testing.T) {
	if SHA256.Header != "X-Hub-Signature-256" {
		t.Errorf("SHA256.Header = %q, want %q", SHA256.Header, "X-Hub-Signature-256")
	}
	if SHA256.Prefix != "sha256=" {
		t.Errorf("SHA256.Prefix = %q, want %q", SHA256.Prefix, "sha256=")
	}
	if SHA1.Header != "X-Hub-Signature" {
		t.Errorf("SHA1.Header = %q, want %q", SHA1.Header, "X-Hub-Signature")
	}
	if SHA1.Prefix != "sha1=" {
		t.Errorf("SHA1.Prefix = %q, want %q", SHA1.Prefix, "sha1=")
	}
}

func newSignedRequest(t *testing.T, body []byte, hashes ...Hash) *http.Request {
	t.Helper()
	r := httptest.NewRequest("POST", "/", bytes.NewReader(body))
	for _, h := range hashes {
		r.Header.Set(h.Header, Sign(h, testSecret, body))
	}
	return r
}

func TestNewDefaults(t *testing.T) {
	x := New(testSecret)
	if x.Secret != testSecret {
		t.Errorf("Secret = %q, want %q", x.Secret, testSecret)
	}
	if len(x.Hashes) != 1 || x.Hashes[0].Header != SHA256.Header {
		t.Errorf("Hashes = %v, want [SHA256]", x.Hashes)
	}
	if x.AcceptAny {
		t.Error("AcceptAny = true, want false")
	}
	if x.Limit != DefaultLimit {
		t.Errorf("Limit = %d, want %d", x.Limit, DefaultLimit)
	}
}

func TestRequireAllMustPass(t *testing.T) {
	called := false
	x := New(testSecret, SHA1, SHA256)
	handler := x.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("handler failed to read body: %v", err)
		}
		if string(body) != string(testBody) {
			t.Errorf("handler body = %q, want %q", body, testBody)
		}
		called = true
	}))

	r := newSignedRequest(t, testBody, SHA1, SHA256)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if !called {
		t.Error("handler should have been called when all headers present and valid")
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestRequireAllMissingOneHeader(t *testing.T) {
	x := New(testSecret, SHA1, SHA256)
	handler := x.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called when a header is missing")
	}))

	r := newSignedRequest(t, testBody, SHA256)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestRequireAllOneHeaderWrong(t *testing.T) {
	x := New(testSecret, SHA1, SHA256)
	handler := x.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called when a signature is wrong")
	}))

	r := newSignedRequest(t, testBody, SHA1, SHA256)
	r.Header.Set("X-Hub-Signature-256", "sha256=deadbeef")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestRequireAllNoHeaders(t *testing.T) {
	x := New(testSecret, SHA256)
	handler := x.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called without signature")
	}))

	r := httptest.NewRequest("POST", "/", bytes.NewReader(testBody))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/tab-separated-values" {
		t.Errorf("Content-Type = %q, want %q", ct, "text/tab-separated-values")
	}
	if !strings.Contains(w.Body.String(), "X-Hub-Signature-256") {
		t.Errorf("body = %q, want mention of expected header", w.Body.String())
	}
}

func TestRequireAllDefaultsSHA256(t *testing.T) {
	called := false
	x := New(testSecret)
	handler := x.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	r := newSignedRequest(t, testBody, SHA256)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if !called {
		t.Error("handler should have been called with default SHA256")
	}
}

func TestRequireAnyAtLeastOne(t *testing.T) {
	called := false
	x := New(testSecret, SHA1, SHA256)
	x.AcceptAny = true
	handler := x.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("handler failed to read body: %v", err)
		}
		if string(body) != string(testBody) {
			t.Errorf("handler body = %q, want %q", body, testBody)
		}
		called = true
	}))

	r := newSignedRequest(t, testBody, SHA256)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if !called {
		t.Error("handler should be called with only SHA256 header present and valid")
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestRequireAnyBothHeaders(t *testing.T) {
	called := false
	x := New(testSecret, SHA1, SHA256)
	x.AcceptAny = true
	handler := x.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	r := newSignedRequest(t, testBody, SHA1, SHA256)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if !called {
		t.Error("handler should have been called with both headers")
	}
}

func TestRequireAnyNoHeaders(t *testing.T) {
	x := New(testSecret, SHA256)
	x.AcceptAny = true
	handler := x.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called without any signature")
	}))

	r := httptest.NewRequest("POST", "/", bytes.NewReader(testBody))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestRequireAnyPresentButWrong(t *testing.T) {
	x := New(testSecret, SHA1, SHA256)
	x.AcceptAny = true
	handler := x.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called with wrong signature")
	}))

	r := httptest.NewRequest("POST", "/", bytes.NewReader(testBody))
	r.Header.Set("X-Hub-Signature-256", "sha256=deadbeef")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestRequireAnyPresentButWrongOtherValid(t *testing.T) {
	x := New(testSecret, SHA1, SHA256)
	x.AcceptAny = true
	handler := x.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called when one present header is wrong")
	}))

	r := newSignedRequest(t, testBody, SHA1)
	r.Header.Set("X-Hub-Signature-256", "sha256=deadbeef")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d — all present sigs must pass", w.Code, http.StatusUnauthorized)
	}
}

func TestRequireBodyReadable(t *testing.T) {
	x := New(testSecret, SHA256)
	handler := x.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read body: %v", err)
		}
		if !strings.Contains(string(body), "Hello") {
			t.Errorf("body = %q, want to contain 'Hello'", body)
		}
	}))

	r := newSignedRequest(t, testBody, SHA256)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
}

func TestNewLimitField(t *testing.T) {
	x := New(testSecret)
	if x.Limit != DefaultLimit {
		t.Errorf("Limit = %d, want %d", x.Limit, DefaultLimit)
	}
	x.Limit = 1 << 20
	if x.Limit != 1<<20 {
		t.Errorf("Limit = %d, want %d", x.Limit, 1<<20)
	}
}

func TestRequireBodyTooLarge(t *testing.T) {
	x := New(testSecret)
	x.Limit = 5
	handler := x.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called when body exceeds limit")
	}))

	bigBody := make([]byte, 100)
	r := httptest.NewRequest("POST", "/", bytes.NewReader(bigBody))
	r.Header.Set(SHA256.Header, Sign(SHA256, testSecret, bigBody))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want %d", w.Code, http.StatusRequestEntityTooLarge)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/tab-separated-values" {
		t.Errorf("Content-Type = %q, want %q", ct, "text/tab-separated-values")
	}
	if !strings.Contains(w.Body.String(), "error") {
		t.Errorf("body = %q, want JSON with 'error' key", w.Body.String())
	}
}

func TestErrorTextPlainForBrowser(t *testing.T) {
	x := New(testSecret)
	handler := x.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called without signature")
	}))

	r := httptest.NewRequest("POST", "/", bytes.NewReader(testBody))
	r.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/plain" {
		t.Errorf("Content-Type = %q, want %q", ct, "text/plain")
	}
	if !strings.Contains(w.Body.String(), "missing_signature") {
		t.Errorf("body = %q, want TSV with missing_signature", w.Body.String())
	}
}

func TestVerifyGitHubTestVector(t *testing.T) {
	sig256 := "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"
	if err := Verify(SHA256, testSecret, testBody, sig256); err != nil {
		t.Errorf("Verify should pass with GitHub's official test vector: %v", err)
	}

	mac := hmac.New(sha1.New, []byte(testSecret))
	mac.Write(testBody)
	sig1 := "sha1=" + hex.EncodeToString(mac.Sum(nil))
	if err := Verify(SHA1, testSecret, testBody, sig1); err != nil {
		t.Errorf("Verify should pass with SHA1 test vector: %v", err)
	}
}
