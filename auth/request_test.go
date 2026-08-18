package auth_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/therootcompany/golib/auth"
)

var errRejected = errors.New("authentication rejected")

// mockPrinciple is a simple BasicPrinciple for testing.
type mockPrinciple struct {
	id string
}

func (m mockPrinciple) ID() string            { return m.id }
func (m mockPrinciple) Permissions() []string { return nil }

// mockAuthenticator records the last credentials it received and returns a
// configurable result. If fail is true, Authenticate returns an error instead
// of a principle.
type mockAuthenticator struct {
	lastUser  string
	lastToken string
	calls     int
	principle auth.BasicPrinciple
	err       error
}

func (m *mockAuthenticator) Authenticate(username, token string) (auth.BasicPrinciple, error) {
	m.lastUser = username
	m.lastToken = token
	m.calls++
	return m.principle, m.err
}

func newRequest(method, target string) *http.Request {
	return httptest.NewRequest(method, target, nil)
}

// --- Tier 1: Must have ---

// TestAuthenticate_TokenCookie verifies that a cookie value is extracted and
// passed to the authenticator as ("", value).
func TestAuthenticate_TokenCookie(t *testing.T) {
	mock := &mockAuthenticator{principle: mockPrinciple{id: "user1"}}
	ra := &auth.BasicRequestAuthenticator{
		Authenticator: mock,
		TokenCookies:  []string{"session"},
	}
	r := newRequest("GET", "/")
	r.AddCookie(&http.Cookie{Name: "session", Value: "abc123"})

	p, err := ra.Authenticate(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.calls != 1 {
		t.Fatalf("expected 1 call, got %d", mock.calls)
	}
	if mock.lastUser != "" {
		t.Errorf("expected empty username, got %q", mock.lastUser)
	}
	if mock.lastToken != "abc123" {
		t.Errorf("expected token %q, got %q", "abc123", mock.lastToken)
	}
	if p.ID() != "user1" {
		t.Errorf("expected principle ID %q, got %q", "user1", p.ID())
	}
}

// TestAuthenticate_NoCredentials verifies that a request with no credentials
// returns ErrNoCredentials.
func TestAuthenticate_NoCredentials(t *testing.T) {
	mock := &mockAuthenticator{}
	ra := &auth.BasicRequestAuthenticator{
		Authenticator: mock,
		TokenCookies:  []string{"session"},
	}
	r := newRequest("GET", "/")

	_, err := ra.Authenticate(r)
	if err != auth.ErrNoCredentials {
		t.Fatalf("expected ErrNoCredentials, got %v", err)
	}
	if mock.calls != 0 {
		t.Fatalf("expected 0 calls to authenticator, got %d", mock.calls)
	}
}

// TestAuthenticate_EmptyCookieValueSkipped verifies that a cookie with an empty
// value is not treated as a credential.
func TestAuthenticate_EmptyCookieValueSkipped(t *testing.T) {
	mock := &mockAuthenticator{principle: mockPrinciple{id: "user1"}}
	ra := &auth.BasicRequestAuthenticator{
		Authenticator: mock,
		TokenCookies:  []string{"session"},
	}
	r := newRequest("GET", "/")
	r.AddCookie(&http.Cookie{Name: "session", Value: ""})

	_, err := ra.Authenticate(r)
	if err != auth.ErrNoCredentials {
		t.Fatalf("expected ErrNoCredentials for empty cookie, got %v", err)
	}
	if mock.calls != 0 {
		t.Fatalf("expected 0 calls to authenticator, got %d", mock.calls)
	}
}

// TestAuthenticate_CookiePriorityLowerThanBearer verifies that a Bearer token
// in the Authorization header takes priority over a cookie.
func TestAuthenticate_CookiePriorityLowerThanBearer(t *testing.T) {
	mock := &mockAuthenticator{principle: mockPrinciple{id: "user1"}}
	ra := &auth.BasicRequestAuthenticator{
		Authenticator:        mock,
		AuthorizationSchemes: []string{"Bearer"},
		TokenCookies:         []string{"session"},
	}
	r := newRequest("GET", "/")
	r.Header.Set("Authorization", "Bearer bearer-token")
	r.AddCookie(&http.Cookie{Name: "session", Value: "cookie-token"})

	_, err := ra.Authenticate(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.lastToken != "bearer-token" {
		t.Errorf("expected bearer token to win, got %q", mock.lastToken)
	}
}

// TestAuthenticate_TokenCookieErrorPropagates verifies that when the
// downstream authenticator rejects a cookie token, the error is returned
// to the caller rather than being swallowed.
func TestAuthenticate_TokenCookieErrorPropagates(t *testing.T) {
	mock := &mockAuthenticator{err: errRejected}
	ra := &auth.BasicRequestAuthenticator{
		Authenticator: mock,
		TokenCookies:  []string{"session"},
	}
	r := newRequest("GET", "/")
	r.AddCookie(&http.Cookie{Name: "session", Value: "abc123"})

	_, err := ra.Authenticate(r)
	if err != errRejected {
		t.Fatalf("expected errRejected, got %v", err)
	}
	if mock.calls != 1 {
		t.Fatalf("expected 1 call to authenticator, got %d", mock.calls)
	}
	if mock.lastToken != "abc123" {
		t.Errorf("expected token %q, got %q", "abc123", mock.lastToken)
	}
}

// --- Tier 2: Should have ---

// TestAuthenticate_SecondCookieUsedIfFirstAbsent verifies that the loop
// continues past a missing cookie to find a later one.
func TestAuthenticate_SecondCookieUsedIfFirstAbsent(t *testing.T) {
	mock := &mockAuthenticator{principle: mockPrinciple{id: "user1"}}
	ra := &auth.BasicRequestAuthenticator{
		Authenticator: mock,
		TokenCookies:  []string{"session", "id_token"},
	}
	r := newRequest("GET", "/")
	r.AddCookie(&http.Cookie{Name: "id_token", Value: "second-token"})

	_, err := ra.Authenticate(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.lastToken != "second-token" {
		t.Errorf("expected second cookie value %q, got %q", "second-token", mock.lastToken)
	}
}

// TestAuthenticate_CookiePriorityLowerThanQueryParam verifies that a query
// parameter token takes priority over a cookie (step 4 before step 5).
func TestAuthenticate_CookiePriorityLowerThanQueryParam(t *testing.T) {
	mock := &mockAuthenticator{principle: mockPrinciple{id: "user1"}}
	ra := &auth.BasicRequestAuthenticator{
		Authenticator:    mock,
		TokenQueryParams: []string{"access_token"},
		TokenCookies:     []string{"session"},
	}
	r := newRequest("GET", "/?access_token=param-token")
	r.AddCookie(&http.Cookie{Name: "session", Value: "cookie-token"})

	_, err := ra.Authenticate(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.lastToken != "param-token" {
		t.Errorf("expected query param token to win, got %q", mock.lastToken)
	}
}

// --- Tier 3: Broader coverage ---

// TestAuthenticate_BearerAnyScheme verifies that AuthorizationSchemes ["*"]
// accepts any scheme.
func TestAuthenticate_BearerAnyScheme(t *testing.T) {
	mock := &mockAuthenticator{principle: mockPrinciple{id: "user1"}}
	ra := &auth.BasicRequestAuthenticator{
		Authenticator:        mock,
		AuthorizationSchemes: []string{"*"},
	}
	r := newRequest("GET", "/")
	r.Header.Set("Authorization", "Custom abc123")

	_, err := ra.Authenticate(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.lastToken != "abc123" {
		t.Errorf("expected token %q, got %q", "abc123", mock.lastToken)
	}
}

// TestAuthenticate_UnacceptedSchemeReturnsError verifies that an Authorization
// header with an unaccepted scheme returns ErrNoCredentials rather than
// falling through to cookies. BasicAuth is enabled so that step 1 is exercised
// but does not match the Custom scheme.
func TestAuthenticate_UnacceptedSchemeReturnsError(t *testing.T) {
	mock := &mockAuthenticator{}
	ra := &auth.BasicRequestAuthenticator{
		Authenticator:        mock,
		BasicAuth:            true,
		AuthorizationSchemes: []string{"Bearer"},
		TokenCookies:         []string{"session"},
	}
	r := newRequest("GET", "/")
	r.Header.Set("Authorization", "Custom abc123")
	r.AddCookie(&http.Cookie{Name: "session", Value: "cookie-token"})

	_, err := ra.Authenticate(r)
	if err != auth.ErrNoCredentials {
		t.Fatalf("expected ErrNoCredentials for unaccepted scheme, got %v", err)
	}
	if mock.calls != 0 {
		t.Fatalf("expected 0 calls to authenticator (no fall-through), got %d", mock.calls)
	}
}

// TestAuthenticate_BasicAuthPriority verifies that Basic Auth (step 1) takes
// priority over cookie-based tokens (step 5).
func TestAuthenticate_BasicAuthPriority(t *testing.T) {
	mock := &mockAuthenticator{principle: mockPrinciple{id: "user1"}}
	ra := &auth.BasicRequestAuthenticator{
		Authenticator: mock,
		BasicAuth:     true,
		TokenCookies:  []string{"session"},
	}
	r := newRequest("GET", "/")
	r.SetBasicAuth("alice", "password")
	r.AddCookie(&http.Cookie{Name: "session", Value: "cookie-token"})

	_, err := ra.Authenticate(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.lastUser != "alice" {
		t.Errorf("expected username %q, got %q", "alice", mock.lastUser)
	}
	if mock.lastToken != "password" {
		t.Errorf("expected password %q, got %q", "password", mock.lastToken)
	}
}
