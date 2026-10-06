package fbhttp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/storage"
	"github.com/filebrowser/filebrowser/v2/users"
)

func signSessionToken(t *testing.T, sid string, key []byte) string {
	t.Helper()
	claims := &authToken{
		User:    userInfo{ID: 1, Username: "u"},
		Session: sid,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-time.Minute)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return signed
}

func sessionTestStorage(t *testing.T, key []byte) *storage.Storage {
	t.Helper()
	return scopedUserStorage(t, t.TempDir(), users.Permissions{Download: true}, key)
}

// callProtected sends token through a withUser-protected handler.
func callProtected(st *storage.Storage, server *settings.Server, token string) int {
	protected := withUser(func(_ http.ResponseWriter, _ *http.Request, _ *data) (int, error) {
		return 0, nil
	})
	req, _ := http.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("X-Auth", token)
	rec := httptest.NewRecorder()
	handle(protected, "", st, server).ServeHTTP(rec, req)
	return rec.Code
}

func TestLogoutRevokesSession(t *testing.T) {
	key := []byte("test-signing-key")
	st := sessionTestStorage(t, key)
	server := &settings.Server{Root: t.TempDir()}
	token := signSessionToken(t, "logout-sid", key)

	if code := callProtected(st, server, token); code != http.StatusOK {
		t.Fatalf("before logout: expected 200, got %d", code)
	}

	req, _ := http.NewRequest(http.MethodPost, "/logout", http.NoBody)
	req.Header.Set("X-Auth", token)
	rec := httptest.NewRecorder()
	handle(logoutHandler(time.Hour), "", st, server).ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("logout: expected 204, got %d", rec.Code)
	}

	if code := callProtected(st, server, token); code != http.StatusUnauthorized {
		t.Fatalf("REVOCATION BROKEN: token still valid after logout, got %d", code)
	}
}

func TestLogoutRevokesRenewedTokens(t *testing.T) {
	key := []byte("test-signing-key")
	st := sessionTestStorage(t, key)
	server := &settings.Server{Root: t.TempDir()}
	oldToken := signSessionToken(t, "renew-sid", key)

	req, _ := http.NewRequest(http.MethodPost, "/renew", http.NoBody)
	req.Header.Set("X-Auth", oldToken)
	rec := httptest.NewRecorder()
	handle(renewHandler(time.Hour), "", st, server).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("renew: expected 200, got %d", rec.Code)
	}
	newToken := rec.Body.String()

	var tk authToken
	if _, err := jwt.ParseWithClaims(newToken, &tk, func(_ *jwt.Token) (interface{}, error) { return key, nil }); err != nil {
		t.Fatalf("renewed token invalid: %v", err)
	}
	if tk.Session != "renew-sid" {
		t.Fatalf("renewal must keep the session, got %q", tk.Session)
	}

	sessions.revoke("renew-sid", time.Now().Add(time.Hour))
	for name, token := range map[string]string{"old": oldToken, "renewed": newToken} {
		if code := callProtected(st, server, token); code != http.StatusUnauthorized {
			t.Fatalf("%s token still valid after revoking the session, got %d", name, code)
		}
	}
}

func TestLoginIssuesSession(t *testing.T) {
	key := []byte("test-signing-key")
	st := sessionTestStorage(t, key)
	server := &settings.Server{Root: t.TempDir()}

	// A token with no session (older tokens) is renewed into one with a session.
	req, _ := http.NewRequest(http.MethodPost, "/renew", http.NoBody)
	req.Header.Set("X-Auth", signSessionToken(t, "", key))
	rec := httptest.NewRecorder()
	handle(renewHandler(time.Hour), "", st, server).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("renew: expected 200, got %d", rec.Code)
	}
	var tk authToken
	if _, err := jwt.ParseWithClaims(rec.Body.String(), &tk, func(_ *jwt.Token) (interface{}, error) { return key, nil }); err != nil {
		t.Fatalf("renewed token invalid: %v", err)
	}
	if tk.Session == "" {
		t.Fatal("expected renewed token to carry a session")
	}
}

func TestSessionWithoutIDKeepsWorking(t *testing.T) {
	key := []byte("test-signing-key")
	st := sessionTestStorage(t, key)
	server := &settings.Server{Root: t.TempDir()}

	if code := callProtected(st, server, signToken(t, users.Permissions{Download: true}, key)); code != http.StatusOK {
		t.Fatalf("token without a session: expected 200, got %d", code)
	}
}

func TestSessionCloseWaitsForGrace(t *testing.T) {
	key := []byte("test-signing-key")
	st := sessionTestStorage(t, key)
	server := &settings.Server{Root: t.TempDir()}
	token := signSessionToken(t, "close-sid", key)

	// Beacons cannot set headers, so the token travels in the body.
	req, _ := http.NewRequest(http.MethodPost, "/session/close", strings.NewReader(token))
	rec := httptest.NewRecorder()
	handle(sessionCloseHandler(time.Hour), "", st, server).ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("close: expected 204, got %d", rec.Code)
	}

	// Still usable inside the grace period (a page reload), and using it
	// cancels the pending close.
	if code := callProtected(st, server, token); code != http.StatusOK {
		t.Fatalf("within grace: expected 200, got %d", code)
	}
	sessions.mu.Lock()
	_, pending := sessions.closing["close-sid"]
	sessions.mu.Unlock()
	if pending {
		t.Fatal("using the session within the grace period must cancel the close")
	}
}

func TestSessionCloseRevokesAfterGrace(t *testing.T) {
	key := []byte("test-signing-key")
	st := sessionTestStorage(t, key)
	server := &settings.Server{Root: t.TempDir()}
	token := signSessionToken(t, "expired-close-sid", key)

	sessions.scheduleClose("expired-close-sid", time.Now().Add(-time.Second), time.Now().Add(time.Hour))

	if code := callProtected(st, server, token); code != http.StatusUnauthorized {
		t.Fatalf("CLOSE NOT ENFORCED: session usable after its grace period, got %d", code)
	}
}

func TestSessionEndpointsIgnoreGarbage(t *testing.T) {
	key := []byte("test-signing-key")
	st := sessionTestStorage(t, key)
	server := &settings.Server{Root: t.TempDir()}

	for name, h := range map[string]handleFunc{
		"logout": logoutHandler(time.Hour),
		"close":  sessionCloseHandler(time.Hour),
	} {
		req, _ := http.NewRequest(http.MethodPost, "/x", io.NopCloser(strings.NewReader("not.a.token")))
		rec := httptest.NewRecorder()
		handle(h, "", st, server).ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("%s with garbage: expected 204, got %d", name, rec.Code)
		}
	}

	// A token signed with another key must not revoke anyone's session.
	forged := signSessionToken(t, "victim-sid", []byte("attacker-key"))
	req, _ := http.NewRequest(http.MethodPost, "/logout", http.NoBody)
	req.Header.Set("X-Auth", forged)
	handle(logoutHandler(time.Hour), "", st, server).ServeHTTP(httptest.NewRecorder(), req)
	if code := callProtected(st, server, signSessionToken(t, "victim-sid", key)); code != http.StatusOK {
		t.Fatalf("forged logout revoked a real session, got %d", code)
	}
}
