package fbhttp

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// sessionCloseGrace is how long a session reported as closed by the browser
	// (tab closed) stays usable. A page reload also reports a close, so the
	// reloaded page gets this long to use the session again and cancel it.
	sessionCloseGrace = 15 * time.Second

	maxSessionBodySize = 4 << 10
)

// sessionRegistry tracks revoked sessions. A session is identified by the "sid"
// claim, which is kept across token renewals, so revoking it invalidates every
// token issued for that login. It lives in memory: a restart forgets it, and
// tokens without a "sid" claim cannot be revoked.
type sessionRegistry struct {
	mu      sync.Mutex
	revoked map[string]time.Time // sid -> when the entry can be forgotten
	closing map[string]closingSession
}

type closingSession struct {
	deadline time.Time
	forget   time.Time
}

var sessions = &sessionRegistry{
	revoked: map[string]time.Time{},
	closing: map[string]closingSession{},
}

func newSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// revoke invalidates the session immediately.
func (s *sessionRegistry) revoke(sid string, forget time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gc(time.Now())
	s.revoked[sid] = forget
	delete(s.closing, sid)
}

// scheduleClose invalidates the session at deadline unless cancelClose is
// called first.
func (s *sessionRegistry) scheduleClose(sid string, deadline, forget time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gc(time.Now())
	if _, ok := s.revoked[sid]; ok {
		return
	}
	s.closing[sid] = closingSession{deadline: deadline, forget: forget}
}

// cancelClose keeps a session that was scheduled to close alive. It is a no-op
// once the deadline has passed.
func (s *sessionRegistry) cancelClose(sid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.closing[sid]; ok && time.Now().Before(c.deadline) {
		delete(s.closing, sid)
	}
}

func (s *sessionRegistry) isRevoked(sid string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.gc(now)
	if _, ok := s.revoked[sid]; ok {
		return true
	}
	if c, ok := s.closing[sid]; ok && !now.Before(c.deadline) {
		s.revoked[sid] = c.forget
		delete(s.closing, sid)
		return true
	}
	return false
}

func (s *sessionRegistry) gc(now time.Time) {
	for sid, forget := range s.revoked {
		if now.After(forget) {
			delete(s.revoked, sid)
		}
	}
	for sid, c := range s.closing {
		if now.After(c.forget) {
			delete(s.closing, sid)
		}
	}
}

// sessionFromRequest returns the session of the token sent in the X-Auth header
// or, for navigator.sendBeacon which cannot set headers, in the request body.
// It reports false when there is no valid, unexpired token.
func sessionFromRequest(r *http.Request, d *data) (string, bool) {
	token := r.Header.Get("X-Auth")
	if token == "" && r.Body != nil {
		body, err := io.ReadAll(io.LimitReader(r.Body, maxSessionBodySize))
		if err != nil {
			return "", false
		}
		token = strings.TrimSpace(string(body))
	}
	if strings.Count(token, ".") != 2 {
		return "", false
	}

	var tk authToken
	p := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}), jwt.WithExpirationRequired())
	parsed, err := p.ParseWithClaims(token, &tk, func(_ *jwt.Token) (interface{}, error) {
		return d.settings.Key, nil
	})
	if err != nil || !parsed.Valid || tk.Session == "" {
		return "", false
	}

	return tk.Session, true
}

// logoutHandler revokes the caller's session right away.
func logoutHandler(tokenExpirationTime time.Duration) handleFunc {
	return func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		if sid, ok := sessionFromRequest(r, d); ok {
			sessions.revoke(sid, time.Now().Add(tokenExpirationTime+time.Hour))
		}
		w.WriteHeader(http.StatusNoContent)
		return 0, nil
	}
}

// sessionCloseHandler is called when the browser tab is going away. The
// session is revoked after sessionCloseGrace unless it is used again.
func sessionCloseHandler(tokenExpirationTime time.Duration) handleFunc {
	return func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		if sid, ok := sessionFromRequest(r, d); ok {
			now := time.Now()
			sessions.scheduleClose(sid, now.Add(sessionCloseGrace), now.Add(tokenExpirationTime+time.Hour))
		}
		w.WriteHeader(http.StatusNoContent)
		return 0, nil
	}
}
