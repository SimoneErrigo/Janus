package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/SimoneErrigo/Janus/backend/internal/config"
)

var tokenSecret []byte

const (
	sessionCookieName      = "janus_session"
	maxLoginLimiterEntries = 4096
)

type loginAttempt struct {
	windowStart time.Time
	failures    int
}

type loginLimiter struct {
	mu       sync.Mutex
	attempts map[string]loginAttempt
}

func init() {
	tokenSecret = make([]byte, 32)
	if _, err := rand.Read(tokenSecret); err != nil {
		panic("cannot initialize authentication secret: " + err.Error())
	}
}

type loginRequest struct {
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
}

type loginResponse struct {
	Token       string `json:"token"`
	DisplayName string `json:"display_name"`
}

type tokenPayload struct {
	Exp  int64  `json:"exp"`
	Name string `json:"name,omitempty"` // display name chosen at login
	ID   string `json:"id,omitempty"`   // short random token ID for session tracking
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientIP := requestClientIP(r)
	if retryAfter := s.loginLimiter.retryAfter(clientIP, time.Now()); retryAfter > 0 {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())+1))
		http.Error(w, "too many login attempts", http.StatusTooManyRequests)
		return
	}

	var req loginRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	cfg := config.Get()
	if subtle.ConstantTimeCompare([]byte(req.Password), []byte(cfg.TeamPassword)) != 1 {
		s.loginLimiter.failure(clientIP, time.Now())
		http.Error(w, "invalid password", http.StatusUnauthorized)
		return
	}
	s.loginLimiter.success(clientIP)

	// Sanitize display name: trim whitespace, cap at 32 chars, ASCII/UTF-8 only
	name := strings.TrimSpace(req.DisplayName)
	if utf8.RuneCountInString(name) > 32 {
		runes := []rune(name)
		name = string(runes[:32])
	}
	if name == "" {
		// Default to guest-XXXX so teammates can identify each other
		b := make([]byte, 2)
		if _, err := rand.Read(b); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		name = "guest-" + hex.EncodeToString(b)
	}

	token, err := generateTokenForUser(name, 24*time.Hour)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: token, Path: "/", MaxAge: int((24 * time.Hour).Seconds()),
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: requestIsHTTPS(r),
	})

	writeJSON(w, http.StatusOK, loginResponse{Token: token, DisplayName: name})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.sessionHub != nil {
		if payload, err := decodeTokenPayload(AuthTokenFromRequest(r)); err == nil {
			s.sessionHub.Remove(payload.ID)
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1,
		Expires: time.Unix(1, 0), HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Secure: requestIsHTTPS(r),
	})
	w.WriteHeader(http.StatusNoContent)
}

func generateTokenForUser(name string, duration time.Duration) (string, error) {
	idBytes := make([]byte, 8)
	if _, err := rand.Read(idBytes); err != nil {
		return "", err
	}
	payload := tokenPayload{
		Exp:  time.Now().Add(duration).Unix(),
		Name: name,
		ID:   hex.EncodeToString(idBytes),
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	mac := hmac.New(sha256.New, tokenSecret)
	mac.Write([]byte(payloadB64))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return payloadB64 + "." + sig, nil
}

// decodeTokenPayload decodes a token's payload WITHOUT signature verification.
// Only call this on already-validated tokens.
func decodeTokenPayload(token string) (tokenPayload, error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return tokenPayload{}, fmt.Errorf("invalid token format")
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return tokenPayload{}, err
	}
	var payload tokenPayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return tokenPayload{}, err
	}
	return payload, nil
}

// DisplayNameFromRequest returns the display name from the request's token.
// Returns "guest" when the token is absent or carries no name.
func DisplayNameFromRequest(r *http.Request) string {
	token := AuthTokenFromRequest(r)
	if token == "" {
		return "guest"
	}
	payload, err := decodeTokenPayload(token)
	if err != nil || payload.Name == "" {
		return "guest"
	}
	return payload.Name
}

func validateToken(token string) bool {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return false
	}

	// Verify signature
	mac := hmac.New(sha256.New, tokenSecret)
	mac.Write([]byte(parts[0]))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(parts[1]), []byte(expectedSig)) {
		return false
	}

	// Check expiration
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}

	var payload tokenPayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return false
	}

	return time.Now().Unix() < payload.Exp
}

// AuthTokenFromRequest returns a bearer token or the same-origin HttpOnly
// session cookie used by EventSource and browser downloads. Tokens are never
// accepted from URLs, where proxies and access logs could retain them.
func AuthTokenFromRequest(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	parts := strings.Fields(auth)
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		return parts[1]
	}
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		return cookie.Value
	}
	return ""
}

// authMiddleware protects routes by requiring a valid token.
// It also updates the session hub so active users are tracked.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := AuthTokenFromRequest(r)
		if token == "" {
			http.Error(w, "missing authorization", http.StatusUnauthorized)
			return
		}

		if !validateToken(token) {
			http.Error(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}

		// Heartbeat the session hub so active users are tracked
		if s.sessionHub != nil {
			if payload, err := decodeTokenPayload(token); err == nil && payload.ID != "" {
				s.sessionHub.Heartbeat(payload.ID, payload.Name)
			}
		}

		next.ServeHTTP(w, r)
	})
}

func remoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return host
	}
	return remoteAddr
}

func requestClientIP(r *http.Request) string {
	// The bundled nginx overwrites X-Real-IP with the actual browser peer. The
	// backend is not published by the standard Compose setup, so preferring this
	// single-hop value avoids rate-limiting every teammate as the nginx address.
	peer := remoteIP(r.RemoteAddr)
	peerIP := net.ParseIP(peer)
	if peerIP != nil && (peerIP.IsLoopback() || peerIP.IsPrivate()) {
		if forwarded := strings.TrimSpace(r.Header.Get("X-Real-IP")); net.ParseIP(forwarded) != nil {
			return forwarded
		}
	}
	return peer
}

func requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	proto := strings.TrimSpace(strings.SplitN(r.Header.Get("X-Forwarded-Proto"), ",", 2)[0])
	return strings.EqualFold(proto, "https")
}

func (l *loginLimiter) retryAfter(ip string, now time.Time) time.Duration {
	const window = time.Minute
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.attempts == nil {
		l.attempts = make(map[string]loginAttempt)
	}
	attempt := l.attempts[ip]
	if now.Sub(attempt.windowStart) >= window {
		delete(l.attempts, ip)
		return 0
	}
	if attempt.failures >= 10 {
		return window - now.Sub(attempt.windowStart)
	}
	return 0
}

func (l *loginLimiter) failure(ip string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.attempts == nil {
		l.attempts = make(map[string]loginAttempt)
	}
	attempt, exists := l.attempts[ip]
	if !exists && len(l.attempts) >= maxLoginLimiterEntries {
		// Evict one arbitrary entry in expected O(1). Exact LRU behavior adds no
		// security value here and would let spoofed IP churn force O(n) scans.
		for key := range l.attempts {
			delete(l.attempts, key)
			break
		}
	}
	if attempt.windowStart.IsZero() || now.Sub(attempt.windowStart) >= time.Minute {
		attempt = loginAttempt{windowStart: now}
	}
	attempt.failures++
	l.attempts[ip] = attempt
}

func (l *loginLimiter) success(ip string) {
	l.mu.Lock()
	delete(l.attempts, ip)
	l.mu.Unlock()
}
