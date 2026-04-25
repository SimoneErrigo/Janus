package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/SimoneErrigo/Janus/backend/internal/config"
)

var tokenSecret []byte

func init() {
	tokenSecret = make([]byte, 32)
	rand.Read(tokenSecret)
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

	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	cfg := config.Get()
	if req.Password != cfg.TeamPassword {
		http.Error(w, "invalid password", http.StatusUnauthorized)
		return
	}

	// Sanitize display name: trim whitespace, cap at 32 chars, ASCII/UTF-8 only
	name := strings.TrimSpace(req.DisplayName)
	if utf8.RuneCountInString(name) > 32 {
		runes := []rune(name)
		name = string(runes[:32])
	}
	if name == "" {
		// Default to guest-XXXX so teammates can identify each other
		b := make([]byte, 2)
		rand.Read(b)
		name = "guest-" + hex.EncodeToString(b)
	}

	token, err := generateTokenForUser(name, 24*time.Hour)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, loginResponse{Token: token, DisplayName: name})
}

func generateTokenForUser(name string, duration time.Duration) (string, error) {
	idBytes := make([]byte, 4)
	rand.Read(idBytes)
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

// AuthTokenFromRequest returns a bearer token from the Authorization header or ?token= (for EventSource).
func AuthTokenFromRequest(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth != "" {
		token := strings.TrimPrefix(auth, "Bearer ")
		if token != auth {
			return token
		}
	}
	return r.URL.Query().Get("token")
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
