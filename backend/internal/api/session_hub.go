package api

import (
	"net/http"
	"sync"
	"time"
)

const sessionTTL = 2 * time.Minute

// SessionEntry represents one active session (token holder).
type SessionEntry struct {
	Name     string    `json:"name"`
	TokenID  string    `json:"token_id"`
	LastSeen time.Time `json:"last_seen"`
}

// SessionHub tracks which display names are currently active based on token heartbeats.
// Every authenticated request updates the holder's last-seen timestamp.
type SessionHub struct {
	mu      sync.RWMutex
	entries map[string]*SessionEntry // key = token ID
}

func NewSessionHub() *SessionHub {
	return &SessionHub{entries: make(map[string]*SessionEntry)}
}

// Heartbeat updates (or creates) the session entry for the given token ID.
func (h *SessionHub) Heartbeat(tokenID, name string) {
	if tokenID == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if e, ok := h.entries[tokenID]; ok {
		e.LastSeen = time.Now()
		if name != "" {
			e.Name = name
		}
	} else {
		h.entries[tokenID] = &SessionEntry{
			Name:     name,
			TokenID:  tokenID,
			LastSeen: time.Now(),
		}
	}
}

// Active returns all sessions seen within the last sessionTTL.
func (h *SessionHub) Active() []SessionEntry {
	h.mu.Lock()
	defer h.mu.Unlock()
	cutoff := time.Now().Add(-sessionTTL)
	out := make([]SessionEntry, 0, len(h.entries))
	for id, e := range h.entries {
		if e.LastSeen.Before(cutoff) {
			delete(h.entries, id)
			continue
		}
		out = append(out, *e)
	}
	return out
}

func (s *Server) handleSessionActive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sessions := s.sessionHub.Active()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"sessions": sessions,
		"count":    len(sessions),
	})
}
