package api

import (
	"net/http"
	"sort"
	"sync"
	"time"
)

const (
	sessionTTL        = 2 * time.Minute
	maxActiveSessions = 4096
)

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
	now := time.Now()
	h.mu.Lock()
	defer h.mu.Unlock()
	if e, ok := h.entries[tokenID]; ok {
		e.LastSeen = now
		if name != "" {
			e.Name = name
		}
	} else {
		if len(h.entries) >= maxActiveSessions {
			for id := range h.entries {
				delete(h.entries, id)
				break
			}
		}
		h.entries[tokenID] = &SessionEntry{
			Name:     name,
			TokenID:  tokenID,
			LastSeen: now,
		}
	}
}

// Remove immediately hides a logged-out session instead of waiting for its TTL.
func (h *SessionHub) Remove(tokenID string) {
	if tokenID == "" {
		return
	}
	h.mu.Lock()
	delete(h.entries, tokenID)
	h.mu.Unlock()
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
	sort.Slice(out, func(i, j int) bool {
		if !out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return out[i].Name < out[j].Name
	})
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
