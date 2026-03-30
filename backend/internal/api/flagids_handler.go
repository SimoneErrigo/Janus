package api

import (
	"log"
	"net/http"
)

func (s *Server) handleFlagIDs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.flagIDPoller == nil || !s.flagIDPoller.IsEnabled() {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"enabled":  false,
			"flag_ids": map[string][]string{},
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"enabled":  true,
		"flag_ids": s.flagIDPoller.GetFlagIDs(),
	})
}

func (s *Server) handleFlagIDStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.flagIDPoller == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"enabled": false,
		})
		return
	}

	writeJSON(w, http.StatusOK, s.flagIDPoller.GetStatus())
}

func (s *Server) handleFlagIDRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.flagIDPoller == nil || !s.flagIDPoller.IsEnabled() {
		http.Error(w, "flag ID poller is not enabled", http.StatusBadRequest)
		return
	}

	s.flagIDPoller.FetchNow()
	writeJSON(w, http.StatusOK, s.flagIDPoller.GetStatus())
}

func (s *Server) handleFlagIDBackfill(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.flagIDPoller == nil || !s.flagIDPoller.IsEnabled() {
		http.Error(w, "flag ID poller is not enabled", http.StatusBadRequest)
		return
	}

	currentRound := s.flagIDPoller.CurrentRound()
	n, err := s.packetStore.SmartBackfillFlagIDs(s.flagIDPoller, currentRound)
	if err != nil {
		log.Printf("on-demand backfill error: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if n > 0 {
		log.Printf("on-demand backfill: marked %d packets with flag IDs (round %d)", n, currentRound)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"updated": n, "round": currentRound})
}
