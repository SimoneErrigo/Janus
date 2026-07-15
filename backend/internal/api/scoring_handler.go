package api

import "net/http"

func (s *Server) handleScoringStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	counts, err := s.packetStore.ScoreCounts()
	if err != nil {
		http.Error(w, "scoring status: "+err.Error(), http.StatusInternalServerError)
		return
	}
	currentRound := 0
	if s.flagIDPoller != nil {
		status := s.flagIDPoller.GetStatus()
		currentRound = status.ClockRound
		if currentRound == 0 {
			currentRound = status.CurrentRound
		}
	}
	result := map[string]any{
		"available":     s.scoring != nil,
		"current_round": currentRound,
		"counts":        counts,
	}
	if s.scoring != nil {
		status := s.scoring.Status()
		result["epoch"] = status.Epoch
		result["opening_rounds"] = status.OpeningRounds
		result["baseline_start_round"] = status.StartRound
		result["baseline_end_round"] = status.EndRound
		result["baseline_required_rounds"] = status.RequiredRounds
		result["rebuilding"] = status.Rebuilding
		result["replayed_packets"] = status.ReplayedPackets
		result["queue_dropped"] = status.QueueDropped
		result["store_errors"] = status.StoreErrors
		result["last_error"] = status.LastError
		result["services"] = status.Services
		result["snapshots"] = status.Snapshots
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleScoringBaselineRebuild(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.scoring == nil {
		http.Error(w, "scoring is unavailable", http.StatusServiceUnavailable)
		return
	}
	// Serialize manual rebuilds with configuration saves so a queued rebuild
	// can never restore the previous start/end range after new values persist.
	s.configMu.Lock()
	defer s.configMu.Unlock()
	if err := s.scoring.RebuildBaseline(); err != nil {
		http.Error(w, "rebuilding scoring baseline: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, s.scoring.Status())
}
