package api

import "net/http"

func (s *Server) handleSystemStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats, err := s.statsCollector.Collect()
	if err != nil {
		http.Error(w, "failed to collect stats: "+err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, stats)
}
