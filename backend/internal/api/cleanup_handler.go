package api

import (
	"encoding/json"
	"net/http"

	"github.com/SimoneErrigo/Janus/backend/internal/cleanup"
)

func (s *Server) handleCleanupConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		settings := s.cleanupMgr.GetSettings()
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"max_age_minutes": settings.MaxAgeMinutes,
			"max_db_size_mb":  settings.MaxDBSizeMB,
			"db_size_mb":      s.cleanupMgr.DBSizeMB(),
		})
	case http.MethodPut:
		var req cleanup.Settings
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		s.cleanupMgr.UpdateSettings(req)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"max_age_minutes": req.MaxAgeMinutes,
			"max_db_size_mb":  req.MaxDBSizeMB,
			"db_size_mb":      s.cleanupMgr.DBSizeMB(),
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleCleanupRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	result := s.cleanupMgr.RunNow()
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleCleanupPurgePackets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	result := s.cleanupMgr.PurgePackets()
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleCleanupPurgeDropped(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	result := s.cleanupMgr.PurgeDroppedPackets()
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleCleanupPurge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	result := s.cleanupMgr.PurgeAll()
	writeJSON(w, http.StatusOK, result)
}
