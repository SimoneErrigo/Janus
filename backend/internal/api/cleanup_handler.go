package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/SimoneErrigo/Janus/backend/internal/cleanup"
	"github.com/SimoneErrigo/Janus/backend/internal/config"
)

func (s *Server) handleCleanupConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg := config.Get()
		settings := cleanup.Settings{MaxAgeMinutes: cfg.CleanupMaxAgeMinutes, MaxDBSizeMB: cfg.CleanupMaxDBSizeMB}
		effective := s.cleanupMgr.GetSettings()
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"max_age_minutes":           settings.MaxAgeMinutes,
			"max_db_size_mb":            settings.MaxDBSizeMB,
			"effective_max_age_minutes": effective.MaxAgeMinutes,
			"effective_max_db_size_mb":  effective.MaxDBSizeMB,
			"db_size_mb":                s.cleanupMgr.DBSizeMB(),
			"db_used_mb":                s.cleanupMgr.DBUsedMB(),
		})
	case http.MethodPut:
		var req cleanup.Settings
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&req); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.MaxAgeMinutes < 0 || req.MaxAgeMinutes > 525600 {
			http.Error(w, "max_age_minutes must be between 0 and 525600", http.StatusBadRequest)
			return
		}
		if req.MaxDBSizeMB < 0 || req.MaxDBSizeMB > 1048576 {
			http.Error(w, "max_db_size_mb must be between 0 and 1048576", http.StatusBadRequest)
			return
		}
		s.configMu.Lock()
		defer s.configMu.Unlock()
		cfg, err := config.Update(func(cfg *config.Config) error {
			cfg.CleanupMaxAgeMinutes = req.MaxAgeMinutes
			cfg.CleanupMaxDBSizeMB = req.MaxDBSizeMB
			return nil
		})
		if err != nil {
			http.Error(w, fmt.Sprintf("saving cleanup settings: %v", err), http.StatusInternalServerError)
			return
		}
		s.cleanupMgr.UpdateSettings(effectiveCleanupSettings(cfg))
		effective := s.cleanupMgr.GetSettings()
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"max_age_minutes":           req.MaxAgeMinutes,
			"max_db_size_mb":            req.MaxDBSizeMB,
			"effective_max_age_minutes": effective.MaxAgeMinutes,
			"effective_max_db_size_mb":  effective.MaxDBSizeMB,
			"db_size_mb":                s.cleanupMgr.DBSizeMB(),
			"db_used_mb":                s.cleanupMgr.DBUsedMB(),
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
	log.Printf("[user=%s] action=purge-packets", DisplayNameFromRequest(r))
	result := s.cleanupMgr.PurgePackets()
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleCleanupPurgeDropped(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	log.Printf("[user=%s] action=purge-dropped", DisplayNameFromRequest(r))
	result := s.cleanupMgr.PurgeDroppedPackets()
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleCleanupPurge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	log.Printf("[user=%s] action=purge-all", DisplayNameFromRequest(r))
	result := s.cleanupMgr.PurgeAll()
	writeJSON(w, http.StatusOK, result)
}
