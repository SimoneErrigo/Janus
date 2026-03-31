package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"

	"github.com/SimoneErrigo/Janus/backend/internal/dropper"
)

func (s *Server) handlePresetsGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, dropper.GetPresets())
}

type applyPresetsRequest struct {
	// ServiceIDs to apply the rules to
	ServiceIDs []string `json:"service_ids"`
	// Selected preset rules to create: category name -> list of rule indices
	Selected map[string][]int `json:"selected"`
}

type applyPresetsResponse struct {
	Created int `json:"created"`
	Errors  int `json:"errors"`
}

func (s *Server) handlePresetsApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req applyPresetsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	if len(req.ServiceIDs) == 0 {
		http.Error(w, "service_ids is required", http.StatusBadRequest)
		return
	}
	if len(req.Selected) == 0 {
		http.Error(w, "selected is required", http.StatusBadRequest)
		return
	}

	// Build a lookup map: category name -> PresetCategory
	presets := dropper.GetPresets()
	presetMap := make(map[string]dropper.PresetCategory, len(presets))
	for _, cat := range presets {
		presetMap[cat.Name] = cat
	}

	var created, errors int

	for catName, indices := range req.Selected {
		cat, ok := presetMap[catName]
		if !ok {
			continue
		}
		for _, idx := range indices {
			if idx < 0 || idx >= len(cat.Rules) {
				continue
			}
			preset := cat.Rules[idx]

			for _, svcID := range req.ServiceIDs {
				b := make([]byte, 8)
				rand.Read(b)

				rule := &dropper.Rule{
					ID:        hex.EncodeToString(b),
					ServiceID: svcID,
					Name:      preset.Name,
					Type:      preset.Type,
					Scope:     preset.Scope,
					Pattern:   preset.Pattern,
					Priority:  10,
					Enabled:   true,
					Action:    preset.Action,
				}

				if err := s.ruleStore.CreateRule(rule); err != nil {
					log.Printf("Preset rule creation failed (%s for %s): %v", preset.Name, svcID, err)
					errors++
				} else {
					created++
				}
			}
		}
	}

	log.Printf("Presets applied: %d rules created, %d errors", created, errors)
	writeJSON(w, http.StatusOK, applyPresetsResponse{
		Created: created,
		Errors:  errors,
	})
}
