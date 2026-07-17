package api

import (
	"encoding/json"
	"fmt"
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
	if len(req.ServiceIDs) > 64 || len(req.Selected) > 64 {
		http.Error(w, "too many services or preset categories", http.StatusBadRequest)
		return
	}
	if len(req.Selected) == 0 {
		http.Error(w, "selected is required", http.StatusBadRequest)
		return
	}
	selectedCount := 0
	for _, indices := range req.Selected {
		selectedCount += len(indices)
	}
	if selectedCount == 0 || selectedCount*len(req.ServiceIDs) > 500 {
		http.Error(w, "preset selection must create at most 500 rules", http.StatusBadRequest)
		return
	}
	for _, serviceID := range req.ServiceIDs {
		if _, ok := s.store.GetService(serviceID); !ok {
			http.Error(w, "service not found: "+serviceID, http.StatusBadRequest)
			return
		}
	}

	// Build a lookup map: category name -> PresetCategory
	presets := dropper.GetPresets()
	presetMap := make(map[string]dropper.PresetCategory, len(presets))
	for _, cat := range presets {
		presetMap[cat.Name] = cat
	}

	var candidates []*dropper.Rule
	createdBy := DisplayNameFromRequest(r)
	for catName, indices := range req.Selected {
		cat, ok := presetMap[catName]
		if !ok {
			http.Error(w, "unknown preset category: "+catName, http.StatusBadRequest)
			return
		}
		for _, idx := range indices {
			if idx < 0 || idx >= len(cat.Rules) {
				http.Error(w, fmt.Sprintf("invalid preset index %d for %s", idx, catName), http.StatusBadRequest)
				return
			}
			preset := cat.Rules[idx]
			for _, svcID := range req.ServiceIDs {
				id, err := newRuleID()
				if err != nil {
					http.Error(w, "internal error", http.StatusInternalServerError)
					return
				}
				rule := &dropper.Rule{
					ID:        id,
					ServiceID: svcID,
					Name:      preset.Name,
					Type:      preset.Type,
					Scope:     preset.Scope,
					Pattern:   preset.Pattern,
					Priority:  10,
					Enabled:   true,
					Action:    preset.Action,
					CreatedBy: createdBy,
				}
				rule.Expression = dropper.DeriveExpression(rule)
				if err := validateRule(rule); err != nil {
					http.Error(w, fmt.Sprintf("invalid preset %q: %v", preset.Name, err), http.StatusBadRequest)
					return
				}
				candidates = append(candidates, rule)
			}
		}
	}

	s.ruleMu.Lock()
	defer s.ruleMu.Unlock()
	seen := make(map[string]struct{})
	for _, serviceID := range req.ServiceIDs {
		for _, existing := range s.ruleStore.ListRules(serviceID) {
			seen[presetRuleKey(existing)] = struct{}{}
		}
	}
	for _, candidate := range candidates {
		key := presetRuleKey(candidate)
		if _, duplicate := seen[key]; duplicate {
			http.Error(w, fmt.Sprintf("duplicate rule: %q already exists for service %s", candidate.Name, candidate.ServiceID), http.StatusConflict)
			return
		}
		seen[key] = struct{}{}
	}

	if err := s.ruleStore.CreateRules(candidates); err != nil {
		log.Printf("Preset batch creation failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, applyPresetsResponse{Errors: 1})
		return
	}

	created := len(candidates)
	log.Printf("Presets applied: %d alert rules created", created)
	writeJSON(w, http.StatusOK, applyPresetsResponse{
		Created: created,
	})
}

func presetRuleKey(rule *dropper.Rule) string {
	return rule.ServiceID + "\x00" + rule.Expression + "\x00" + string(rule.Action)
}
