package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/SimoneErrigo/Janus/backend/internal/dropper"
)

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listRules(w, r)
	case http.MethodPost:
		s.createRule(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleRuleByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/rules/")
	if id == "" {
		http.Error(w, "missing rule ID", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.getRule(w, r, id)
	case http.MethodPut:
		s.updateRule(w, r, id)
	case http.MethodDelete:
		s.deleteRule(w, r, id)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) listRules(w http.ResponseWriter, r *http.Request) {
	serviceID := r.URL.Query().Get("service_id")
	rules := s.ruleStore.ListRules(serviceID)
	writeJSON(w, http.StatusOK, rules)
}

func (s *Server) getRule(w http.ResponseWriter, r *http.Request, id string) {
	rule, ok := s.ruleStore.GetRule(id)
	if !ok {
		http.Error(w, "rule not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, rule)
}

func (s *Server) createRule(w http.ResponseWriter, r *http.Request) {
	var rule dropper.Rule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Auto-generate ID if not provided
	if rule.ID == "" {
		b := make([]byte, 8)
		rand.Read(b)
		rule.ID = hex.EncodeToString(b)
	}

	// Default action to drop if not specified
	if rule.Action == "" {
		rule.Action = dropper.ActionDrop
	}

	if err := validateRule(&rule); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Reject duplicate rules (same service + type + scope + pattern + action)
	existing := s.ruleStore.ListRules(rule.ServiceID)
	for _, e := range existing {
		if e.Type == rule.Type && e.Scope == rule.Scope &&
			e.Pattern == rule.Pattern && e.Action == rule.Action {
			http.Error(w, fmt.Sprintf("duplicate rule: an identical rule already exists (id=%s, name=%q)", e.ID, e.Name), http.StatusConflict)
			return
		}
	}

	// Attribute the rule to the requesting user
	rule.CreatedBy = DisplayNameFromRequest(r)

	if err := s.ruleStore.CreateRule(&rule); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	user := rule.CreatedBy
	log.Printf("[user=%s] Rule created: %s (%s) for service %s", user, rule.Name, rule.ID, rule.ServiceID)
	writeJSON(w, http.StatusCreated, rule)
}

func (s *Server) updateRule(w http.ResponseWriter, r *http.Request, id string) {
	var rule dropper.Rule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	rule.ID = id

	// Flag rules must always remain action=alert
	if rule.IsFlagRule() && rule.Action != dropper.ActionAlert {
		rule.Action = dropper.ActionAlert
	}

	// Default action to drop if not specified
	if rule.Action == "" {
		rule.Action = dropper.ActionDrop
	}

	if err := validateRule(&rule); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := s.ruleStore.UpdateRule(&rule); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	log.Printf("[user=%s] Rule updated: %s (%s)", DisplayNameFromRequest(r), rule.Name, rule.ID)
	writeJSON(w, http.StatusOK, rule)
}

func (s *Server) deleteRule(w http.ResponseWriter, r *http.Request, id string) {
	if err := s.ruleStore.DeleteRule(id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	log.Printf("[user=%s] Rule deleted: %s", DisplayNameFromRequest(r), id)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRulesBulkDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(body.IDs) == 0 {
		http.Error(w, "ids array is required", http.StatusBadRequest)
		return
	}

	deleted, err := s.ruleStore.DeleteRules(body.IDs)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("Bulk deleted %d rules", deleted)
	writeJSON(w, http.StatusOK, map[string]int{"deleted": deleted})
}

func validateRule(r *dropper.Rule) error {
	if r.ID == "" {
		return fmt.Errorf("id is required")
	}
	if r.ServiceID == "" {
		return fmt.Errorf("service_id is required")
	}
	if r.Name == "" {
		return fmt.Errorf("name is required")
	}
	if r.Pattern == "" {
		return fmt.Errorf("pattern is required")
	}

	switch r.Type {
	case dropper.MatchString, dropper.MatchRegex, dropper.MatchBytes:
	default:
		return fmt.Errorf("type must be one of: string, regex, bytes")
	}

	// Validate scope — supports comma-separated multi-scope (e.g. "body,header")
	for _, s := range strings.Split(string(r.Scope), ",") {
		switch dropper.Scope(s) {
		case dropper.ScopeHeader, dropper.ScopeBody, dropper.ScopeURL, dropper.ScopeRaw:
		default:
			return fmt.Errorf("scope must be one of: header, body, url, raw (comma-separated for multiple)")
		}
	}

	switch r.Action {
	case dropper.ActionDrop, dropper.ActionAlert, dropper.ActionBoth, dropper.ActionWhitelist:
	default:
		return fmt.Errorf("action must be one of: drop, alert, both, whitelist")
	}

	return nil
}
