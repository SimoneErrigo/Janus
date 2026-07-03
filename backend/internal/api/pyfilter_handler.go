package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net/http"
	"strings"

	"github.com/SimoneErrigo/Janus/backend/internal/dropper"
	"github.com/SimoneErrigo/Janus/backend/internal/filter"
	"github.com/SimoneErrigo/Janus/backend/internal/pyfilter"
	"github.com/SimoneErrigo/Janus/backend/internal/sniffer"
)

// pyDropForbiddenFields are network/identity fields a Python filter's drop
// expression may not use. Dropping by src IP is meaningless under SNAT (every
// team shares the same source address) and would take out all traffic, so we
// keep pyfilter drops strictly content-based.
var pyDropForbiddenFields = map[string]bool{
	"src": true, "dst": true, "peer": true, "sport": true, "dport": true,
}

// InstallPyFilterDrop installs (idempotently) a content-only drop rule requested
// by a Python filter match, so future matching traffic is blocked by the fast
// in-process rules engine (fail2ban style). It is a no-op when m.Drop is empty,
// and returns an error if the expression is invalid or references a forbidden
// network/identity field.
func InstallPyFilterDrop(ruleStore *dropper.RuleStore, flow pyfilter.Flow, m pyfilter.Match) (string, error) {
	expr := strings.TrimSpace(m.Drop)
	if expr == "" {
		return "", nil
	}
	ast, err := filter.Parse(expr)
	if err != nil {
		return "", fmt.Errorf("invalid drop expression %q: %w", expr, err)
	}
	for _, f := range filter.FieldsUsed(ast) {
		if pyDropForbiddenFields[f] {
			return "", fmt.Errorf("drop expression may not use %q — pyfilter drops are content-only (IP/port dropping is unsafe under SNAT)", f)
		}
	}

	svcID, _ := flow["service"].(string)
	// Deterministic id per (script, service, expression) so repeated matches
	// reuse one rule instead of flooding the store — one ban per offender.
	h := fnv.New32a()
	_, _ = h.Write([]byte(svcID + "|" + expr))
	ruleID := fmt.Sprintf("pyfilter-drop:%s:%08x", m.Script, h.Sum32())

	if existing, ok := ruleStore.GetRule(ruleID); ok {
		if existing.Enabled && existing.Action == dropper.ActionDrop {
			return ruleID, nil
		}
		existing.Enabled = true
		existing.Action = dropper.ActionDrop
		return ruleID, ruleStore.UpdateRule(existing)
	}

	rule := &dropper.Rule{
		ID:         ruleID,
		ServiceID:  svcID,
		Name:       "Python drop (" + m.Name + ")",
		Expression: expr,
		Action:     dropper.ActionDrop,
		Priority:   0,
		Enabled:    true,
		CreatedBy:  "pyfilter",
	}
	if err := ruleStore.CreateRule(rule); err != nil {
		return "", err
	}
	return ruleID, nil
}

// FlowFromPacket builds the generic flow dict handed to Python filter scripts.
// Kept exported so the live-capture wiring in main can reuse the exact same
// shape the /test endpoint exposes.
func FlowFromPacket(p *sniffer.Packet) pyfilter.Flow {
	body := p.BodyString
	if body == "" && len(p.Body) > 0 {
		body = string(p.Body)
	}
	return pyfilter.Flow{
		"id":              p.ID,
		"service":         p.ServiceID,
		"direction":       string(p.Direction),
		"method":          p.Method,
		"url":             p.URL,
		"status":          p.Status,
		"src":             p.SrcIP,
		"dst":             p.DstIP,
		"sport":           p.SrcPort,
		"dport":           p.DstPort,
		"headers":         p.Headers,
		"body":            body,
		"flagged":         p.Flagged,
		"contains_flagid": p.ContainsFlagID,
		"timestamp":       p.Timestamp.Unix(),
	}
}

// pyFilterAvailable guards handlers when the engine is disabled/unset.
func (s *Server) pyFilterAvailable(w http.ResponseWriter) bool {
	if s.pyfilter == nil {
		http.Error(w, "python filters are disabled (PYFILTER_ENABLED=false)", http.StatusServiceUnavailable)
		return false
	}
	return true
}

type pyFilterRequest struct {
	Name    string `json:"name"`
	Code    string `json:"code"`
	Enabled bool   `json:"enabled"`
}

// GET /api/pyfilters — list scripts + engine status.
// POST /api/pyfilters — create a script.
func (s *Server) handlePyFilters(w http.ResponseWriter, r *http.Request) {
	if !s.pyFilterAvailable(w) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{
			"scripts": s.pyfilter.ListScripts(),
			"status":  s.pyfilter.Status(),
		})
	case http.MethodPost:
		var req pyFilterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		sc, err := s.pyfilter.CreateScript(req.Name, req.Code, req.Enabled)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusCreated, sc)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// GET/PUT/DELETE /api/pyfilters/{id}
func (s *Server) handlePyFilterByID(w http.ResponseWriter, r *http.Request) {
	if !s.pyFilterAvailable(w) {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/pyfilters/")
	if id == "" {
		http.Error(w, "missing script id", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet:
		sc, ok := s.pyfilter.GetScript(id)
		if !ok {
			http.Error(w, "script not found", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, sc)
	case http.MethodPut:
		var req pyFilterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		sc, err := s.pyfilter.UpdateScript(id, req.Name, req.Code, req.Enabled)
		if err != nil {
			s.writePyFilterErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, sc)
	case http.MethodDelete:
		if err := s.pyfilter.DeleteScript(id); err != nil {
			s.writePyFilterErr(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) writePyFilterErr(w http.ResponseWriter, err error) {
	if errors.Is(err, pyfilter.ErrNotFound()) {
		http.Error(w, "script not found", http.StatusNotFound)
		return
	}
	http.Error(w, err.Error(), http.StatusBadRequest)
}

// GET /api/pyfilters/status
func (s *Server) handlePyFilterStatus(w http.ResponseWriter, r *http.Request) {
	if s.pyfilter == nil {
		writeJSON(w, http.StatusOK, pyfilter.Status{Available: false})
		return
	}
	writeJSON(w, http.StatusOK, s.pyfilter.Status())
}

type pyFilterTestRequest struct {
	Name     string        `json:"name"`
	Code     string        `json:"code"`
	PacketID int64         `json:"packet_id,omitempty"`
	Flow     pyfilter.Flow `json:"flow,omitempty"`
	// Repeat re-runs the same flow N times so stateful scripts can be tested.
	Repeat int `json:"repeat,omitempty"`
}

// POST /api/pyfilters/test — evaluate a (possibly unsaved) script against a
// sample flow or a stored packet, in isolation, and report the verdict.
func (s *Server) handlePyFilterTest(w http.ResponseWriter, r *http.Request) {
	if !s.pyFilterAvailable(w) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req pyFilterTestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	flow := req.Flow
	if req.PacketID > 0 {
		p, err := s.packetStore.GetPacketByID(req.PacketID)
		if err != nil || p == nil {
			http.Error(w, "packet not found", http.StatusNotFound)
			return
		}
		flow = FlowFromPacket(p)
	}
	if flow == nil {
		flow = pyfilter.Flow{}
	}

	repeat := req.Repeat
	if repeat < 1 {
		repeat = 1
	}
	if repeat > 500 {
		repeat = 500 // bound the isolated test run
	}

	matches, scriptErr, err := s.pyfilter.Test(req.Name, req.Code, flow, repeat)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"matched":      len(matches) > 0,
		"matches":      matches,
		"script_error": scriptErr,
		"flow":         flow,
	})
}
