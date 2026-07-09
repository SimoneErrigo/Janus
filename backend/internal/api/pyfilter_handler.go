package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/SimoneErrigo/Janus/backend/internal/pyfilter"
	"github.com/SimoneErrigo/Janus/backend/internal/sniffer"
)

// FlowFromPacket builds the generic flow dict handed to Python filter scripts.
// Kept exported so the live-capture wiring in main can reuse the exact same
// shape the /test endpoint exposes.
func FlowFromPacket(p *sniffer.Packet) pyfilter.Flow {
	body := p.BodyString
	if body == "" && len(p.Body) > 0 {
		body = string(p.Body)
	}
	return pyfilter.Flow{
		"id":        p.ID,
		"service":   p.ServiceID,
		"direction": string(p.Direction),
		"method":    p.Method,
		"url":       p.URL,
		"status":    p.Status,
		"src":       p.SrcIP,
		"dst":       p.DstIP,
		"sport":     p.SrcPort,
		"dport":     p.DstPort,
		"headers":   p.Headers,
		"body":      body,
		// Exact bytes for binary payload analysis (util.magic/entropy/…); the
		// content property prefers this over the lossy utf-8 body string.
		"body_b64":        base64.StdEncoding.EncodeToString(p.Body),
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
	// Blocking runs the script inline (synchronously) on the request hot path so
	// a match returning {"drop": True} blocks the current request in real time.
	Blocking bool `json:"blocking"`
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
		sc, err := s.pyfilter.CreateScript(req.Name, req.Code, req.Enabled, req.Blocking)
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
		sc, err := s.pyfilter.UpdateScript(id, req.Name, req.Code, req.Enabled, req.Blocking)
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

// GET /api/pyfilter-engine/status
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
	// Flows is an ordered sequence (a whole reconstructed flow) evaluated in
	// turn; when set it takes precedence over Flow/PacketID.
	Flows []pyfilter.Flow `json:"flows,omitempty"`
	// FlowPacketID resolves a whole flow server-side from one of its packet #s.
	FlowPacketID int64 `json:"flow_packet_id,omitempty"`
	// Repeat re-runs the whole sequence N times so stateful scripts can be tested.
	Repeat int `json:"repeat,omitempty"`
}

// pyFilterTestStep is one packet's verdict in a sequence test.
type pyFilterTestStep struct {
	Index     int              `json:"index"`
	Direction string           `json:"direction,omitempty"`
	Matched   bool             `json:"matched"`
	Matches   []pyfilter.Match `json:"matches"`
	// Rewrite is the new content (best-effort text) when an inline filter
	// rewrote this message; empty otherwise.
	Rewrite string `json:"rewrite,omitempty"`
}

// POST /api/pyfilter-engine/test — evaluate a (possibly unsaved) script against a
// single flow, a stored packet, or a whole reconstructed flow (an ordered
// sequence of packets), in isolation, and report a per-step verdict.
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

	// Resolve the flow sequence (precedence: explicit flows > server-resolved
	// flow > single packet > single flow object).
	var flows []pyfilter.Flow
	switch {
	case len(req.Flows) > 0:
		flows = req.Flows
	case req.FlowPacketID > 0:
		packets, err := s.packetStore.QueryFlow(req.FlowPacketID)
		if err != nil {
			http.Error(w, "flow query error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		for _, p := range packets {
			flows = append(flows, FlowFromPacket(p))
		}
	case req.PacketID > 0:
		p, err := s.packetStore.GetPacketByID(req.PacketID)
		if err != nil || p == nil {
			http.Error(w, "packet not found", http.StatusNotFound)
			return
		}
		flows = []pyfilter.Flow{FlowFromPacket(p)}
	default:
		f := req.Flow
		if f == nil {
			f = pyfilter.Flow{}
		}
		flows = []pyfilter.Flow{f}
	}
	if len(flows) == 0 {
		flows = []pyfilter.Flow{{}}
	}
	if len(flows) > 500 {
		flows = flows[:500] // bound the isolated test run
	}

	repeat := req.Repeat
	if repeat < 1 {
		repeat = 1
	}
	if repeat > 500 {
		repeat = 500
	}

	steps, scriptErr, err := s.pyfilter.TestSequence(req.Name, req.Code, flows, repeat)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	outSteps := make([]pyFilterTestStep, len(steps))
	anyMatch := false
	var lastMatches []pyfilter.Match
	for i, st := range steps {
		dir, _ := flows[i]["direction"].(string)
		step := pyFilterTestStep{Index: i, Direction: dir, Matched: len(st.Matches) > 0, Matches: st.Matches}
		if st.Rewrite != nil {
			step.Rewrite = string(st.Rewrite)
		}
		outSteps[i] = step
		if len(st.Matches) > 0 {
			anyMatch = true
		}
		lastMatches = st.Matches
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"matched":      anyMatch,
		"steps":        outSteps,
		"matches":      lastMatches, // backward-compat: last step's matches
		"script_error": scriptErr,
	})
}
