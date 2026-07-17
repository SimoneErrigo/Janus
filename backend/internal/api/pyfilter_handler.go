package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	flowmodel "github.com/SimoneErrigo/Janus/backend/internal/flow"
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
	eventID := p.PyFilterEventID
	if eventID == "" {
		if p.ID > 0 {
			eventID = fmt.Sprintf("packet/%d", p.ID)
		} else {
			eventID = sniffer.MakePyFilterEventID(p.SessionID, p.Direction, p.Timestamp)
		}
	}
	return pyfilter.Flow{
		"id": p.ID, "service": p.ServiceID, "session": p.SessionID,
		"event_id": eventID,
		"protocol": p.Protocol, "round": p.Round, "truncated": p.CaptureTruncated, "body_complete": !p.CaptureTruncated,
		"decoded": p.Decoded, "direction": string(p.Direction),
		"method":  p.Method,
		"url":     p.URL,
		"status":  p.Status,
		"src":     p.SrcIP,
		"dst":     p.DstIP,
		"sport":   p.SrcPort,
		"dport":   p.DstPort,
		"headers": p.Headers,
		"body":    body,
		// Exact bytes for binary payload analysis (util.magic/entropy/…); the
		// content property prefers this over the lossy utf-8 body string.
		"body_b64":           base64.StdEncoding.EncodeToString(p.Body),
		"size_bytes":         len(p.Body),
		"flagged":            p.Flagged,
		"contains_flagid":    p.ContainsFlagID,
		"matched_flagids":    p.MatchedFlagIDs,
		"flag_count_body":    p.FlagCountBody,
		"flag_count_headers": p.FlagCountHeaders,
		"flag_count_url":     p.FlagCountURL,
		"admitted":           p.Verdict.Outcome != flowmodel.OutcomeDropped,
		"timestamp":          float64(p.Timestamp.UnixNano()) / float64(time.Second),
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
	Blocking   bool     `json:"blocking"`
	Mode       string   `json:"mode,omitempty"`
	ServiceIDs []string `json:"service_ids,omitempty"`
	Directions []string `json:"directions,omitempty"`
	Protocols  []string `json:"protocols,omitempty"`
}

func (r pyFilterRequest) options() pyfilter.ScriptOptions {
	mode := r.Mode
	if mode == "" {
		if r.Blocking {
			mode = "block"
		} else {
			mode = "observe"
		}
	}
	return pyfilter.ScriptOptions{Enabled: r.Enabled, Mode: mode, ServiceIDs: r.ServiceIDs, Directions: r.Directions, Protocols: r.Protocols}
}

func (s *Server) validateEnabledPyFilter(w http.ResponseWriter, req pyFilterRequest) bool {
	if len(req.Name) > 128 || len(req.Code) > 256<<10 {
		http.Error(w, "name or code is too long", http.StatusBadRequest)
		return false
	}
	mode := req.options().Mode
	if mode != "observe" && mode != "block" && mode != "rewrite" {
		http.Error(w, "mode must be observe, block, or rewrite", http.StatusBadRequest)
		return false
	}
	if len(req.ServiceIDs) > 256 || len(req.Directions) > 2 || len(req.Protocols) > 64 {
		http.Error(w, "too many scope values", http.StatusBadRequest)
		return false
	}
	for _, direction := range req.Directions {
		if direction != "request" && direction != "response" {
			http.Error(w, "direction must be request or response", http.StatusBadRequest)
			return false
		}
	}
	if !req.Enabled {
		return true
	}
	message, err := s.pyfilter.ValidateScript(req.Name, req.Code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return false
	}
	if message != "" {
		http.Error(w, message, http.StatusBadRequest)
		return false
	}
	return true
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
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if !s.validateEnabledPyFilter(w, req) {
			return
		}
		sc, err := s.pyfilter.CreateScriptWith(req.Name, req.Code, req.options())
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
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if !s.validateEnabledPyFilter(w, req) {
			return
		}
		sc, err := s.pyfilter.UpdateScriptWith(id, req.Name, req.Code, req.options())
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
	Name       string        `json:"name"`
	Code       string        `json:"code"`
	Mode       string        `json:"mode,omitempty"`
	ServiceIDs []string      `json:"service_ids,omitempty"`
	Directions []string      `json:"directions,omitempty"`
	Protocols  []string      `json:"protocols,omitempty"`
	PacketID   int64         `json:"packet_id,omitempty"`
	Flow       pyfilter.Flow `json:"flow,omitempty"`
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
	// Rewritten distinguishes an intentional empty payload from no rewrite;
	// RewriteB64 preserves exact binary TCP/UDP/WebSocket content.
	Rewritten  bool                   `json:"rewritten"`
	Rewrite    string                 `json:"rewrite,omitempty"`
	RewriteB64 string                 `json:"rewrite_b64,omitempty"`
	Console    []pyfilter.ConsoleLine `json:"console,omitempty"`
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
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<20)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(req.Name) > 128 || len(req.Code) > 256<<10 {
		http.Error(w, "name or code is too long", http.StatusBadRequest)
		return
	}
	if len(req.ServiceIDs) > 256 || len(req.Directions) > 2 || len(req.Protocols) > 64 {
		http.Error(w, "too many scope values", http.StatusBadRequest)
		return
	}
	for _, direction := range req.Directions {
		if direction != "request" && direction != "response" {
			http.Error(w, "direction must be request or response", http.StatusBadRequest)
			return
		}
	}
	if req.Flows != nil {
		if len(req.Flows) == 0 {
			http.Error(w, "flows must contain at least one flow", http.StatusBadRequest)
			return
		}
		if len(req.Flows) > 200 {
			http.Error(w, "flows must contain at most 200 flows", http.StatusBadRequest)
			return
		}
	}

	// Resolve the flow sequence (precedence: explicit flows > server-resolved
	// flow > single packet > single flow object).
	var flows []pyfilter.Flow
	switch {
	case req.Flows != nil:
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
	if len(flows) > 200 {
		flows = flows[:200]
	}
	if req.Flows != nil || (req.FlowPacketID == 0 && req.PacketID == 0) {
		for index, flow := range flows {
			if err := s.annotateSyntheticFlagCounts(flow); err != nil {
				http.Error(w, fmt.Sprintf("invalid flow %d: %v", index+1, err), http.StatusBadRequest)
				return
			}
		}
	}

	repeat := req.Repeat
	if repeat < 1 {
		repeat = 1
	}
	if repeat > 50 {
		repeat = 50
	}
	if repeat*len(flows) > 2000 {
		repeat = 2000 / len(flows)
		if repeat < 1 {
			repeat = 1
		}
	}

	mode := req.Mode
	if mode == "" {
		mode = "rewrite" // preserve the original tester's block/rewrite preview
	}
	if mode != "observe" && mode != "block" && mode != "rewrite" {
		http.Error(w, "mode must be observe, block, or rewrite", http.StatusBadRequest)
		return
	}
	steps, scriptErr, err := s.pyfilter.TestSequenceScoped(req.Name, req.Code, flows, repeat, pyfilter.ScriptOptions{
		Mode: mode, ServiceIDs: req.ServiceIDs, Directions: req.Directions, Protocols: req.Protocols,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	outSteps := make([]pyFilterTestStep, len(steps))
	anyMatch := false
	var lastMatches []pyfilter.Match
	for i, st := range steps {
		dir, _ := flows[i]["direction"].(string)
		step := pyFilterTestStep{Index: i, Direction: dir, Matched: len(st.Matches) > 0, Matches: st.Matches, Console: st.Console}
		if st.Rewrite != nil {
			step.Rewritten = true
			step.Rewrite = string(st.Rewrite)
			step.RewriteB64 = base64.StdEncoding.EncodeToString(st.Rewrite)
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

func (s *Server) annotateSyntheticFlagCounts(flow pyfilter.Flow) error {
	if flow == nil {
		return errors.New("flow must be an object")
	}
	bodyText, err := syntheticString(flow, "body")
	if err != nil {
		return err
	}
	body := []byte(bodyText)
	if encoded, err := syntheticString(flow, "body_b64"); err != nil {
		return err
	} else if encoded != "" {
		decoded, decodeErr := base64.StdEncoding.DecodeString(encoded)
		if decodeErr != nil {
			return errors.New("body_b64 must be valid base64")
		}
		body = decoded
	}
	headers, err := syntheticHTTPHeaders(flow["headers"])
	if err != nil {
		return err
	}
	url, err := syntheticString(flow, "url")
	if err != nil {
		return err
	}
	var scannedURL, scannedHeaders, scannedBody int
	if s.proxy != nil {
		scannedURL, scannedHeaders, scannedBody = s.proxy.CountFlags(url, sniffer.FlattenHeadersString(headers), body)
	}
	urlCount, err := syntheticFlagCount(flow, "flag_count_url", scannedURL)
	if err != nil {
		return err
	}
	headerCount, err := syntheticFlagCount(flow, "flag_count_headers", scannedHeaders)
	if err != nil {
		return err
	}
	bodyCount, err := syntheticFlagCount(flow, "flag_count_body", scannedBody)
	if err != nil {
		return err
	}
	total := urlCount + headerCount + bodyCount
	// The aggregate is derived from the effective component counters. Accept
	// flag_count as input for compatibility, but never let it contradict them.
	if _, err := syntheticFlagCount(flow, "flag_count", total); err != nil {
		return err
	}
	flagged := false
	if raw, exists := flow["flagged"]; exists && raw != nil {
		var ok bool
		flagged, ok = raw.(bool)
		if !ok {
			return errors.New("flagged must be a boolean")
		}
	}
	if flagged && total == 0 {
		// Preserve the legacy boolean as a conservative lower bound while
		// keeping component and aggregate counters internally consistent.
		bodyCount, total = 1, 1
	}
	flow["flag_count_url"] = urlCount
	flow["flag_count_headers"] = headerCount
	flow["flag_count_body"] = bodyCount
	flow["flag_count"] = total
	flow["flagged"] = total > 0
	return nil
}

func syntheticString(flow pyfilter.Flow, key string) (string, error) {
	raw, exists := flow[key]
	if !exists || raw == nil {
		return "", nil
	}
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string", key)
	}
	return value, nil
}

func syntheticHTTPHeaders(raw any) (http.Header, error) {
	headers := make(http.Header)
	set := func(name string, values []string) error {
		if strings.TrimSpace(name) == "" {
			return errors.New("header names must not be empty")
		}
		headers[name] = append([]string(nil), values...)
		return nil
	}
	switch values := raw.(type) {
	case nil:
		return headers, nil
	case http.Header:
		for name, items := range values {
			if err := set(name, items); err != nil {
				return nil, err
			}
		}
	case map[string]string:
		for name, value := range values {
			if err := set(name, []string{value}); err != nil {
				return nil, err
			}
		}
	case map[string][]string:
		for name, items := range values {
			if err := set(name, items); err != nil {
				return nil, err
			}
		}
	case map[string]any:
		for name, rawValue := range values {
			switch value := rawValue.(type) {
			case string:
				if err := set(name, []string{value}); err != nil {
					return nil, err
				}
			case []any:
				items := make([]string, len(value))
				for i, item := range value {
					var ok bool
					items[i], ok = item.(string)
					if !ok {
						return nil, fmt.Errorf("header %q values must be strings", name)
					}
				}
				if err := set(name, items); err != nil {
					return nil, err
				}
			case []string:
				if err := set(name, value); err != nil {
					return nil, err
				}
			default:
				return nil, fmt.Errorf("header %q must be a string or string array", name)
			}
		}
	default:
		return nil, errors.New("headers must be an object of string values")
	}
	return headers, nil
}

const maxSyntheticFlagCount = 1_000_000_000

func syntheticFlagCount(flow pyfilter.Flow, key string, fallback int) (int, error) {
	raw, exists := flow[key]
	if !exists {
		return fallback, nil
	}
	var value int64
	switch typed := raw.(type) {
	case int:
		value = int64(typed)
	case int64:
		value = typed
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) || math.Trunc(typed) != typed {
			return 0, fmt.Errorf("%s must be a non-negative integer", key)
		}
		value = int64(typed)
	case json.Number:
		parsed, err := typed.Int64()
		if err != nil {
			return 0, fmt.Errorf("%s must be a non-negative integer", key)
		}
		value = parsed
	default:
		return 0, fmt.Errorf("%s must be a non-negative integer", key)
	}
	if value < 0 || value > maxSyntheticFlagCount {
		return 0, fmt.Errorf("%s must be between 0 and %d", key, maxSyntheticFlagCount)
	}
	return int(value), nil
}
