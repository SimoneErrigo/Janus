package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/SimoneErrigo/Janus/backend/internal/filter"
	"github.com/SimoneErrigo/Janus/backend/internal/sniffer"
)

type paginatedPackets struct {
	Packets    []*sniffer.Packet `json:"packets"`
	Total      int               `json:"total"`
	Limit      int               `json:"limit"`
	Offset     int               `json:"offset"`
	TotalExact bool              `json:"total_exact"`
	Partial    bool              `json:"partial,omitempty"`
	NextCursor string            `json:"next_cursor,omitempty"`
}

type packetCursor struct {
	Timestamp string `json:"t"`
	ID        int64  `json:"id"`
}

func (s *Server) handlePackets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if len(r.URL.RawQuery) > 64<<10 {
		http.Error(w, "query string is too long", http.StatusRequestURITooLong)
		return
	}

	q := sniffer.PacketQuery{}
	params := r.URL.Query()
	if raw := params.Get("cursor"); raw != "" {
		cursor, err := decodePacketCursor(raw)
		if err != nil {
			http.Error(w, "invalid cursor", http.StatusBadRequest)
			return
		}
		q.CursorTimestamp, q.CursorID = cursor.Timestamp, cursor.ID
	}

	q.ServiceID = params.Get("service_id")

	// Resolve service_name to service_id
	if v := params.Get("service_name"); v != "" && q.ServiceID == "" {
		for _, svc := range s.store.ListServices() {
			if strings.EqualFold(svc.Name, v) {
				q.ServiceID = svc.ID
				break
			}
		}
		if q.ServiceID == "" {
			// No matching service found — return empty results
			writeJSON(w, http.StatusOK, paginatedPackets{
				Packets: []*sniffer.Packet{},
				Total:   0,
				Limit:   50,
				Offset:  0,
			})
			return
		}
	}

	q.SrcIP = params.Get("src_ip")
	q.DstIP = params.Get("dst_ip")
	q.Protocol = params.Get("protocol")
	q.Method = params.Get("method")
	dirParam := params.Get("direction")
	if dirParam == "" {
		dirParam = params.Get("dir")
	}
	if dirParam != "" {
		dir := strings.ToLower(strings.TrimSpace(dirParam))
		switch dir {
		case "req", "request":
			q.Direction = "request"
		case "res", "response":
			q.Direction = "response"
		default:
			http.Error(w, "invalid direction: use 'req', 'res', 'request', or 'response'", http.StatusBadRequest)
			return
		}
	}
	q.SessionID = params.Get("session_id")
	q.PeerIP = params.Get("peer_ip")
	q.URL = params.Get("url")
	q.Contains = params.Get("contains")
	q.ContainsBody = params.Get("contains_body")
	q.ContainsHeaders = params.Get("contains_headers")
	q.Regex = params.Get("regex")
	q.Q = params.Get("q")
	if len(q.Q) > 4096 {
		http.Error(w, "q expression is too long", http.StatusBadRequest)
		return
	}
	if q.Q != "" {
		// Parse-validate up front so syntax errors come back as 400, not 500.
		if _, err := filter.Compile(q.Q); err != nil {
			http.Error(w, "invalid q expression: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	// Negation filters
	q.NotServiceID = params.Get("not_service_id")
	q.NotSrcIP = params.Get("not_src_ip")
	q.NotDstIP = params.Get("not_dst_ip")
	q.NotProtocol = params.Get("not_protocol")
	q.NotMethod = params.Get("not_method")
	q.NotPeerIP = params.Get("not_peer_ip")
	q.NotURL = params.Get("not_url")
	q.NotContains = params.Get("not_contains")
	q.NotContainsBody = params.Get("not_contains_body")
	q.NotContainsHeaders = params.Get("not_contains_headers")
	q.NotRegex = params.Get("not_regex")
	for name, value := range map[string]string{
		"service_id": q.ServiceID, "session_id": q.SessionID, "src_ip": q.SrcIP, "dst_ip": q.DstIP,
		"peer_ip": q.PeerIP, "url": q.URL, "contains": q.Contains, "contains_body": q.ContainsBody,
		"contains_headers": q.ContainsHeaders, "regex": q.Regex, "not_service_id": q.NotServiceID,
		"not_src_ip": q.NotSrcIP, "not_dst_ip": q.NotDstIP, "not_peer_ip": q.NotPeerIP,
		"not_url": q.NotURL, "not_contains": q.NotContains, "not_contains_body": q.NotContainsBody,
		"not_contains_headers": q.NotContainsHeaders, "not_regex": q.NotRegex,
	} {
		if len(value) > 4096 {
			http.Error(w, name+" is too long", http.StatusBadRequest)
			return
		}
	}
	if v := params.Get("not_direction"); v != "" {
		dir := strings.ToLower(strings.TrimSpace(v))
		switch dir {
		case "req", "request":
			q.NotDirection = "request"
		case "res", "response":
			q.NotDirection = "response"
		default:
			http.Error(w, "invalid not_direction: use 'req', 'res', 'request', or 'response'", http.StatusBadRequest)
			return
		}
	}

	if v := params.Get("flagged"); v != "" {
		flagged, ok := parseBoolQuery(v)
		if !ok {
			http.Error(w, "invalid flagged boolean", http.StatusBadRequest)
			return
		}
		q.Flagged = &flagged
	}

	if v := params.Get("sort"); v != "" {
		if v != "asc" && v != "desc" {
			http.Error(w, "invalid sort: use 'asc' or 'desc'", http.StatusBadRequest)
			return
		}
		q.SortOrder = v
	}

	if v := params.Get("time_from"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			http.Error(w, "invalid time_from: use RFC3339 format", http.StatusBadRequest)
			return
		}
		q.TimeFrom = &t
	}

	if v := params.Get("time_to"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			http.Error(w, "invalid time_to: use RFC3339 format", http.StatusBadRequest)
			return
		}
		q.TimeTo = &t
	}

	if v := params.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			http.Error(w, "invalid limit", http.StatusBadRequest)
			return
		}
		q.Limit = n
		if q.Limit > 500 {
			q.Limit = 500
		}
	}

	if v := params.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			http.Error(w, "invalid offset", http.StatusBadRequest)
			return
		}
		if n > 10_000_000 {
			http.Error(w, "offset is too large", http.StatusBadRequest)
			return
		}
		q.Offset = n
	}

	if v := params.Get("contains_flagid"); v != "" {
		b, ok := parseBoolQuery(v)
		if !ok {
			http.Error(w, "invalid contains_flagid boolean", http.StatusBadRequest)
			return
		}
		q.ContainsFlagID = &b
	}
	if v := params.Get("flagid_round"); v != "" {
		round, err := strconv.Atoi(v)
		if err != nil || round < 0 {
			http.Error(w, "invalid flagid_round", http.StatusBadRequest)
			return
		}
		q.FlagIDRound = &round
	}

	if v := params.Get("has_matched_rules"); v != "" {
		b, ok := parseBoolQuery(v)
		if !ok {
			http.Error(w, "invalid has_matched_rules boolean", http.StatusBadRequest)
			return
		}
		q.HasMatchedRules = &b
	}

	if v := params.Get("dropped"); v != "" {
		b, ok := parseBoolQuery(v)
		if !ok {
			http.Error(w, "invalid dropped boolean", http.StatusBadRequest)
			return
		}
		q.Dropped = &b
	}

	if v := params.Get("summary"); v == "true" || v == "1" {
		q.Summary = true
	}

	// Per-user hide filters (client-sent): exclude_ids=comma,separated and hidden_before=RFC3339.
	if v := params.Get("exclude_ids"); v != "" {
		parts := strings.Split(v, ",")
		if len(parts) > 500 {
			parts = parts[:500]
		}
		ids := make([]int64, 0, len(parts))
		for _, p := range parts {
			if id, err := strconv.ParseInt(strings.TrimSpace(p), 10, 64); err == nil {
				ids = append(ids, id)
			}
		}
		q.ExcludeIDs = ids
	}
	if v := params.Get("hidden_before"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			http.Error(w, "invalid hidden_before: use RFC3339 format", http.StatusBadRequest)
			return
		}
		q.HiddenBefore = &t
	}

	packets, total, meta, err := s.packetStore.QueryPage(q)
	if err != nil {
		http.Error(w, "query error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if packets == nil {
		packets = []*sniffer.Packet{}
	}
	s.annotateRounds(packets)

	limit := q.Limit
	if limit <= 0 {
		limit = 50
	}

	result := paginatedPackets{
		Packets:    packets,
		Total:      total,
		Limit:      limit,
		Offset:     q.Offset,
		TotalExact: meta.TotalExact,
		Partial:    meta.Partial,
		NextCursor: encodePacketCursor(meta.NextTimestamp, meta.NextID),
	}

	writeJSON(w, http.StatusOK, result)
}

func decodePacketCursor(raw string) (packetCursor, error) {
	if len(raw) > 512 {
		return packetCursor{}, fmt.Errorf("cursor too long")
	}
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return packetCursor{}, err
	}
	var cursor packetCursor
	if err := json.Unmarshal(data, &cursor); err != nil {
		return packetCursor{}, err
	}
	timestamp, err := time.Parse(time.RFC3339Nano, cursor.Timestamp)
	if err != nil || cursor.ID <= 0 {
		return packetCursor{}, fmt.Errorf("invalid cursor payload")
	}
	cursor.Timestamp = sniffer.CanonicalTimestamp(timestamp)
	return cursor, nil
}

func encodePacketCursor(timestamp time.Time, id int64) string {
	if timestamp.IsZero() || id <= 0 {
		return ""
	}
	data, err := json.Marshal(packetCursor{Timestamp: sniffer.CanonicalTimestamp(timestamp), ID: id})
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

func (s *Server) handlePacketByID(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/packets/")
	if idStr == "" {
		http.Error(w, "missing packet ID", http.StatusBadRequest)
		return
	}

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid packet ID", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		pkt, err := s.packetStore.GetPacketByID(id)
		if err != nil {
			http.Error(w, "packet not found", http.StatusNotFound)
			return
		}
		s.annotateRound(pkt)
		writeJSON(w, http.StatusOK, pkt)

	case http.MethodDelete:
		n, err := s.packetStore.DeletePacketIDs([]int64{id})
		if err != nil {
			http.Error(w, "delete error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if n == 0 {
			http.Error(w, "packet not found", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, map[string]int64{"deleted": n})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handlePacketsBulkDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		IDs []int64 `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(body.IDs) == 0 {
		writeJSON(w, http.StatusOK, map[string]int64{"deleted": 0})
		return
	}
	if len(body.IDs) > 500 {
		http.Error(w, "ids must contain at most 500 packets", http.StatusBadRequest)
		return
	}
	for _, id := range body.IDs {
		if id <= 0 {
			http.Error(w, "ids must contain only positive packet IDs", http.StatusBadRequest)
			return
		}
	}

	n, err := s.packetStore.DeletePacketIDs(body.IDs)
	if err != nil {
		http.Error(w, "bulk delete error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("[user=%s] action=bulk-delete-packets count=%d", DisplayNameFromRequest(r), n)
	writeJSON(w, http.StatusOK, map[string]int64{"deleted": n})
}

func (s *Server) handlePacketsLabel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		IDs   []int64 `json:"ids"`
		Label string  `json:"label"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if len(req.IDs) == 0 || len(req.IDs) > 500 {
		http.Error(w, "ids must contain 1 to 500 packets", http.StatusBadRequest)
		return
	}
	switch req.Label {
	case "", "exploit", "checker", "normal":
	default:
		http.Error(w, "label must be exploit, checker, normal, or empty", http.StatusBadRequest)
		return
	}
	if err := s.packetStore.SetAnalystLabel(req.IDs, req.Label); err != nil {
		http.Error(w, "failed to set label", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"updated": len(req.IDs), "label": req.Label})
}

func (s *Server) handlePacketFlow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	packetIDStr := r.URL.Query().Get("packet_id")
	if packetIDStr == "" {
		http.Error(w, "packet_id is required", http.StatusBadRequest)
		return
	}

	packetID, err := strconv.ParseInt(packetIDStr, 10, 64)
	if err != nil || packetID <= 0 {
		http.Error(w, fmt.Sprintf("invalid packet_id: %v", err), http.StatusBadRequest)
		return
	}

	packets, err := s.packetStore.QueryFlow(packetID)
	if err != nil {
		http.Error(w, "flow query error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if packets == nil {
		packets = []*sniffer.Packet{}
	}
	s.annotateRounds(packets)

	writeJSON(w, http.StatusOK, paginatedPackets{
		Packets: packets,
		Total:   len(packets),
		Limit:   len(packets),
		Offset:  0,
	})
}

func parseBoolQuery(value string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "1":
		return true, true
	case "false", "0":
		return false, true
	default:
		return false, false
	}
}
