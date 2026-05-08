package api

import (
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
	Packets []*sniffer.Packet `json:"packets"`
	Total   int               `json:"total"`
	Limit   int               `json:"limit"`
	Offset  int               `json:"offset"`
}

func (s *Server) handlePackets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := sniffer.PacketQuery{}
	params := r.URL.Query()

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
	if v := params.Get("not_direction"); v != "" {
		dir := strings.ToLower(strings.TrimSpace(v))
		switch dir {
		case "req", "request":
			q.NotDirection = "request"
		case "res", "response":
			q.NotDirection = "response"
		}
	}

	if v := params.Get("flagged"); v != "" {
		flagged := v == "true" || v == "1"
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
	}

	if v := params.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			http.Error(w, "invalid offset", http.StatusBadRequest)
			return
		}
		q.Offset = n
	}

	if v := params.Get("contains_flagid"); v != "" {
		b := v == "true" || v == "1"
		q.ContainsFlagID = &b
	}

	if v := params.Get("has_matched_rules"); v != "" {
		b := v == "true" || v == "1"
		q.HasMatchedRules = &b
	}

	if v := params.Get("dropped"); v != "" {
		b := v == "true" || v == "1"
		q.Dropped = &b
	}

	if v := params.Get("summary"); v == "true" || v == "1" {
		q.Summary = true
	}

	// Per-user hide filters (client-sent): exclude_ids=comma,separated and hidden_before=RFC3339.
	if v := params.Get("exclude_ids"); v != "" {
		parts := strings.Split(v, ",")
		if len(parts) > 2000 {
			parts = parts[:2000]
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

	packets, total, err := s.packetStore.Query(q)
	if err != nil {
		http.Error(w, "query error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if packets == nil {
		packets = []*sniffer.Packet{}
	}

	limit := q.Limit
	if limit <= 0 {
		limit = 50
	}

	result := paginatedPackets{
		Packets: packets,
		Total:   total,
		Limit:   limit,
		Offset:  q.Offset,
	}

	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handlePacketByID(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/packets/")
	if idStr == "" {
		http.Error(w, "missing packet ID", http.StatusBadRequest)
		return
	}

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
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

	n, err := s.packetStore.DeletePacketIDs(body.IDs)
	if err != nil {
		http.Error(w, "bulk delete error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("[user=%s] action=bulk-delete-packets count=%d", DisplayNameFromRequest(r), n)
	writeJSON(w, http.StatusOK, map[string]int64{"deleted": n})
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
	if err != nil {
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

	writeJSON(w, http.StatusOK, paginatedPackets{
		Packets: packets,
		Total:   len(packets),
		Limit:   len(packets),
		Offset:  0,
	})
}
