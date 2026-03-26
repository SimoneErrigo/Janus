package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/SimoneErrigo/Janus/backend/internal/cache"
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
	q.SessionID = params.Get("session_id")
	q.PeerIP = params.Get("peer_ip")
	q.Contains = params.Get("contains")
	q.Regex = params.Get("regex")

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

	containsFlagID := params.Get("contains_flagid") == "true" || params.Get("contains_flagid") == "1"

	// Build cache key from all query params
	serviceIDForCache := q.ServiceID
	if serviceIDForCache == "" {
		serviceIDForCache = "_all"
	}

	// Only cache queries without contains_flagid (live data, not cacheable)
	canCache := !containsFlagID && s.cache != nil
	var queryHash string
	if canCache {
		qp := make(map[string]string)
		for k, v := range params {
			if len(v) > 0 {
				qp[k] = v[0]
			}
		}
		queryHash = cache.QueryHash(qp)

		if cached, ok := s.cache.GetPacketQuery(serviceIDForCache, queryHash); ok {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Cache", "HIT")
			w.WriteHeader(http.StatusOK)
			w.Write(cached)
			return
		}
	}

	packets, total, err := s.packetStore.Query(q)
	if err != nil {
		http.Error(w, "query error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if packets == nil {
		packets = []*sniffer.Packet{}
	}

	// Apply contains_flagid filter in-memory using live flag ID values
	if containsFlagID && s.flagIDPoller != nil && s.flagIDPoller.IsEnabled() {
		var filtered []*sniffer.Packet
		for _, pkt := range packets {
			text := pkt.BodyString + " " + pkt.URL
			for k, v := range pkt.Headers {
				text += " " + k + ": " + v
			}
			if s.flagIDPoller.ContainsFlagID(text) {
				filtered = append(filtered, pkt)
			}
		}
		total = len(filtered)
		packets = filtered
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

	// Cache the result
	if canCache {
		if data, err := json.Marshal(result); err == nil {
			s.cache.SetPacketQuery(serviceIDForCache, queryHash, data)
		}
	}

	w.Header().Set("X-Cache", "MISS")
	writeJSON(w, http.StatusOK, result)
}
