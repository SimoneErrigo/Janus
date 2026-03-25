package api

import (
	"net/http"
	"strconv"
	"time"

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

	writeJSON(w, http.StatusOK, paginatedPackets{
		Packets: packets,
		Total:   total,
		Limit:   limit,
		Offset:  q.Offset,
	})
}
