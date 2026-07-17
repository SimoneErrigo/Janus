package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/SimoneErrigo/Janus/backend/internal/sniffer"
)

// GET  /api/flows/saved        — list all saved flows
// POST /api/flows/saved        — pin a new flow from an anchor packet
// GET  /api/flows/saved/{id}   — get flow detail with full packets
// DELETE /api/flows/saved/{id} — delete a saved flow

func (s *Server) handleSavedFlows(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listSavedFlows(w, r)
	case http.MethodPost:
		s.createSavedFlow(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleSavedFlowByID(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/flows/saved/")
	if idStr == "" {
		http.Error(w, "missing flow ID", http.StatusBadRequest)
		return
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid flow ID", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.getSavedFlow(w, r, id)
	case http.MethodDelete:
		s.deleteSavedFlow(w, r, id)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) listSavedFlows(w http.ResponseWriter, r *http.Request) {
	flows, err := s.packetStore.ListSavedFlows()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if flows == nil {
		flows = []*sniffer.SavedFlow{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"flows": flows})
}

func (s *Server) createSavedFlow(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AnchorPacketID int64   `json:"anchor_packet_id"`
		PacketIDs      []int64 `json:"packet_ids"`
		Name           string  `json:"name"`
		Notes          string  `json:"notes"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.AnchorPacketID < 0 || (req.AnchorPacketID == 0 && len(req.PacketIDs) == 0) {
		http.Error(w, "anchor_packet_id or packet_ids is required", http.StatusBadRequest)
		return
	}
	if len(req.PacketIDs) > 500 {
		http.Error(w, "packet_ids must contain at most 500 packets", http.StatusBadRequest)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if len(req.Name) > 256 || len(req.Notes) > 16<<10 {
		http.Error(w, "name or notes is too long", http.StatusBadRequest)
		return
	}

	var packets []*sniffer.Packet
	var ids []int64

	if len(req.PacketIDs) > 0 {
		// Pin an arbitrary selection of packets — they don't need to belong to
		// the same logical flow. Snapshot in chronological order.
		packets = make([]*sniffer.Packet, 0, len(req.PacketIDs))
		seen := make(map[int64]struct{}, len(req.PacketIDs))
		for _, pid := range req.PacketIDs {
			if pid <= 0 {
				http.Error(w, "packet_ids must be positive", http.StatusBadRequest)
				return
			}
			if _, duplicate := seen[pid]; duplicate {
				continue
			}
			seen[pid] = struct{}{}
			pkt, err := s.packetStore.GetPacketByID(pid)
			if err != nil {
				http.Error(w, "packet not found: "+strconv.FormatInt(pid, 10), http.StatusNotFound)
				return
			}
			packets = append(packets, pkt)
		}
		if len(packets) == 0 {
			http.Error(w, "no packets found for the given ids", http.StatusNotFound)
			return
		}
		sort.SliceStable(packets, func(i, j int) bool {
			if packets[i].Timestamp.Equal(packets[j].Timestamp) {
				return packets[i].ID < packets[j].ID
			}
			return packets[i].Timestamp.Before(packets[j].Timestamp)
		})
		if req.AnchorPacketID == 0 {
			req.AnchorPacketID = packets[0].ID
		}
		ids = make([]int64, len(packets))
		for i, p := range packets {
			ids[i] = p.ID
		}
	} else {
		// Resolve the flow from the anchor packet and snapshot its full packets
		var err error
		packets, err = s.packetStore.QueryFlow(req.AnchorPacketID)
		if err != nil {
			http.Error(w, "flow query error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		ids = make([]int64, len(packets))
		for i, p := range packets {
			ids[i] = p.ID
		}
	}

	if req.Name == "" {
		req.Name = "Flow #" + strconv.FormatInt(req.AnchorPacketID, 10)
	}

	sf := &sniffer.SavedFlow{
		Name:           req.Name,
		AnchorPacketID: req.AnchorPacketID,
		PacketIDs:      ids,
		CreatedBy:      DisplayNameFromRequest(r),
		CreatedAt:      time.Now(),
		Notes:          req.Notes,
	}
	if err := s.packetStore.InsertSavedFlow(sf, packets); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, sf)
}

func (s *Server) getSavedFlow(w http.ResponseWriter, r *http.Request, id int64) {
	sf, err := s.packetStore.GetSavedFlowByID(id)
	if err != nil {
		http.Error(w, "saved flow not found", http.StatusNotFound)
		return
	}

	// Prefer the snapshotted packets — they survive packet purges.
	packets, err := s.packetStore.GetSavedFlowSnapshot(id)
	if err != nil {
		http.Error(w, "snapshot read error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	missingCount := 0
	if len(packets) == 0 {
		// Legacy flow pinned before snapshots existed: fall back to live packets.
		packets = make([]*sniffer.Packet, 0, len(sf.PacketIDs))
		for _, pid := range sf.PacketIDs {
			pkt, err := s.packetStore.GetPacketByID(pid)
			if err != nil {
				missingCount++
				continue
			}
			packets = append(packets, pkt)
		}
	}
	s.annotateRounds(packets)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"flow":          sf,
		"packets":       packets,
		"missing_count": missingCount,
	})
}

func (s *Server) deleteSavedFlow(w http.ResponseWriter, r *http.Request, id int64) {
	if err := s.packetStore.DeleteSavedFlow(id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
