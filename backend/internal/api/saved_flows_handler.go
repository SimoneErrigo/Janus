package api

import (
	"encoding/json"
	"net/http"
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
	if err != nil {
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
		AnchorPacketID int64  `json:"anchor_packet_id"`
		Name           string `json:"name"`
		Notes          string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.AnchorPacketID == 0 {
		http.Error(w, "anchor_packet_id is required", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		req.Name = "Flow #" + strconv.FormatInt(req.AnchorPacketID, 10)
	}

	// Resolve the flow from the anchor packet and snapshot its IDs
	packets, err := s.packetStore.QueryFlow(req.AnchorPacketID)
	if err != nil {
		http.Error(w, "flow query error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	ids := make([]int64, len(packets))
	for i, p := range packets {
		ids[i] = p.ID
	}

	sf := &sniffer.SavedFlow{
		Name:           req.Name,
		AnchorPacketID: req.AnchorPacketID,
		PacketIDs:      ids,
		CreatedBy:      DisplayNameFromRequest(r),
		CreatedAt:      time.Now(),
		Notes:          req.Notes,
	}
	if err := s.packetStore.InsertSavedFlow(sf); err != nil {
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

	// Re-fetch packets by ID; gracefully handle deletions
	packets := make([]*sniffer.Packet, 0, len(sf.PacketIDs))
	missingCount := 0
	for _, pid := range sf.PacketIDs {
		pkt, err := s.packetStore.GetPacketByID(pid)
		if err != nil {
			missingCount++
			continue
		}
		packets = append(packets, pkt)
	}

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
