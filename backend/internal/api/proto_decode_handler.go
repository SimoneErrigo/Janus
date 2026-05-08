package api

import (
	"net/http"
	"strconv"
)

// handlePacketDecoded decodes a captured gRPC packet body into JSON using
// the .proto files configured on the owning service. URL: /api/packets/decoded?packet_id=N
func (s *Server) handlePacketDecoded(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	idStr := r.URL.Query().Get("packet_id")
	if idStr == "" {
		http.Error(w, "missing packet_id", http.StatusBadRequest)
		return
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid packet_id", http.StatusBadRequest)
		return
	}

	pkt, err := s.packetStore.GetPacketByID(id)
	if err != nil {
		http.Error(w, "packet not found", http.StatusNotFound)
		return
	}

	svc, ok := s.store.GetService(pkt.ServiceID)
	if !ok {
		http.Error(w, "service for packet not found", http.StatusNotFound)
		return
	}
	if len(svc.ProtoPaths) == 0 {
		http.Error(w, "no .proto paths configured for this service", http.StatusBadRequest)
		return
	}

	// For paired request/response, the URL is set on both packets to the
	// request path, so we can resolve the method either way and pick
	// input vs output type based on direction.
	result, err := s.protoCache.Decode(svc.ID, svc.ProtoPaths, pkt.URL, string(pkt.Direction), pkt.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, result)
}
