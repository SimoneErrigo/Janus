package api

import (
	"net/http"
	"strconv"

	"github.com/SimoneErrigo/Janus/backend/internal/protodecode"
)

// handlePacketDecoded decodes a captured gRPC packet body into JSON using
// the .proto files configured on the owning service. URL: /api/packets/decoded?packet_id=N
//
// Resolution order for proto paths:
//  1. svc.ProtoPaths if set
//  2. files auto-discovered under PROTO_DIR (default /protos)
//
// The fallback lets users decode bodies without per-service configuration:
// drop the .proto into the mounted protos/ folder and it just works.
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

	paths := svc.ProtoPaths
	cacheKey := svc.ID
	if len(paths) == 0 {
		paths = protodecode.DiscoverProtoFiles(s.protoDir)
		// Use a shared cache key so discovery results are reused across services.
		cacheKey = "__discovery__"
	}
	if len(paths) == 0 {
		http.Error(w, "no .proto paths configured for this service and none auto-discovered", http.StatusBadRequest)
		return
	}

	// For paired request/response, the URL is set on both packets to the
	// request path, so we can resolve the method either way and pick
	// input vs output type based on direction.
	result, err := s.protoCache.Decode(cacheKey, paths, pkt.URL, string(pkt.Direction), pkt.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// handleListProtos returns the list of .proto files auto-discovered under
// the configured PROTO_DIR. Used by the frontend to offer a picker so
// users don't have to type container paths by hand.
func (s *Server) handleListProtos(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	files := protodecode.DiscoverProtoFiles(s.protoDir)
	if files == nil {
		files = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"dir":   s.protoDir,
		"files": files,
	})
}
