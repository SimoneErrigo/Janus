package api

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/SimoneErrigo/Janus/backend/internal/proxy"
	"github.com/SimoneErrigo/Janus/backend/internal/sniffer"
	"github.com/SimoneErrigo/Janus/backend/internal/storage"
)

// Server holds the REST API dependencies.
type Server struct {
	store       *storage.Store
	proxy       *proxy.Manager
	packetStore *sniffer.PacketStore
	mux         *http.ServeMux
}

// NewServer creates a new API server.
func NewServer(store *storage.Store, proxyMgr *proxy.Manager, packetStore *sniffer.PacketStore) *Server {
	s := &Server{
		store:       store,
		proxy:       proxyMgr,
		packetStore: packetStore,
		mux:         http.NewServeMux(),
	}
	s.routes()
	return s
}

// Handler returns the HTTP handler for this server.
func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) routes() {
	s.mux.HandleFunc("/api/services", s.handleServices)
	s.mux.HandleFunc("/api/services/", s.handleServiceByID)
	s.mux.HandleFunc("/api/packets", s.handlePackets)
}

func (s *Server) handleServices(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listServices(w, r)
	case http.MethodPost:
		s.createService(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleServiceByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/services/")
	if id == "" {
		http.Error(w, "missing service ID", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.getService(w, r, id)
	case http.MethodPut:
		s.updateService(w, r, id)
	case http.MethodDelete:
		s.deleteService(w, r, id)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) listServices(w http.ResponseWriter, r *http.Request) {
	services := s.store.ListServices()
	writeJSON(w, http.StatusOK, services)
}

func (s *Server) getService(w http.ResponseWriter, r *http.Request, id string) {
	svc, ok := s.store.GetService(id)
	if !ok {
		http.Error(w, "service not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, svc)
}

func (s *Server) createService(w http.ResponseWriter, r *http.Request) {
	var svc storage.Service
	if err := json.NewDecoder(r.Body).Decode(&svc); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := validateService(&svc); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := s.store.CreateService(&svc); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	if svc.Enabled {
		if err := s.proxy.StartService(&svc); err != nil {
			log.Printf("Warning: service created but proxy failed to start: %v", err)
		}
	}

	log.Printf("Service created: %s (%s)", svc.Name, svc.ID)
	writeJSON(w, http.StatusCreated, svc)
}

func (s *Server) updateService(w http.ResponseWriter, r *http.Request, id string) {
	var svc storage.Service
	if err := json.NewDecoder(r.Body).Decode(&svc); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	svc.ID = id

	if err := validateService(&svc); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := s.store.UpdateService(&svc); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	// Restart proxy if enabled, stop if disabled
	if svc.Enabled {
		if err := s.proxy.RestartService(&svc); err != nil {
			log.Printf("Warning: service updated but proxy failed to restart: %v", err)
		}
	} else {
		s.proxy.StopService(svc.ID)
	}

	log.Printf("Service updated: %s (%s)", svc.Name, svc.ID)
	writeJSON(w, http.StatusOK, svc)
}

func (s *Server) deleteService(w http.ResponseWriter, r *http.Request, id string) {
	s.proxy.StopService(id)

	if err := s.store.DeleteService(id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	log.Printf("Service deleted: %s", id)
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
	}
}
