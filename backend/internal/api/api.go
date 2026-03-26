package api

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/SimoneErrigo/Janus/backend/internal/cleanup"
	"github.com/SimoneErrigo/Janus/backend/internal/dropper"
	"github.com/SimoneErrigo/Janus/backend/internal/proxy"
	"github.com/SimoneErrigo/Janus/backend/internal/sniffer"
	"github.com/SimoneErrigo/Janus/backend/internal/storage"
)

// Server holds the REST API dependencies.
type Server struct {
	store       *storage.Store
	proxy       *proxy.Manager
	packetStore *sniffer.PacketStore
	ruleStore   *dropper.RuleStore
	cleanupMgr  *cleanup.Manager
	mux         *http.ServeMux
}

// NewServer creates a new API server.
func NewServer(store *storage.Store, proxyMgr *proxy.Manager, packetStore *sniffer.PacketStore, ruleStore *dropper.RuleStore, cleanupMgr *cleanup.Manager) *Server {
	s := &Server{
		store:       store,
		proxy:       proxyMgr,
		packetStore: packetStore,
		ruleStore:   ruleStore,
		cleanupMgr:  cleanupMgr,
		mux:         http.NewServeMux(),
	}
	s.routes()
	return s
}

// Handler returns the HTTP handler for this server.
func (s *Server) Handler() http.Handler {
	return corsMiddleware(s.mux)
}

func (s *Server) routes() {
	// Public routes (no auth required)
	s.mux.HandleFunc("/api/login", s.handleLogin)

	// Protected routes (auth required)
	protected := http.NewServeMux()
	protected.HandleFunc("/api/services", s.handleServices)
	protected.HandleFunc("/api/services/", s.handleServiceByID)
	protected.HandleFunc("/api/packets", s.handlePackets)
	protected.HandleFunc("/api/rules", s.handleRules)
	protected.HandleFunc("/api/rules/", s.handleRuleByID)
	protected.HandleFunc("/api/alerts", s.handleAlerts)
	protected.HandleFunc("/api/alerts/", s.handleAlertByID)
	protected.HandleFunc("/api/config", s.handleConfig)
	protected.HandleFunc("/api/config/cleanup", s.handleCleanupConfig)
	protected.HandleFunc("/api/cleanup/run", s.handleCleanupRun)

	s.mux.Handle("/api/", authMiddleware(protected))
}

// corsMiddleware adds CORS headers for the frontend.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
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
