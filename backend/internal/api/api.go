package api

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/SimoneErrigo/Janus/backend/internal/cache"
	"github.com/SimoneErrigo/Janus/backend/internal/cleanup"
	"github.com/SimoneErrigo/Janus/backend/internal/dropper"
	"github.com/SimoneErrigo/Janus/backend/internal/flagids"
	"github.com/SimoneErrigo/Janus/backend/internal/protodecode"
	"github.com/SimoneErrigo/Janus/backend/internal/proxy"
	"github.com/SimoneErrigo/Janus/backend/internal/pyfilter"
	"github.com/SimoneErrigo/Janus/backend/internal/rounddiff"
	"github.com/SimoneErrigo/Janus/backend/internal/scoring"
	"github.com/SimoneErrigo/Janus/backend/internal/sniffer"
	"github.com/SimoneErrigo/Janus/backend/internal/storage"
	"github.com/SimoneErrigo/Janus/backend/internal/sysstat"
)

// Server holds the REST API dependencies.
type Server struct {
	store          storage.Repository
	proxy          *proxy.Manager
	packetStore    *sniffer.PacketStore
	ruleStore      *dropper.RuleStore
	cleanupMgr     *cleanup.Manager
	flagIDPoller   *flagids.Poller
	cache          *cache.Client
	statsCollector *sysstat.Collector
	packetHub      *PacketStreamHub
	captureCtrl    *sniffer.CaptureController
	sessionHub     *SessionHub
	protoCache     *protodecode.Cache
	protoDir       string
	roundDiffCache *rounddiff.Cache
	pyfilter       *pyfilter.Manager
	scoring        scoringProvider
	loginLimiter   loginLimiter
	configMu       sync.Mutex
	serviceMu      sync.Mutex
	ruleMu         sync.Mutex
	protocolMu     sync.Mutex
	mux            *http.ServeMux
}

type scoringProvider interface {
	Status() scoring.Status
	ConfigureBaseline(scoring.BaselineConfig) error
	RebuildBaseline() error
}

// NewServer creates a new API server.
func NewServer(store storage.Repository, proxyMgr *proxy.Manager, packetStore *sniffer.PacketStore, ruleStore *dropper.RuleStore, cleanupMgr *cleanup.Manager, flagIDPoller *flagids.Poller, cacheClient *cache.Client, statsCollector *sysstat.Collector, packetHub *PacketStreamHub, captureCtrl *sniffer.CaptureController, protoDir string, pyMgr *pyfilter.Manager) *Server {
	s := &Server{
		store:          store,
		proxy:          proxyMgr,
		packetStore:    packetStore,
		ruleStore:      ruleStore,
		cleanupMgr:     cleanupMgr,
		flagIDPoller:   flagIDPoller,
		cache:          cacheClient,
		statsCollector: statsCollector,
		packetHub:      packetHub,
		captureCtrl:    captureCtrl,
		sessionHub:     NewSessionHub(),
		protoCache:     protodecode.NewCache(),
		protoDir:       protoDir,
		roundDiffCache: rounddiff.NewCache(128, 30*time.Minute),
		pyfilter:       pyMgr,
		mux:            http.NewServeMux(),
	}
	s.routes()
	return s
}

// Handler returns the HTTP handler for this server.
func (s *Server) Handler() http.Handler {
	return corsMiddleware(requestBodyLimitMiddleware(s.mux))
}

func (s *Server) SetScoringStatusProvider(provider scoringProvider) {
	s.scoring = provider
}

func (s *Server) prewarmPyFilters(serviceID string) {
	if s.pyfilter != nil {
		if err := s.pyfilter.PrewarmServices([]string{serviceID}); err != nil {
			log.Printf("Warning: failed to prewarm Python filters for %s: %v", serviceID, err)
		}
	}
}

// annotateRound fills the `Round` field on a packet from competition timing,
// falling back to the round of a matched Flag ID when timing is unavailable.
func (s *Server) annotateRound(p *sniffer.Packet) {
	if p == nil || s.flagIDPoller == nil {
		return
	}
	p.Round = s.flagIDPoller.RoundForTime(p.Timestamp)
	if p.Round == 0 && p.FlagIDRound > 0 {
		p.Round = p.FlagIDRound
	}
}

// annotateRounds is the slice form, used by every endpoint that returns a
// list of packets.
func (s *Server) annotateRounds(pkts []*sniffer.Packet) {
	if s.flagIDPoller == nil {
		return
	}
	for _, p := range pkts {
		s.annotateRound(p)
	}
}

func (s *Server) routes() {
	// Public routes (no auth required)
	s.mux.HandleFunc("/api/login", s.handleLogin)

	// Protected routes (auth required)
	protected := http.NewServeMux()
	protected.HandleFunc("/api/services", s.handleServices)
	protected.HandleFunc("/api/services/", s.handleServiceByID)
	protected.HandleFunc("/api/protocol-presets", s.handleProtocolPresets)
	// Proxy listener health / retry controls. Kept under /api/proxy/ rather
	// than /api/services/ so the path can't ever be shadowed by a service
	// whose ID happens to be "status" or "retry-all" (validateService allows
	// both spellings).
	protected.HandleFunc("/api/proxy/statuses", s.handleServicesStatus)
	protected.HandleFunc("/api/proxy/retry-all", s.handleServicesRetryAll)
	protected.HandleFunc("/api/packets/stream", s.handlePacketStream)
	protected.HandleFunc("/api/packets/flow/pcap", s.handleFlowPcap)
	protected.HandleFunc("/api/packets/flow", s.handlePacketFlow)
	protected.HandleFunc("/api/packets/exploit", s.handleExploitGen)
	protected.HandleFunc("/api/packets/decoded", s.handlePacketDecoded)
	protected.HandleFunc("/api/packets/decoded-custom", s.handlePacketDecodedCustom)
	protected.HandleFunc("/api/protos", s.handleListProtos)
	protected.HandleFunc("/api/protos/encode-field", s.handleProtoEncodeField)
	protected.HandleFunc("/api/protocols/import", s.handleProtocolImport)
	protected.HandleFunc("/api/protocols", s.handleProtocols)
	protected.HandleFunc("/api/protocols/", s.handleProtocolByID)
	protected.HandleFunc("/api/packets/bulk-delete", s.handlePacketsBulkDelete)
	protected.HandleFunc("/api/packets/label", s.handlePacketsLabel)
	protected.HandleFunc("/api/packets/", s.handlePacketByID)
	protected.HandleFunc("/api/packets", s.handlePackets)
	protected.HandleFunc("/api/rules/presets/apply", s.handlePresetsApply)
	protected.HandleFunc("/api/rules/presets", s.handlePresetsGet)
	protected.HandleFunc("/api/rules/bulk-delete", s.handleRulesBulkDelete)
	protected.HandleFunc("/api/rules", s.handleRules)
	protected.HandleFunc("/api/rules/", s.handleRuleByID)
	protected.HandleFunc("/api/alerts", s.handleAlerts)
	protected.HandleFunc("/api/alerts/", s.handleAlertByID)
	protected.HandleFunc("/api/config", s.handleConfig)
	protected.HandleFunc("/api/config/cleanup", s.handleCleanupConfig)
	protected.HandleFunc("/api/cleanup/run", s.handleCleanupRun)
	protected.HandleFunc("/api/cleanup/purge", s.handleCleanupPurge)
	protected.HandleFunc("/api/cleanup/purge-packets", s.handleCleanupPurgePackets)
	protected.HandleFunc("/api/cleanup/purge-dropped", s.handleCleanupPurgeDropped)
	protected.HandleFunc("/api/flagids", s.handleFlagIDs)
	protected.HandleFunc("/api/flagids/status", s.handleFlagIDStatus)
	protected.HandleFunc("/api/flagids/refresh", s.handleFlagIDRefresh)
	protected.HandleFunc("/api/traffic/capture", s.handleTrafficCaptureStatus)
	protected.HandleFunc("/api/traffic/capture/start", s.handleTrafficCaptureStart)
	protected.HandleFunc("/api/traffic/capture/stop", s.handleTrafficCaptureStop)
	protected.HandleFunc("/api/traffic/capture/apply-flagids", s.handleTrafficCaptureApplyFlagIDs)
	protected.HandleFunc("/api/system/stats", s.handleSystemStats)
	protected.HandleFunc("/api/filter/validate", s.handleFilterValidate)
	protected.HandleFunc("/api/filter/schema", s.handleFilterSchema)
	protected.HandleFunc("/api/scoring/status", s.handleScoringStatus)
	protected.HandleFunc("/api/scoring/baseline/rebuild", s.handleScoringBaselineRebuild)
	protected.HandleFunc("/api/session/active", s.handleSessionActive)
	protected.HandleFunc("/api/logout", s.handleLogout)
	protected.HandleFunc("/api/flows/saved/", s.handleSavedFlowByID)
	protected.HandleFunc("/api/flows/saved", s.handleSavedFlows)
	protected.HandleFunc("/api/pcap/export", s.handlePcapExport)
	protected.HandleFunc("/api/pcap/export-selection", s.handlePcapExportSelection)
	protected.HandleFunc("/api/pcap/files/", s.handlePcapFile)
	protected.HandleFunc("/api/pcap/files", s.handlePcapListFiles)
	protected.HandleFunc("/api/pcap/import", s.handlePcapImport)
	protected.HandleFunc("/api/pcap/import/", s.handlePcapImportStatus)
	protected.HandleFunc("/api/round-diff", s.handleRoundDiff)
	// Python filters (mitmproxy-style scriptable filtering). Engine endpoints
	// live under /api/pyfilter-engine/ rather than /api/pyfilters/ so they
	// can't ever be shadowed by a script whose slug is "status" or "test"
	// (slugID allows both).
	protected.HandleFunc("/api/pyfilter-engine/status", s.handlePyFilterStatus)
	protected.HandleFunc("/api/pyfilter-engine/test", s.handlePyFilterTest)
	protected.HandleFunc("/api/pyfilters", s.handlePyFilters)
	protected.HandleFunc("/api/pyfilters/", s.handlePyFilterByID)

	s.mux.Handle("/api/", s.authMiddleware(protected))
}

// corsMiddleware adds CORS headers for the frontend.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			if !sameHostOrigin(origin, r.Host) {
				http.Error(w, "origin not allowed", http.StatusForbidden)
				return
			} else {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Add("Vary", "Origin")
			}
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func sameHostOrigin(origin, requestHost string) bool {
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		return false
	}
	// SameSite cookies do not isolate ports. Compare the complete authority so
	// an unrelated web service on another port of the team host cannot make
	// credentialed Janus calls and read their responses through CORS.
	return strings.EqualFold(strings.TrimSpace(requestHost), u.Host)
}

func requestBodyLimitMiddleware(next http.Handler) http.Handler {
	const maxRequestBytes = 16 << 20
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// PCAP imports enforce their own larger multipart/file limits.
		if r.Body != nil && r.URL.Path != "/api/pcap/import" {
			if r.ContentLength > maxRequestBytes {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
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
	rest := strings.TrimPrefix(r.URL.Path, "/api/services/")
	if rest == "" {
		http.Error(w, "missing service ID", http.StatusBadRequest)
		return
	}

	// Subpath actions: /api/services/{id}/{action}. Today the only supported
	// action is /retry, which kicks the bind-retry loop immediately. Adding
	// new actions just means another case here — keeps URL layout REST-y
	// without forcing us to register a new prefix mux entry per verb.
	if idx := strings.Index(rest, "/"); idx >= 0 {
		id := rest[:idx]
		action := rest[idx+1:]
		switch action {
		case "retry":
			s.handleServiceRetry(w, r, id)
			return
		default:
			http.Error(w, "unknown action", http.StatusNotFound)
			return
		}
	}

	id := rest
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

// handleServicesStatus returns a map of serviceID -> proxy.Status so the UI
// can render real listener state (running / retrying + last bind error)
// instead of just the configured "enabled" flag.
func (s *Server) handleServicesStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	statuses := s.proxy.AllStatuses()
	out := make(map[string]proxy.Status, len(statuses))
	for _, st := range statuses {
		out[st.ServiceID] = st
	}
	writeJSON(w, http.StatusOK, out)
}

// handleServiceRetry kicks the bind-retry loop for a single service to run
// immediately. Use case: user just rebuilt the underlying container and
// doesn't want to wait for the next 1s tick. Idempotent — kicks are
// coalesced inside the manager.
func (s *Server) handleServiceRetry(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.proxy.IsRegistered(id) {
		http.Error(w, "service not found", http.StatusNotFound)
		return
	}
	s.proxy.KickRetry(id) // false just means "already running" — not an error
	st, _ := s.proxy.Status(id)
	writeJSON(w, http.StatusOK, st)
}

// handleServicesRetryAll nudges every retrying proxy in one call. Cheap
// fallback for the user when they've rebuilt several containers at once.
func (s *Server) handleServicesRetryAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	n := s.proxy.KickAllRetries()
	writeJSON(w, http.StatusOK, map[string]int{"kicked": n})
}

func (s *Server) listServices(w http.ResponseWriter, r *http.Request) {
	services := s.store.ListServices()
	writeJSON(w, http.StatusOK, services)
}

func (s *Server) handleProtocolPresets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, storage.ProtocolPresets())
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
	s.protocolMu.Lock()
	defer s.protocolMu.Unlock()
	s.serviceMu.Lock()
	defer s.serviceMu.Unlock()

	// The ID is an internal key; users only provide a name. Auto-generate a
	// unique slug from the name when the client didn't supply one.
	if strings.TrimSpace(svc.ID) == "" {
		svc.ID = uniqueServiceID(svc.Name, func(id string) bool {
			_, exists := s.store.GetService(id)
			return exists
		})
	}

	applyServiceDefaults(&svc)
	svc.ApplyProtocolPreset()

	if err := validateService(&svc); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if svc.ProtocolID != "" {
		if _, ok := s.store.GetProtocol(svc.ProtocolID); !ok {
			http.Error(w, "protocol_id not found", http.StatusBadRequest)
			return
		}
	}

	if err := s.store.CreateService(&svc); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	if svc.Enabled {
		s.prewarmPyFilters(svc.ID)
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
	s.protocolMu.Lock()
	defer s.protocolMu.Unlock()
	s.serviceMu.Lock()
	defer s.serviceMu.Unlock()
	previous, ok := s.store.GetService(id)
	if !ok {
		http.Error(w, "service not found", http.StatusNotFound)
		return
	}

	svc.ID = id

	applyServiceDefaults(&svc)
	if svc.Protocol != previous.Protocol || svc.Spec.Listener.Transport == "" {
		svc.ApplyProtocolPreset()
	} else {
		svc.NormalizeSpec()
	}

	if err := validateService(&svc); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if svc.ProtocolID != "" {
		if _, ok := s.store.GetProtocol(svc.ProtocolID); !ok {
			http.Error(w, "protocol_id not found", http.StatusBadRequest)
			return
		}
	}

	if err := s.store.UpdateService(&svc); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Drop any cached .proto descriptors so the next decode rebuilds them.
	s.protoCache.Invalidate(svc.ID)

	// Restart proxy if enabled, stop if disabled
	if svc.Enabled {
		s.prewarmPyFilters(svc.ID)
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
	s.serviceMu.Lock()
	defer s.serviceMu.Unlock()
	if _, ok := s.store.GetService(id); !ok {
		http.Error(w, "service not found", http.StatusNotFound)
		return
	}

	if err := s.store.DeleteService(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.proxy.StopService(id)

	s.protoCache.Invalidate(id)

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
