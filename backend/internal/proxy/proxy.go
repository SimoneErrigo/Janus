package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/SimoneErrigo/Janus/backend/internal/dropper"
	"github.com/SimoneErrigo/Janus/backend/internal/flagids"
	"github.com/SimoneErrigo/Janus/backend/internal/sniffer"
	"github.com/SimoneErrigo/Janus/backend/internal/storage"
)

// Manager manages proxy instances for configured services.
type Manager struct {
	mu            sync.RWMutex
	proxies       map[string]*runningProxy // service ID -> running proxy
	engineMu      sync.RWMutex
	engines       map[string]*dropper.Engine // service ID -> shared drop engine
	packetStore   *sniffer.PacketStore
	ruleStore     *dropper.RuleStore
	flagRegex     *regexp.Regexp
	flagScanner   *flagids.FlagScanner // optimized byte-level flag scanner
	rulesCache    dropper.RulesCache
	flagIDChecker sniffer.FlagIDChecker
	captureCtrl   *sniffer.CaptureController
}

type runningProxy struct {
	service  *storage.Service
	listener net.Listener
	server   *http.Server
	cancel   context.CancelFunc
}

// NewManager creates a new proxy manager.
func NewManager(packetStore *sniffer.PacketStore, ruleStore *dropper.RuleStore, flagRegex *regexp.Regexp, flagScanner *flagids.FlagScanner) *Manager {
	return &Manager{
		proxies:     make(map[string]*runningProxy),
		engines:     make(map[string]*dropper.Engine),
		packetStore: packetStore,
		ruleStore:   ruleStore,
		flagRegex:   flagRegex,
		flagScanner: flagScanner,
	}
}

// engineFor returns a shared drop engine for the given service, creating it on
// first use. Reusing the engine across requests/connections preserves the
// compiled-regex cache and avoids per-connection allocations on the hot path.
// Uses a dedicated mutex so it can be called while m.mu is held by StartService.
func (m *Manager) engineFor(svc *storage.Service) *dropper.Engine {
	if m.ruleStore == nil {
		return nil
	}
	m.engineMu.RLock()
	if e := m.engines[svc.ID]; e != nil {
		m.engineMu.RUnlock()
		return e
	}
	m.engineMu.RUnlock()

	m.engineMu.Lock()
	defer m.engineMu.Unlock()
	if e := m.engines[svc.ID]; e != nil {
		return e
	}
	e := dropper.NewEngine(m.ruleStore)
	if m.rulesCache != nil {
		e.SetCache(m.rulesCache)
	}
	m.engines[svc.ID] = e
	return e
}

// dropEngineCache drops the cached engine for the given service ID.
// Called when a service is stopped/deleted so its engine can be GC'd.
func (m *Manager) dropEngineCache(serviceID string) {
	m.engineMu.Lock()
	delete(m.engines, serviceID)
	m.engineMu.Unlock()
}

// SetRulesCache sets the Redis cache for rule lookups on all new engines.
func (m *Manager) SetRulesCache(c dropper.RulesCache) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rulesCache = c
}

// SetFlagIDChecker sets the flag ID checker for marking packets at ingestion time.
func (m *Manager) SetFlagIDChecker(c sniffer.FlagIDChecker) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flagIDChecker = c
}

func (m *Manager) currentFlagIDChecker() sniffer.FlagIDChecker {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.flagIDChecker
}

func (m *Manager) SetCaptureController(c *sniffer.CaptureController) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.captureCtrl = c
}

func (m *Manager) shouldCapture() bool {
	m.mu.RLock()
	ctrl := m.captureCtrl
	m.mu.RUnlock()
	if ctrl == nil {
		return true
	}
	return ctrl.ShouldCapture()
}

func (m *Manager) shouldApplyFlagIDsOnIngest() bool {
	m.mu.RLock()
	ctrl := m.captureCtrl
	m.mu.RUnlock()
	if ctrl == nil {
		return true
	}
	return ctrl.ShouldApplyFlagIDsOnIngest()
}

// StartService starts a proxy for the given service.
func (m *Manager) StartService(svc *storage.Service) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.proxies[svc.ID]; exists {
		return fmt.Errorf("proxy for service %q is already running", svc.ID)
	}

	rp, err := m.startProxy(svc)
	if err != nil {
		return err
	}

	m.proxies[svc.ID] = rp
	log.Printf("Proxy started: %s (%s:%d -> %s) [%s]", svc.Name, svc.ListenAddr, svc.ListenPort, svc.TargetAddr, svc.Protocol)
	return nil
}

// StopService stops the proxy for the given service ID.
func (m *Manager) StopService(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	rp, exists := m.proxies[id]
	if !exists {
		return fmt.Errorf("no proxy running for service %q", id)
	}

	rp.cancel()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if rp.server != nil {
		rp.server.Shutdown(ctx)
	}
	if rp.listener != nil {
		rp.listener.Close()
	}

	delete(m.proxies, id)
	m.dropEngineCache(id)
	log.Printf("Proxy stopped: %s", rp.service.Name)
	return nil
}

// RestartService stops and restarts the proxy for the given service.
func (m *Manager) RestartService(svc *storage.Service) error {
	// Stop if running (ignore error if not running)
	m.StopService(svc.ID)
	return m.StartService(svc)
}

// StopAll stops all running proxies.
func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, rp := range m.proxies {
		rp.cancel()
		if rp.server != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			rp.server.Shutdown(ctx)
			cancel()
		}
		if rp.listener != nil {
			rp.listener.Close()
		}
		delete(m.proxies, id)
		m.dropEngineCache(id)
		log.Printf("Proxy stopped: %s", rp.service.Name)
	}
}

// IsRunning returns true if a proxy is running for the given service ID.
func (m *Manager) IsRunning(id string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.proxies[id]
	return exists
}

func (m *Manager) startProxy(svc *storage.Service) (*runningProxy, error) {
	ctx, cancel := context.WithCancel(context.Background())

	switch svc.Protocol {
	case storage.ProtocolHTTP:
		return m.startHTTPProxy(ctx, cancel, svc)
	case storage.ProtocolHTTPS, storage.ProtocolHTTP2, storage.ProtocolGRPC:
		return m.startTLSProxy(ctx, cancel, svc)
	case storage.ProtocolTCP:
		return m.startTCPProxy(ctx, cancel, svc)
	default:
		cancel()
		return nil, fmt.Errorf("protocol %q not yet supported", svc.Protocol)
	}
}

func (m *Manager) startHTTPProxy(ctx context.Context, cancel context.CancelFunc, svc *storage.Service) (*runningProxy, error) {
	targetURL, err := url.Parse("http://" + svc.TargetAddr)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("invalid target address: %w", err)
	}

	reverseProxy := httputil.NewSingleHostReverseProxy(targetURL)
	reverseProxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("[%s] proxy error: %v", svc.Name, err)
		w.WriteHeader(http.StatusBadGateway)
	}

	listenAddr := fmt.Sprintf("0.0.0.0:%d", svc.ListenPort)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("listen on %s: %w", listenAddr, err)
	}

	var handler http.Handler = reverseProxy
	if m.packetStore != nil {
		dropEngine := m.engineFor(svc)
		handler = sniffer.HTTPMiddleware(reverseProxy, svc, m.packetStore, dropEngine, m.flagRegex, m.flagScanner, m.currentFlagIDChecker, m.shouldCapture, m.shouldApplyFlagIDsOnIngest)
	}

	server := &http.Server{
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	rp := &runningProxy{
		service:  svc,
		listener: listener,
		server:   server,
		cancel:   cancel,
	}

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("[%s] server error: %v", svc.Name, err)
		}
	}()

	go func() {
		<-ctx.Done()
		server.Shutdown(context.Background())
	}()

	return rp, nil
}

func (m *Manager) startTLSProxy(ctx context.Context, cancel context.CancelFunc, svc *storage.Service) (*runningProxy, error) {
	tlsConfig, err := buildTLSConfig(svc)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("TLS config: %w", err)
	}

	// Target is the backend service
	targetScheme := "http"
	if svc.TargetTLS {
		targetScheme = "https"
	}
	targetURL, err := url.Parse(targetScheme + "://" + svc.TargetAddr)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("invalid target address: %w", err)
	}

	reverseProxy := httputil.NewSingleHostReverseProxy(targetURL)
	reverseProxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("[%s] proxy error: %v", svc.Name, err)
		w.WriteHeader(http.StatusBadGateway)
	}

	// For gRPC/HTTP2, configure HTTP/2 transport to backend
	if svc.Protocol == storage.ProtocolGRPC || svc.Protocol == storage.ProtocolHTTP2 {
		// Flush immediately after each write for streaming/gRPC support
		reverseProxy.FlushInterval = -1
		if svc.TargetTLS {
			reverseProxy.Transport = &http2.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
		} else {
			reverseProxy.Transport = &http2.Transport{
				AllowHTTP: true,
				DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
					return net.DialTimeout(network, addr, 10*time.Second)
				},
			}
		}
	} else if svc.TargetTLS {
		// For HTTPS backends with custom/self-signed certs (common in CTF), skip verification
		reverseProxy.Transport = &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			TLSHandshakeTimeout: 10 * time.Second,
			IdleConnTimeout:     90 * time.Second,
		}
	}

	var handler http.Handler = reverseProxy
	if m.packetStore != nil {
		dropEngine := m.engineFor(svc)
		handler = sniffer.HTTPMiddleware(handler, svc, m.packetStore, dropEngine, m.flagRegex, m.flagScanner, m.currentFlagIDChecker, m.shouldCapture, m.shouldApplyFlagIDsOnIngest)
	}

	// For gRPC, support h2c (HTTP/2 cleartext) from backend if needed
	if svc.Protocol == storage.ProtocolGRPC {
		h2s := &http2.Server{}
		handler = h2c.NewHandler(handler, h2s)
	}

	listenAddr := fmt.Sprintf("0.0.0.0:%d", svc.ListenPort)
	listener, err := tls.Listen("tcp", listenAddr, tlsConfig)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("TLS listen on %s: %w", listenAddr, err)
	}

	server := &http.Server{
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Enable HTTP/2 on the server
	if err := http2.ConfigureServer(server, &http2.Server{}); err != nil {
		cancel()
		listener.Close()
		return nil, fmt.Errorf("configuring HTTP/2: %w", err)
	}

	rp := &runningProxy{
		service:  svc,
		listener: listener,
		server:   server,
		cancel:   cancel,
	}

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("[%s] TLS server error: %v", svc.Name, err)
		}
	}()

	go func() {
		<-ctx.Done()
		server.Shutdown(context.Background())
	}()

	return rp, nil
}
