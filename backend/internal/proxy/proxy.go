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

// retryInterval is the fixed sleep between bind attempts when the listener
// could not be brought up (typically because the target port was still held
// by the previous container). In A&D every retry second is potential points,
// so we keep this short and do NOT use exponential backoff: the common case
// is "container rebuild took a few seconds, then the port is free forever".
const retryInterval = 1 * time.Second

// ProxyState describes the lifecycle of a managed proxy listener.
type ProxyState string

const (
	// StateRunning means the listener is bound and serving traffic.
	StateRunning ProxyState = "running"
	// StateRetrying means the proxy is registered but the listener could not
	// be brought up yet. The retry loop keeps trying every retryInterval and
	// can be kicked immediately via Manager.KickRetry.
	StateRetrying ProxyState = "retrying"
)

// Status is the public, JSON-friendly view of a proxy's current health.
// Returned by Manager.Status / Manager.AllStatuses and consumed by the
// /api/services/status endpoint so the UI can render the *real* listener
// state instead of just the configured "enabled" flag.
type Status struct {
	ServiceID   string    `json:"service_id"`
	State       string    `json:"state"`
	Running     bool      `json:"running"`
	LastError   string    `json:"last_error,omitempty"`
	LastAttempt time.Time `json:"last_attempt,omitempty"`
}

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
	pyBlockFn     sniffer.PyBlockFunc // inline (synchronous) Python filter eval
}

// runningProxy tracks the lifecycle of a single proxy. The outer ctx/cancel
// pair are created in StartService and live for the entire registered
// lifetime of the proxy; each bind attempt builds its own sub-context that
// is automatically torn down when the outer ctx is cancelled (i.e. when
// StopService is called). listener/server may be nil while the proxy is in
// the retrying state.
type runningProxy struct {
	service  *storage.Service
	ctx      context.Context
	cancel   context.CancelFunc
	retryNow chan struct{}

	stateMu     sync.RWMutex
	listener    net.Listener
	server      *http.Server
	state       ProxyState
	lastError   string
	lastAttempt time.Time
}

func (rp *runningProxy) markRunning(listener net.Listener, server *http.Server) {
	rp.stateMu.Lock()
	defer rp.stateMu.Unlock()
	rp.listener = listener
	rp.server = server
	rp.state = StateRunning
	rp.lastError = ""
	rp.lastAttempt = time.Now()
}

func (rp *runningProxy) markRetrying(err error) {
	rp.stateMu.Lock()
	defer rp.stateMu.Unlock()
	rp.listener = nil
	rp.server = nil
	rp.state = StateRetrying
	if err != nil {
		rp.lastError = err.Error()
	}
	rp.lastAttempt = time.Now()
}

func (rp *runningProxy) snapshot() Status {
	rp.stateMu.RLock()
	defer rp.stateMu.RUnlock()
	return Status{
		ServiceID:   rp.service.ID,
		State:       string(rp.state),
		Running:     rp.state == StateRunning,
		LastError:   rp.lastError,
		LastAttempt: rp.lastAttempt,
	}
}

func (rp *runningProxy) currentState() ProxyState {
	rp.stateMu.RLock()
	defer rp.stateMu.RUnlock()
	return rp.state
}

func (rp *runningProxy) takeServerAndListener() (*http.Server, net.Listener) {
	rp.stateMu.Lock()
	defer rp.stateMu.Unlock()
	server, listener := rp.server, rp.listener
	rp.server = nil
	rp.listener = nil
	return server, listener
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

// SetPyBlockFn sets the inline (synchronous) Python-filter evaluator run on the
// request hot path. Call before starting services.
func (m *Manager) SetPyBlockFn(fn sniffer.PyBlockFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pyBlockFn = fn
}

func (m *Manager) currentPyBlockFn() sniffer.PyBlockFunc {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.pyBlockFn
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

// StartService starts a proxy for the given service. If the initial bind
// fails (e.g. the port is still held by the previous container during a
// docker-compose rebuild), the proxy is registered in the retrying state
// and a background loop keeps trying every retryInterval until it succeeds
// or StopService is called. The caller therefore does NOT get an error
// back for a transient bind failure — they should look at Status / the
// /api/services/status endpoint to see the live state.
func (m *Manager) StartService(svc *storage.Service) error {
	m.mu.Lock()
	if _, exists := m.proxies[svc.ID]; exists {
		m.mu.Unlock()
		return fmt.Errorf("proxy for service %q is already running", svc.ID)
	}

	ctx, cancel := context.WithCancel(context.Background())
	rp := &runningProxy{
		service:     svc,
		ctx:         ctx,
		cancel:      cancel,
		retryNow:    make(chan struct{}, 1),
		state:       StateRetrying,
		lastAttempt: time.Now(),
	}
	m.proxies[svc.ID] = rp
	m.mu.Unlock()

	// Try once synchronously so the common (port-free) case stays fast and
	// the caller's log line reflects the actual outcome. On failure we fall
	// through to a background retry loop and return nil — the proxy is
	// registered and will keep retrying.
	if err := m.attemptBind(rp); err != nil {
		rp.markRetrying(err)
		log.Printf("Proxy bind failed for %s, retrying every %s: %v", svc.Name, retryInterval, err)
		go m.retryLoop(rp)
		return nil
	}
	log.Printf("Proxy started: %s (%s:%d -> %s) [%s]", svc.Name, svc.ListenAddr, svc.ListenPort, svc.TargetAddr, svc.Protocol)
	return nil
}

// StopService stops the proxy for the given service ID. Works whether the
// proxy is currently running or in the retrying state — cancelling rp.ctx
// terminates any in-flight retry loop alongside the live listener.
func (m *Manager) StopService(id string) error {
	m.mu.Lock()
	rp, exists := m.proxies[id]
	if !exists {
		m.mu.Unlock()
		return fmt.Errorf("no proxy running for service %q", id)
	}
	delete(m.proxies, id)
	m.mu.Unlock()

	rp.cancel()

	server, listener := rp.takeServerAndListener()
	if server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		server.Shutdown(ctx)
		cancel()
	}
	if listener != nil {
		listener.Close()
	}

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
	rps := make(map[string]*runningProxy, len(m.proxies))
	for id, rp := range m.proxies {
		rps[id] = rp
		delete(m.proxies, id)
	}
	m.mu.Unlock()

	for id, rp := range rps {
		rp.cancel()
		server, listener := rp.takeServerAndListener()
		if server != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			server.Shutdown(ctx)
			cancel()
		}
		if listener != nil {
			listener.Close()
		}
		m.dropEngineCache(id)
		log.Printf("Proxy stopped: %s", rp.service.Name)
	}
}

// IsRunning returns true if a proxy is fully bound and serving for the
// given service ID. A proxy in the retrying state returns false.
func (m *Manager) IsRunning(id string) bool {
	m.mu.RLock()
	rp, exists := m.proxies[id]
	m.mu.RUnlock()
	if !exists {
		return false
	}
	return rp.currentState() == StateRunning
}

// IsRegistered returns true if the manager has any record of the proxy —
// whether it's currently running or still retrying its first bind.
func (m *Manager) IsRegistered(id string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.proxies[id]
	return exists
}

// Status returns the current health snapshot for a service, or (Status{}, false)
// if no proxy is registered for that ID.
func (m *Manager) Status(id string) (Status, bool) {
	m.mu.RLock()
	rp, ok := m.proxies[id]
	m.mu.RUnlock()
	if !ok {
		return Status{}, false
	}
	return rp.snapshot(), true
}

// AllStatuses returns a snapshot of every registered proxy. Used by the
// /api/services/status endpoint so the UI can paint listener state in
// near-real-time without hammering individual status endpoints.
func (m *Manager) AllStatuses() []Status {
	m.mu.RLock()
	rps := make([]*runningProxy, 0, len(m.proxies))
	for _, rp := range m.proxies {
		rps = append(rps, rp)
	}
	m.mu.RUnlock()

	out := make([]Status, 0, len(rps))
	for _, rp := range rps {
		out = append(out, rp.snapshot())
	}
	return out
}

// KickRetry asks the retry loop for the given service to attempt a bind
// immediately instead of waiting for the next tick. It is the fast-path
// counterpart to the user clicking "Retry now" in the UI after rebuilding
// a container. No-op (returns false) if the proxy isn't registered or is
// already in the running state.
func (m *Manager) KickRetry(id string) bool {
	m.mu.RLock()
	rp, ok := m.proxies[id]
	m.mu.RUnlock()
	if !ok {
		return false
	}
	if rp.currentState() == StateRunning {
		return false
	}
	select {
	case rp.retryNow <- struct{}{}:
	default:
		// already a pending kick — coalesce
	}
	return true
}

// KickAllRetries signals every retrying proxy to attempt a bind now.
// Returns the number of proxies that were nudged.
func (m *Manager) KickAllRetries() int {
	m.mu.RLock()
	rps := make([]*runningProxy, 0, len(m.proxies))
	for _, rp := range m.proxies {
		rps = append(rps, rp)
	}
	m.mu.RUnlock()

	n := 0
	for _, rp := range rps {
		if rp.currentState() != StateRetrying {
			continue
		}
		select {
		case rp.retryNow <- struct{}{}:
			n++
		default:
		}
	}
	return n
}

// attemptBind runs one bind attempt against the configured listener. On
// success rp transitions to the running state. On failure the error is
// returned unchanged and rp is left untouched (the caller decides whether
// to mark it retrying / log / schedule the next attempt). Each attempt
// creates a sub-context derived from rp.ctx so that StopService can tear
// down a successfully-bound listener by cancelling the outer context.
func (m *Manager) attemptBind(rp *runningProxy) error {
	ctx, cancel := context.WithCancel(rp.ctx)
	var inner *runningProxy
	var err error
	switch rp.service.Protocol {
	case storage.ProtocolHTTP, storage.ProtocolWS:
		inner, err = m.startHTTPProxy(ctx, cancel, rp.service)
	case storage.ProtocolHTTPS, storage.ProtocolWSS, storage.ProtocolHTTP2, storage.ProtocolGRPC:
		inner, err = m.startTLSProxy(ctx, cancel, rp.service)
	case storage.ProtocolTCP:
		inner, err = m.startTCPProxy(ctx, cancel, rp.service)
	default:
		cancel()
		return fmt.Errorf("protocol %q not yet supported", rp.service.Protocol)
	}
	if err != nil {
		// The per-protocol helper already called cancel() on its way out,
		// so the sub-context is released; no goroutines were spawned.
		return err
	}
	// inner is a throwaway carrier — we only need its listener+server. Its
	// own cancel was stored on inner.cancel and will fire when rp.ctx is
	// cancelled (child context propagation), so we deliberately discard it.
	rp.markRunning(inner.listener, inner.server)
	return nil
}

// retryLoop keeps re-trying attemptBind every retryInterval until it
// succeeds or rp.ctx is cancelled (StopService). A kick on rp.retryNow
// short-circuits the wait. The loop exits after the first successful
// bind: we don't need a long-running watcher because once Janus owns the
// port it owns it until shutdown.
func (m *Manager) retryLoop(rp *runningProxy) {
	ticker := time.NewTicker(retryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-rp.ctx.Done():
			return
		case <-ticker.C:
		case <-rp.retryNow:
		}
		if err := m.attemptBind(rp); err != nil {
			rp.markRetrying(err)
			continue
		}
		log.Printf("Proxy bound (retry succeeded): %s (%s:%d -> %s) [%s]", rp.service.Name, rp.service.ListenAddr, rp.service.ListenPort, rp.service.TargetAddr, rp.service.Protocol)
		return
	}
}

func (m *Manager) startHTTPProxy(ctx context.Context, cancel context.CancelFunc, svc *storage.Service) (*runningProxy, error) {
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
	m.configureWebSocketReverseProxy(reverseProxy, svc)
	if svc.TargetTLS {
		// Challenge backends commonly use a self-signed certificate. This is
		// also what lets a public ws listener connect to a private wss backend.
		reverseProxy.Transport = &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			TLSHandshakeTimeout: 10 * time.Second,
			IdleConnTimeout:     90 * time.Second,
		}
	}
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
		handler = sniffer.HTTPMiddleware(reverseProxy, svc, m.packetStore, dropEngine, m.flagRegex, m.flagScanner, m.currentFlagIDChecker, m.shouldCapture, m.shouldApplyFlagIDsOnIngest, m.currentPyBlockFn())
	}

	server := newProxyHTTPServer(handler, svc.Protocol)

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
	m.configureWebSocketReverseProxy(reverseProxy, svc)
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
		handler = sniffer.HTTPMiddleware(handler, svc, m.packetStore, dropEngine, m.flagRegex, m.flagScanner, m.currentFlagIDChecker, m.shouldCapture, m.shouldApplyFlagIDsOnIngest, m.currentPyBlockFn())
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

	server := newProxyHTTPServer(handler, svc.Protocol)

	// A WSS listener deliberately advertises only HTTP/1.1: WebSocket uses the
	// RFC 6455 Upgrade handshake, not HTTP/2 extended CONNECT.
	if svc.Protocol != storage.ProtocolWSS {
		if err := http2.ConfigureServer(server, &http2.Server{}); err != nil {
			cancel()
			listener.Close()
			return nil, fmt.Errorf("configuring HTTP/2: %w", err)
		}
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

// newProxyHTTPServer keeps the normal defensive HTTP timeouts while allowing
// WebSocket connections to remain open. Once a request is upgraded, net/http
// hands the underlying connection to ReverseProxy; a ReadTimeout/WriteTimeout
// would otherwise terminate a healthy WS/WSS tunnel after 30 seconds.
func newProxyHTTPServer(handler http.Handler, protocol storage.Protocol) *http.Server {
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 30 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if protocol == storage.ProtocolWS || protocol == storage.ProtocolWSS {
		server.ReadTimeout = 0
		server.WriteTimeout = 0
	}
	return server
}
