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
	"strconv"
	"strings"
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
	Transport   string    `json:"transport,omitempty"`
	Application string    `json:"application,omitempty"`
	BindAddress string    `json:"bind_address,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
	LastAttempt time.Time `json:"last_attempt,omitempty"`
}

// Manager manages proxy instances for configured services.
type Manager struct {
	mu            sync.RWMutex
	reconfigureMu sync.Mutex
	proxies       map[string]*ServiceRuntime // service ID -> isolated runtime
	packetStore   sniffer.PacketSink
	ruleStore     dropper.RuleSource
	flagRegex     *regexp.Regexp
	flagScanner   *flagids.FlagScanner // optimized byte-level flag scanner
	rulesCache    dropper.RulesCache
	flagIDChecker sniffer.FlagIDChecker
	captureCtrl   *sniffer.CaptureController
	pyBlockFn     sniffer.PyBlockFunc          // inline (synchronous) Python filter eval
	pyShouldEval  sniffer.PyShouldEvaluateFunc // cheap live-Python allocation/scope preflight
	dataBindMode  string
}

// runningProxy tracks the lifecycle of a single proxy. The outer ctx/cancel
// pair are created in StartService and live for the entire registered
// lifetime of the proxy; each bind attempt builds its own sub-context that
// is automatically torn down when the outer ctx is cancelled (i.e. when
// StopService is called). listener/server may be nil while the proxy is in
// the retrying state.
type ServiceRuntime struct {
	service  *storage.Service
	spec     storage.ServiceSpec
	ctx      context.Context
	cancel   context.CancelFunc
	retryNow chan struct{}

	stateMu     sync.RWMutex
	listener    net.Listener
	server      *http.Server
	state       ProxyState
	lastError   string
	lastAttempt time.Time
	engine      *dropper.Engine
}

// runningProxy remains as an internal alias while protocol helpers are moved
// incrementally onto ServiceRuntime.
type runningProxy = ServiceRuntime

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
	bindAddress := ""
	if rp.listener != nil {
		bindAddress = rp.listener.Addr().String()
	}
	return Status{
		ServiceID:   rp.service.ID,
		State:       string(rp.state),
		Running:     rp.state == StateRunning,
		Transport:   string(rp.spec.Listener.Transport),
		Application: string(rp.spec.Application.Profile),
		BindAddress: bindAddress,
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
func NewManager(packetStore sniffer.PacketSink, ruleStore dropper.RuleSource, flagRegex *regexp.Regexp, flagScanner *flagids.FlagScanner) *Manager {
	return &Manager{
		proxies:      make(map[string]*ServiceRuntime),
		packetStore:  packetStore,
		ruleStore:    ruleStore,
		flagRegex:    flagRegex,
		flagScanner:  flagScanner,
		dataBindMode: "configured",
	}
}

// SetFlagPattern atomically publishes new flag matchers. HTTP-family handlers
// receive their matchers when they are built, so those listeners are restarted
// after publication; stream/datagram/WebSocket message paths read the current
// pair for every message. Invalid patterns leave the running configuration
// untouched.
func (m *Manager) SetFlagPattern(pattern string, caseInsensitive, decodeURL bool) error {
	m.reconfigureMu.Lock()
	defer m.reconfigureMu.Unlock()

	var re *regexp.Regexp
	var err error
	regexpPattern := pattern
	if caseInsensitive && pattern != "" && !strings.HasPrefix(pattern, "(?i)") {
		regexpPattern = "(?i)" + pattern
	}
	if regexpPattern != "" {
		re, err = regexp.Compile(regexpPattern)
		if err != nil {
			return fmt.Errorf("invalid flag regex: %w", err)
		}
	}
	scanner := flagids.NewFlagScanner(pattern, caseInsensitive, decodeURL)

	m.mu.Lock()
	m.flagRegex, m.flagScanner = re, scanner
	services := make([]*storage.Service, 0, len(m.proxies))
	for _, runtime := range m.proxies {
		switch runtime.spec.Application.Profile {
		case storage.ApplicationHTTP, storage.ApplicationWebSocket, storage.ApplicationHTTP2, storage.ApplicationGRPC:
			services = append(services, runtime.service)
		}
	}
	m.mu.Unlock()

	var firstErr error
	for _, svc := range services {
		_ = m.stopServiceLocked(svc.ID)
		if err := m.startServiceLocked(svc); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("refreshing flag matcher for service %q: %w", svc.ID, err)
			}
		}
	}
	return firstErr
}

func (m *Manager) currentFlagMatchers() (*regexp.Regexp, *flagids.FlagScanner) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.flagRegex, m.flagScanner
}

// CountFlags exposes the live matcher pair to diagnostics such as the Python
// filter dry-run, keeping synthetic samples consistent with captured traffic.
func (m *Manager) CountFlags(url, headers string, body []byte) (urlCount, headerCount, bodyCount int) {
	flagRegex, flagScanner := m.currentFlagMatchers()
	return sniffer.CountFlags(flagRegex, flagScanner, url, headers, body)
}

// SetDataPlaneBindMode separates the checker-facing configured address from
// the container runtime bind. Bridge Compose uses wildcard; host networking
// uses configured.
func (m *Manager) SetDataPlaneBindMode(mode string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if mode != "wildcard" {
		mode = "configured"
	}
	m.dataBindMode = mode
}

// engineFor returns a shared drop engine for the given service, creating it on
// first use. Reusing the engine across requests/connections preserves the
// compiled-regex cache and avoids per-connection allocations on the hot path.
// Uses a dedicated mutex so it can be called while m.mu is held by StartService.
func (m *Manager) engineFor(svc *storage.Service) *dropper.Engine {
	if m.ruleStore == nil {
		return nil
	}
	m.mu.RLock()
	runtime := m.proxies[svc.ID]
	m.mu.RUnlock()
	if runtime != nil {
		return runtime.engine
	}
	// Compatibility for isolated unit callers not registered with Manager.
	engine := dropper.NewEngine(m.ruleStore)
	if m.rulesCache != nil {
		engine.SetCache(m.rulesCache)
	}
	return engine
}

// SetRulesCache sets the Redis cache for rule lookups on all new engines.
func (m *Manager) SetRulesCache(c dropper.RulesCache) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rulesCache = c
	for _, runtime := range m.proxies {
		if runtime.engine != nil {
			runtime.engine.SetCache(c)
		}
	}
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

// SetPyShouldEvaluateFn installs the live-Python allocation/scope preflight.
// It avoids constructing flows when Python is paused and avoids HTTP response
// buffering when no enabled inline response filter can match.
func (m *Manager) SetPyShouldEvaluateFn(fn sniffer.PyShouldEvaluateFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pyShouldEval = fn
}

func (m *Manager) currentPyShouldEvaluateFn() sniffer.PyShouldEvaluateFunc {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.pyShouldEval
}

// pyBlockForMessage is the allocation gate for TCP/UDP/WebSocket messages.
// Querying with an empty direction keeps whole-connection tracking intact for
// direction-scoped stateful scripts while avoiding flow maps/body strings/base64
// entirely when the Python runtime (or all applicable scripts) is disabled.
func (m *Manager) pyBlockForMessage(service, protocol string) sniffer.PyBlockFunc {
	m.mu.RLock()
	block, shouldEvaluate := m.pyBlockFn, m.pyShouldEval
	m.mu.RUnlock()
	if block == nil {
		return nil
	}
	if shouldEvaluate != nil && !shouldEvaluate(service, "", protocol) {
		return nil
	}
	return block
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
	m.reconfigureMu.Lock()
	defer m.reconfigureMu.Unlock()
	return m.startServiceLocked(svc)
}

// startServiceLocked is the implementation shared by startup, restart, and
// flag-matcher reconfiguration. The caller holds reconfigureMu so a stale
// restart can never overwrite a concurrent service update.
func (m *Manager) startServiceLocked(svc *storage.Service) error {
	if svc == nil {
		return fmt.Errorf("service is required")
	}
	if err := validateRuntimeSupport(svc.RuntimeSpec()); err != nil {
		return err
	}
	m.mu.Lock()
	if _, exists := m.proxies[svc.ID]; exists {
		m.mu.Unlock()
		return fmt.Errorf("proxy for service %q is already running", svc.ID)
	}

	ctx, cancel := context.WithCancel(context.Background())
	rp := &runningProxy{
		service:     svc,
		spec:        svc.RuntimeSpec(),
		ctx:         ctx,
		cancel:      cancel,
		retryNow:    make(chan struct{}, 1),
		state:       StateRetrying,
		lastAttempt: time.Now(),
	}
	if m.ruleStore != nil {
		rp.engine = dropper.NewEngine(m.ruleStore)
		if m.rulesCache != nil {
			rp.engine.SetCache(m.rulesCache)
		}
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

func validateRuntimeSupport(spec storage.ServiceSpec) error {
	switch spec.Listener.Transport {
	case storage.TransportUDP:
		if spec.Listener.TLS != storage.ClientTLSOff {
			return fmt.Errorf("UDP listener TLS mode %q is not supported", spec.Listener.TLS)
		}
		if spec.Application.Profile != storage.ApplicationRaw && spec.Application.Profile != storage.ApplicationDNS {
			return fmt.Errorf("application profile %q is not supported over UDP", spec.Application.Profile)
		}
	case storage.TransportTCP:
		if !isSupportedTCPApplication(spec.Application.Profile) {
			return fmt.Errorf("application profile %q is not supported over TCP", spec.Application.Profile)
		}
	default:
		return fmt.Errorf("transport %q is not supported", spec.Listener.Transport)
	}
	return nil
}

func isSupportedTCPApplication(profile storage.ApplicationProfile) bool {
	switch profile {
	case storage.ApplicationHTTP, storage.ApplicationWebSocket, storage.ApplicationHTTP2,
		storage.ApplicationGRPC, storage.ApplicationRaw, storage.ApplicationDNS,
		storage.ApplicationRESP, storage.ApplicationMQTT:
		return true
	default:
		return false
	}
}

// StopService stops the proxy for the given service ID. Works whether the
// proxy is currently running or in the retrying state — cancelling rp.ctx
// terminates any in-flight retry loop alongside the live listener.
func (m *Manager) StopService(id string) error {
	m.reconfigureMu.Lock()
	defer m.reconfigureMu.Unlock()
	return m.stopServiceLocked(id)
}

func (m *Manager) stopServiceLocked(id string) error {
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
		if err := server.Shutdown(ctx); err != nil {
			_ = server.Close()
		}
		cancel()
	}
	if listener != nil {
		listener.Close()
	}

	log.Printf("Proxy stopped: %s", rp.service.Name)
	return nil
}

// RestartService stops and restarts the proxy for the given service.
func (m *Manager) RestartService(svc *storage.Service) error {
	m.reconfigureMu.Lock()
	defer m.reconfigureMu.Unlock()
	// Stop if running (ignore error if not running).
	_ = m.stopServiceLocked(svc.ID)
	return m.startServiceLocked(svc)
}

// StopAll stops all running proxies.
func (m *Manager) StopAll() {
	m.reconfigureMu.Lock()
	defer m.reconfigureMu.Unlock()
	m.stopAllLocked()
}

func (m *Manager) stopAllLocked() {
	m.mu.Lock()
	rps := make(map[string]*runningProxy, len(m.proxies))
	for id, rp := range m.proxies {
		rps[id] = rp
		delete(m.proxies, id)
	}
	m.mu.Unlock()

	for _, rp := range rps {
		rp.cancel()
		server, listener := rp.takeServerAndListener()
		if server != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := server.Shutdown(ctx); err != nil {
				_ = server.Close()
			}
			cancel()
		}
		if listener != nil {
			listener.Close()
		}
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
	spec := rp.service.RuntimeSpec()
	if spec.Listener.Transport == storage.TransportUDP {
		inner, err = m.startUDPProxy(ctx, cancel, rp.service)
		if err == nil {
			rp.markRunning(inner.listener, inner.server)
		}
		return err
	}
	if spec.Listener.Transport != storage.TransportTCP {
		cancel()
		return fmt.Errorf("transport %q not supported", spec.Listener.Transport)
	}
	switch spec.Application.Profile {
	case storage.ApplicationHTTP, storage.ApplicationWebSocket, storage.ApplicationHTTP2, storage.ApplicationGRPC:
		if spec.Listener.TLS == storage.ClientTLSTerminate {
			inner, err = m.startTLSProxy(ctx, cancel, rp.service)
		} else {
			inner, err = m.startHTTPProxy(ctx, cancel, rp.service)
		}
	case storage.ApplicationRaw, storage.ApplicationDNS, storage.ApplicationRESP, storage.ApplicationMQTT:
		inner, err = m.startTCPProxy(ctx, cancel, rp.service)
	default:
		cancel()
		return fmt.Errorf("application profile %q not yet supported", spec.Application.Profile)
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

		// A retry is a lifecycle transition just like Start/Stop/Restart. Keep it
		// under the same lock and re-check registration so an in-flight retry can
		// never publish a listener after StopService has removed this runtime.
		m.reconfigureMu.Lock()
		m.mu.RLock()
		registered := m.proxies[rp.service.ID] == rp
		m.mu.RUnlock()
		if !registered {
			m.reconfigureMu.Unlock()
			return
		}
		err := m.attemptBind(rp)
		if err != nil {
			rp.markRetrying(err)
			m.reconfigureMu.Unlock()
			continue
		}
		m.reconfigureMu.Unlock()
		log.Printf("Proxy bound (retry succeeded): %s (%s:%d -> %s) [%s]", rp.service.Name, rp.service.ListenAddr, rp.service.ListenPort, rp.service.TargetAddr, rp.service.Protocol)
		return
	}
}

func (m *Manager) startHTTPProxy(ctx context.Context, cancel context.CancelFunc, svc *storage.Service) (*runningProxy, error) {
	spec := svc.RuntimeSpec()
	targetScheme := "http"
	if spec.Upstream.TLS {
		targetScheme = "https"
	}
	targetURL, err := url.Parse(targetScheme + "://" + spec.Upstream.Address)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("invalid target address: %w", err)
	}

	reverseProxy := httputil.NewSingleHostReverseProxy(targetURL)
	m.configureWebSocketReverseProxy(ctx, reverseProxy, svc)
	if spec.Application.Profile == storage.ApplicationGRPC || spec.Application.Profile == storage.ApplicationHTTP2 {
		reverseProxy.FlushInterval = -1
		if spec.Upstream.TLS {
			reverseProxy.Transport = &http2.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		} else {
			reverseProxy.Transport = &http2.Transport{AllowHTTP: true, DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				return net.DialTimeout(network, addr, 10*time.Second)
			}}
		}
	} else if spec.Upstream.TLS {
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

	listenAddr := m.serviceListenAddress(spec)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("listen on %s: %w", listenAddr, err)
	}

	var handler http.Handler = reverseProxy
	if m.packetStore != nil {
		dropEngine := m.engineFor(svc)
		flagRegex, flagScanner := m.currentFlagMatchers()
		handler = sniffer.HTTPMiddleware(reverseProxy, svc, m.packetStore, dropEngine, flagRegex, flagScanner, m.currentFlagIDChecker, m.shouldCapture, m.shouldApplyFlagIDsOnIngest, m.currentPyBlockFn(), m.currentPyShouldEvaluateFn())
	}
	if spec.Application.Profile == storage.ApplicationGRPC || spec.Application.Profile == storage.ApplicationHTTP2 {
		handler = h2c.NewHandler(handler, &http2.Server{})
	}

	server := newProxyHTTPServerForSpec(handler, spec)
	installConnectionSessions(server, svc.ID)

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
		shutdownProxyHTTPServer(server)
	}()

	return rp, nil
}

func (m *Manager) startTLSProxy(ctx context.Context, cancel context.CancelFunc, svc *storage.Service) (*runningProxy, error) {
	spec := svc.RuntimeSpec()
	tlsConfig, err := buildTLSConfig(svc)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("TLS config: %w", err)
	}

	// Target is the backend service
	targetScheme := "http"
	if spec.Upstream.TLS {
		targetScheme = "https"
	}
	targetURL, err := url.Parse(targetScheme + "://" + spec.Upstream.Address)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("invalid target address: %w", err)
	}

	reverseProxy := httputil.NewSingleHostReverseProxy(targetURL)
	m.configureWebSocketReverseProxy(ctx, reverseProxy, svc)
	reverseProxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("[%s] proxy error: %v", svc.Name, err)
		w.WriteHeader(http.StatusBadGateway)
	}

	// For gRPC/HTTP2, configure HTTP/2 transport to backend
	if spec.Application.Profile == storage.ApplicationGRPC || spec.Application.Profile == storage.ApplicationHTTP2 {
		// Flush immediately after each write for streaming/gRPC support
		reverseProxy.FlushInterval = -1
		if spec.Upstream.TLS {
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
	} else if spec.Upstream.TLS {
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
		flagRegex, flagScanner := m.currentFlagMatchers()
		handler = sniffer.HTTPMiddleware(handler, svc, m.packetStore, dropEngine, flagRegex, flagScanner, m.currentFlagIDChecker, m.shouldCapture, m.shouldApplyFlagIDsOnIngest, m.currentPyBlockFn(), m.currentPyShouldEvaluateFn())
	}

	// For gRPC, support h2c (HTTP/2 cleartext) from backend if needed
	if spec.Application.Profile == storage.ApplicationGRPC {
		h2s := &http2.Server{}
		handler = h2c.NewHandler(handler, h2s)
	}

	listenAddr := m.serviceListenAddress(spec)
	listener, err := tls.Listen("tcp", listenAddr, tlsConfig)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("TLS listen on %s: %w", listenAddr, err)
	}

	server := newProxyHTTPServerForSpec(handler, spec)
	installConnectionSessions(server, svc.ID)

	// A WSS listener deliberately advertises only HTTP/1.1: WebSocket uses the
	// RFC 6455 Upgrade handshake, not HTTP/2 extended CONNECT.
	if spec.Application.Profile != storage.ApplicationWebSocket {
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
		shutdownProxyHTTPServer(server)
	}()

	return rp, nil
}

func shutdownProxyHTTPServer(server *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		_ = server.Close()
	}
}

func (m *Manager) serviceListenAddress(spec storage.ServiceSpec) string {
	m.mu.RLock()
	mode := m.dataBindMode
	m.mu.RUnlock()
	host := spec.Listener.Address
	if mode == "wildcard" {
		host = "0.0.0.0"
	}
	return net.JoinHostPort(host, strconv.Itoa(spec.Listener.Port))
}

// newProxyHTTPServer keeps the normal defensive HTTP timeouts while allowing
// WebSocket connections to remain open. Once a request is upgraded, net/http
// hands the underlying connection to ReverseProxy; a ReadTimeout/WriteTimeout
// would otherwise terminate a healthy WS/WSS tunnel after 30 seconds.
func newProxyHTTPServerForSpec(handler http.Handler, spec storage.ServiceSpec) *http.Server {
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 30 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if spec.Application.Profile == storage.ApplicationWebSocket {
		server.ReadTimeout = 0
		server.WriteTimeout = 0
	}
	return server
}

func installConnectionSessions(server *http.Server, serviceID string) {
	previous := server.ConnContext
	server.ConnContext = func(ctx context.Context, conn net.Conn) context.Context {
		if previous != nil {
			ctx = previous(ctx, conn)
		}
		host, portText, _ := net.SplitHostPort(conn.RemoteAddr().String())
		port, _ := strconv.Atoi(portText)
		sessionID := sniffer.MakeConnectionSessionID(serviceID, host, port)
		return sniffer.WithConnectionSession(ctx, sessionID)
	}
}

// newProxyHTTPServer keeps compatibility with package integrations that still
// construct a server from the beginner-facing preset.
func newProxyHTTPServer(handler http.Handler, protocol storage.Protocol) *http.Server {
	return newProxyHTTPServerForSpec(handler, storage.ProtocolPreset(protocol))
}
