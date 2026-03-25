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
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/SimoneErrigo/Janus/backend/internal/sniffer"
	"github.com/SimoneErrigo/Janus/backend/internal/storage"
)

// Manager manages proxy instances for configured services.
type Manager struct {
	mu          sync.RWMutex
	proxies     map[string]*runningProxy // service ID -> running proxy
	packetStore *sniffer.PacketStore
}

type runningProxy struct {
	service  *storage.Service
	listener net.Listener
	server   *http.Server
	cancel   context.CancelFunc
}

// NewManager creates a new proxy manager.
func NewManager(packetStore *sniffer.PacketStore) *Manager {
	return &Manager{
		proxies:     make(map[string]*runningProxy),
		packetStore: packetStore,
	}
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

	listenAddr := fmt.Sprintf("%s:%d", svc.ListenAddr, svc.ListenPort)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("listen on %s: %w", listenAddr, err)
	}

	var handler http.Handler = reverseProxy
	if m.packetStore != nil {
		handler = sniffer.HTTPMiddleware(reverseProxy, svc, m.packetStore)
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

	// Target is the backend service (plaintext HTTP)
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

	// For gRPC/HTTP2, configure HTTP/2 transport to backend
	if svc.Protocol == storage.ProtocolGRPC || svc.Protocol == storage.ProtocolHTTP2 {
		reverseProxy.Transport = &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				// Connect to backend over plaintext
				return net.DialTimeout(network, addr, 10*time.Second)
			},
		}
	}

	var handler http.Handler = reverseProxy
	if m.packetStore != nil {
		handler = sniffer.HTTPMiddleware(handler, svc, m.packetStore)
	}

	// For gRPC, support h2c (HTTP/2 cleartext) from backend if needed
	if svc.Protocol == storage.ProtocolGRPC {
		h2s := &http2.Server{}
		handler = h2c.NewHandler(handler, h2s)
	}

	listenAddr := fmt.Sprintf("%s:%d", svc.ListenAddr, svc.ListenPort)
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
