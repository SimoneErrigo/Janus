package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/SimoneErrigo/Janus/backend/internal/sniffer"
	"github.com/SimoneErrigo/Janus/backend/internal/storage"
)

const (
	udpSessionTTL  = 60 * time.Second
	udpMaxSessions = 4096
)

type udpListener struct{ *net.UDPConn }

func (l udpListener) Accept() (net.Conn, error) {
	return nil, errors.New("UDP listener does not accept streams")
}
func (l udpListener) Addr() net.Addr { return l.LocalAddr() }

type udpSession struct {
	conn     *net.UDPConn
	client   *net.UDPAddr
	id       string
	lastSeen atomic.Int64
}

func (m *Manager) startUDPProxy(ctx context.Context, cancel context.CancelFunc, svc *storage.Service) (*runningProxy, error) {
	spec := svc.RuntimeSpec()
	listenAddr, err := net.ResolveUDPAddr("udp", m.serviceListenAddress(spec))
	if err != nil {
		cancel()
		return nil, fmt.Errorf("resolve UDP listener: %w", err)
	}
	upstreamAddr, err := net.ResolveUDPAddr("udp", spec.Upstream.Address)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("resolve UDP upstream: %w", err)
	}
	conn, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("UDP listen on %s: %w", listenAddr, err)
	}

	rp := &runningProxy{service: svc, listener: udpListener{conn}, cancel: cancel}
	var sessionsMu sync.Mutex
	sessions := map[string]*udpSession{}
	closeSessions := func() {
		sessionsMu.Lock()
		defer sessionsMu.Unlock()
		for key, session := range sessions {
			_ = session.conn.Close()
			delete(sessions, key)
		}
	}

	removeSession := func(key string, session *udpSession) {
		sessionsMu.Lock()
		defer sessionsMu.Unlock()
		if sessions[key] == session {
			delete(sessions, key)
		}
	}

	var responseLoop func(string, *udpSession)
	responseLoop = func(key string, session *udpSession) {
		defer removeSession(key, session)
		buf := make([]byte, 65535)
		for {
			n, err := session.conn.Read(buf)
			if err != nil {
				return
			}
			wire := append([]byte(nil), buf[:n]...)
			forward, drop := m.inspectTransportMessage(svc, session.id, spec.Listener.Address, spec.Listener.Port, session.client.IP.String(), session.client.Port, sniffer.DirectionResponse, wire)
			if !drop {
				_, _ = conn.WriteToUDP(forward, session.client)
			}
		}
	}

	getSession := func(client *net.UDPAddr) (*udpSession, error) {
		key := client.String()
		now := time.Now().UnixNano()
		sessionsMu.Lock()
		defer sessionsMu.Unlock()
		if existing := sessions[key]; existing != nil {
			existing.lastSeen.Store(now)
			return existing, nil
		}
		if len(sessions) >= udpMaxSessions {
			var oldestKey string
			var oldestSeen int64
			for candidateKey, candidate := range sessions {
				seen := candidate.lastSeen.Load()
				if oldestKey == "" || seen < oldestSeen {
					oldestKey, oldestSeen = candidateKey, seen
				}
			}
			if oldest := sessions[oldestKey]; oldest != nil {
				_ = oldest.conn.Close()
				delete(sessions, oldestKey)
			}
		}
		upstream, dialErr := net.DialUDP("udp", nil, upstreamAddr)
		if dialErr != nil {
			return nil, dialErr
		}
		session := &udpSession{
			conn: upstream, client: cloneUDPAddr(client),
			id: sniffer.MakeConnectionSessionID(svc.ID, client.IP.String(), client.Port),
		}
		session.lastSeen.Store(now)
		sessions[key] = session
		go responseLoop(key, session)
		return session, nil
	}

	go func() {
		buf := make([]byte, 65535)
		for {
			n, client, readErr := conn.ReadFromUDP(buf)
			if readErr != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			session, sessionErr := getSession(client)
			if sessionErr != nil {
				continue
			}
			wire := append([]byte(nil), buf[:n]...)
			forward, drop := m.inspectTransportMessage(svc, session.id, client.IP.String(), client.Port, spec.Listener.Address, spec.Listener.Port, sniffer.DirectionRequest, wire)
			if !drop {
				_, _ = session.conn.Write(forward)
			}
		}
	}()

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				_ = conn.Close()
				closeSessions()
				return
			case now := <-ticker.C:
				cutoff := now.Add(-udpSessionTTL).UnixNano()
				sessionsMu.Lock()
				for key, session := range sessions {
					if session.lastSeen.Load() < cutoff {
						_ = session.conn.Close()
						delete(sessions, key)
					}
				}
				sessionsMu.Unlock()
			}
		}
	}()

	return rp, nil
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	return &net.UDPAddr{IP: append(net.IP(nil), addr.IP...), Port: addr.Port, Zone: addr.Zone}
}
