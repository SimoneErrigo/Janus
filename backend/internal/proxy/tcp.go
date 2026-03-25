package proxy

import (
	"context"
	"io"
	"log"
	"net"
	"fmt"
	"sync"
	"time"

	"github.com/SimoneErrigo/Janus/backend/internal/storage"
)

func (m *Manager) startTCPProxy(ctx context.Context, cancel context.CancelFunc, svc *storage.Service) (*runningProxy, error) {
	listenAddr := fmt.Sprintf("%s:%d", svc.ListenAddr, svc.ListenPort)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("TCP listen on %s: %w", listenAddr, err)
	}

	rp := &runningProxy{
		service:  svc,
		listener: listener,
		cancel:   cancel,
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					log.Printf("[%s] TCP accept error: %v", svc.Name, err)
					continue
				}
			}
			go handleTCPConn(ctx, svc, conn)
		}
	}()

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	return rp, nil
}

func handleTCPConn(ctx context.Context, svc *storage.Service, clientConn net.Conn) {
	defer clientConn.Close()

	backendConn, err := net.DialTimeout("tcp", svc.TargetAddr, 10*time.Second)
	if err != nil {
		log.Printf("[%s] TCP dial backend error: %v", svc.Name, err)
		return
	}
	defer backendConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Backend
	go func() {
		defer wg.Done()
		io.Copy(backendConn, clientConn)
		backendConn.(*net.TCPConn).CloseWrite()
	}()

	// Backend -> Client
	go func() {
		defer wg.Done()
		io.Copy(clientConn, backendConn)
		clientConn.(*net.TCPConn).CloseWrite()
	}()

	// Wait for both directions to finish or context cancel
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}
}
