package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/SimoneErrigo/Janus/backend/internal/sniffer"
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
			go m.handleTCPConn(ctx, svc, conn)
		}
	}()

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	return rp, nil
}

func (m *Manager) handleTCPConn(ctx context.Context, svc *storage.Service, clientConn net.Conn) {
	defer clientConn.Close()

	backendConn, err := net.DialTimeout("tcp", svc.TargetAddr, 10*time.Second)
	if err != nil {
		log.Printf("[%s] TCP dial backend error: %v", svc.Name, err)
		return
	}
	defer backendConn.Close()

	srcIP, srcPortStr, _ := net.SplitHostPort(clientConn.RemoteAddr().String())
	srcPort, _ := strconv.Atoi(srcPortStr)
	dstIP := svc.ListenAddr
	dstPort := svc.ListenPort

	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Backend (request direction)
	go func() {
		defer wg.Done()
		m.sniffCopy(backendConn, clientConn, svc, srcIP, srcPort, dstIP, dstPort, sniffer.DirectionRequest)
		if tc, ok := backendConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	// Backend -> Client (response direction)
	go func() {
		defer wg.Done()
		m.sniffCopy(clientConn, backendConn, svc, dstIP, dstPort, srcIP, srcPort, sniffer.DirectionResponse)
		if tc, ok := clientConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

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

const maxTCPCapture = 1 << 20 // 1 MB per direction per connection

func (m *Manager) sniffCopy(dst io.Writer, src io.Reader, svc *storage.Service, srcIP string, srcPort int, dstIP string, dstPort int, dir sniffer.Direction) {
	var buf bytes.Buffer
	writer := dst
	if m.packetStore != nil {
		// Use TeeReader to capture a copy of the data
		limited := &limitedWriter{buf: &buf, max: maxTCPCapture}
		writer = io.MultiWriter(dst, limited)
	}

	io.Copy(writer, src)

	if m.packetStore != nil && buf.Len() > 0 {
		pkt := &sniffer.Packet{
			ServiceID: svc.ID,
			Timestamp: time.Now(),
			SrcIP:     srcIP,
			SrcPort:   srcPort,
			DstIP:     dstIP,
			DstPort:   dstPort,
			Protocol:  string(svc.Protocol),
			Direction: dir,
			Body:      buf.Bytes(),
		}
		if err := m.packetStore.Insert(pkt); err != nil {
			log.Printf("[%s] sniffer: failed to log TCP packet: %v", svc.Name, err)
		}
	}
}

// limitedWriter writes up to max bytes into buf, then silently discards the rest.
type limitedWriter struct {
	buf *bytes.Buffer
	max int
}

func (lw *limitedWriter) Write(p []byte) (int, error) {
	remaining := lw.max - lw.buf.Len()
	if remaining <= 0 {
		return len(p), nil // discard but report success
	}
	if len(p) > remaining {
		p = p[:remaining]
	}
	lw.buf.Write(p)
	return len(p), nil
}
