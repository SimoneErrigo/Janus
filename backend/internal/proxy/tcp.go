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

	"github.com/SimoneErrigo/Janus/backend/internal/dropper"
	"github.com/SimoneErrigo/Janus/backend/internal/sniffer"
	"github.com/SimoneErrigo/Janus/backend/internal/storage"
)

const maxTCPCapture = 1 << 20 // 1 MB per direction per connection

func (m *Manager) startTCPProxy(ctx context.Context, cancel context.CancelFunc, svc *storage.Service) (*runningProxy, error) {
	listenAddr := fmt.Sprintf("0.0.0.0:%d", svc.ListenPort)
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

	srcIP, srcPortStr, _ := net.SplitHostPort(clientConn.RemoteAddr().String())
	srcPort, _ := strconv.Atoi(srcPortStr)
	dstIP := svc.ListenAddr
	dstPort := svc.ListenPort
	sessionID := sniffer.MakeSessionID(svc.ID, srcIP, srcPort)

	// Read initial data from client for rule evaluation
	var initialData []byte
	var matchedRules []sniffer.MatchedRuleInfo
	shouldDrop := false
	var alertRules []dropper.Rule

	if m.ruleStore != nil {
		buf := make([]byte, 4096)
		clientConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _ := clientConn.Read(buf)
		clientConn.SetReadDeadline(time.Time{})
		if n > 0 {
			initialData = buf[:n]

			// Evaluate all rules on initial data
			engine := dropper.NewEngine(m.ruleStore)
			result := engine.EvaluateActions(&dropper.HTTPRequest{
				ServiceID: svc.ID,
				RawBytes:  initialData,
				Body:      initialData,
			})
			for _, rule := range result.AllMatched {
				matchedRules = append(matchedRules, sniffer.MatchedRuleInfo{ID: rule.ID, Name: rule.Name, Action: string(rule.Action)})
			}
			shouldDrop = result.ShouldDrop
			alertRules = result.AlertRules
		}
	}

	// Check flagged and log the initial request packet
	now := time.Now()
	if len(initialData) > 0 && m.packetStore != nil {
		flagged := sniffer.CheckFlagged(m.flagRegex, "", "", initialData)
		if matchedRules == nil {
			matchedRules = []sniffer.MatchedRuleInfo{}
		}
		pkt := &sniffer.Packet{
			ServiceID:    svc.ID,
			SessionID:    sessionID,
			Timestamp:    now,
			SrcIP:        srcIP,
			SrcPort:      srcPort,
			DstIP:        dstIP,
			DstPort:      dstPort,
			Protocol:     string(svc.Protocol),
			Direction:    sniffer.DirectionRequest,
			Body:         initialData,
			MatchedRules: matchedRules,
			Flagged:      flagged,
		}
		if err := m.packetStore.Insert(pkt); err != nil {
			log.Printf("[%s] sniffer: failed to log TCP initial packet: %v", svc.Name, err)
		}

		// Insert alerts for alert/both rules
		for _, rule := range alertRules {
			alert := &sniffer.Alert{
				PacketID:       pkt.ID,
				RuleID:         rule.ID,
				ServiceID:      svc.ID,
				SrcIP:          srcIP,
				Timestamp:      now,
				PatternMatched: rule.Pattern,
			}
			if err := m.packetStore.InsertAlert(alert); err != nil {
				log.Printf("[%s] sniffer: failed to log TCP alert: %v", svc.Name, err)
			}
		}
	}

	if shouldDrop {
		log.Printf("[%s] TCP DROP: %d rule(s) matched", svc.Name, len(matchedRules))
		if tc, ok := clientConn.(*net.TCPConn); ok {
			tc.SetLinger(0)
		}
		return
	}

	backendConn, err := net.DialTimeout("tcp", svc.TargetAddr, 10*time.Second)
	if err != nil {
		log.Printf("[%s] TCP dial backend error: %v", svc.Name, err)
		return
	}
	defer backendConn.Close()

	// Forward initial data that was already read
	if len(initialData) > 0 {
		backendConn.Write(initialData)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Backend (request direction)
	go func() {
		defer wg.Done()
		m.sniffCopy(backendConn, clientConn, svc, sessionID, srcIP, srcPort, dstIP, dstPort, sniffer.DirectionRequest)
		if tc, ok := backendConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	// Backend -> Client (response direction)
	go func() {
		defer wg.Done()
		m.sniffCopy(clientConn, backendConn, svc, sessionID, dstIP, dstPort, srcIP, srcPort, sniffer.DirectionResponse)
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

func (m *Manager) sniffCopy(dst io.Writer, src io.Reader, svc *storage.Service, sessionID string, srcIP string, srcPort int, dstIP string, dstPort int, dir sniffer.Direction) {
	var buf bytes.Buffer
	writer := dst
	if m.packetStore != nil {
		// Use TeeReader to capture a copy of the data
		limited := &limitedWriter{buf: &buf, max: maxTCPCapture}
		writer = io.MultiWriter(dst, limited)
	}

	io.Copy(writer, src)

	if m.packetStore != nil && buf.Len() > 0 {
		data := buf.Bytes()
		flagged := sniffer.CheckFlagged(m.flagRegex, "", "", data)
		pkt := &sniffer.Packet{
			ServiceID:    svc.ID,
			SessionID:    sessionID,
			Timestamp:    time.Now(),
			SrcIP:        srcIP,
			SrcPort:      srcPort,
			DstIP:        dstIP,
			DstPort:      dstPort,
			Protocol:     string(svc.Protocol),
			Direction:    dir,
			Body:         data,
			MatchedRules: []sniffer.MatchedRuleInfo{},
			Flagged:      flagged,
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
