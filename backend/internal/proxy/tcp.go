package proxy

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/SimoneErrigo/Janus/backend/internal/appdecode"
	"github.com/SimoneErrigo/Janus/backend/internal/dropper"
	flowmodel "github.com/SimoneErrigo/Janus/backend/internal/flow"
	"github.com/SimoneErrigo/Janus/backend/internal/framing"
	"github.com/SimoneErrigo/Janus/backend/internal/sniffer"
	"github.com/SimoneErrigo/Janus/backend/internal/storage"
)

const maxTCPCapture = 1 << 20 // 1 MB per direction per connection

func (m *Manager) startTCPProxy(ctx context.Context, cancel context.CancelFunc, svc *storage.Service) (*runningProxy, error) {
	spec := svc.RuntimeSpec()
	listenAddr := m.serviceListenAddress(spec)
	var listener net.Listener
	var err error
	if spec.Listener.TLS == storage.ClientTLSTerminate {
		tlsConfig, tlsErr := buildTLSConfig(svc)
		if tlsErr != nil {
			cancel()
			return nil, fmt.Errorf("TLS config: %w", tlsErr)
		}
		listener, err = tls.Listen("tcp", listenAddr, tlsConfig)
	} else {
		listener, err = net.Listen("tcp", listenAddr)
	}
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

// tcpLingerTimeout is the extra time the response goroutine is allowed to
// keep reading after the request side has finished. This captures late-arriving
// TCP segments such as Python rich.console.print_exception tracebacks that the
// backend sends after it has processed the full request.
const tcpLingerTimeout = 5 * time.Second

func (m *Manager) handleTCPConn(ctx context.Context, svc *storage.Service, clientConn net.Conn) {
	defer clientConn.Close()

	srcIP, srcPortStr, _ := net.SplitHostPort(clientConn.RemoteAddr().String())
	srcPort, _ := strconv.Atoi(srcPortStr)
	spec := svc.RuntimeSpec()
	dstIP := spec.Listener.Address
	dstPort := spec.Listener.Port
	sessionID := sniffer.MakeConnectionSessionID(svc.ID, srcIP, srcPort)

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var backendConn net.Conn
	var err error
	if spec.Upstream.TLS {
		backendConn, err = tls.DialWithDialer(dialer, "tcp", spec.Upstream.Address, &tls.Config{InsecureSkipVerify: true})
	} else {
		backendConn, err = dialer.DialContext(ctx, "tcp", spec.Upstream.Address)
	}
	if err != nil {
		log.Printf("[%s] TCP dial backend error: %v", svc.Name, err)
		return
	}
	defer backendConn.Close()

	// closeBoth tears down both connections immediately. Used for drop rules,
	// ctx cancellation, and when the response side finishes.
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			clientConn.Close()
			backendConn.Close()
		})
	}

	// halfCloseBackend sends TCP FIN on the write side of backendConn without
	// closing the read side. This tells the backend the client is done sending
	// while keeping backendConn readable so the response goroutine can still
	// drain any remaining (or late-arriving) data from the backend.
	halfCloseBackend := func() {
		if tc, ok := backendConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	requestFrames, err := framing.NewReader(clientConn, spec.Framing)
	if err != nil {
		log.Printf("[%s] TCP request framing error: %v", svc.Name, err)
		return
	}
	responseFrames, err := framing.NewReader(backendConn, spec.Framing)
	if err != nil {
		log.Printf("[%s] TCP response framing error: %v", svc.Name, err)
		return
	}

	// Client -> Backend (request direction) — evaluate rules on every chunk.
	// No defer closeBoth here: on natural EOF we half-close instead of tearing
	// down both sides, so the response goroutine can drain any late data.
	go func() {
		defer wg.Done()
		m.sniffCopyWithRules(backendConn, requestFrames, svc, sessionID, srcIP, srcPort, dstIP, dstPort, sniffer.DirectionRequest, closeBoth)
		// Request side is done (natural EOF, write error, or drop).
		// Half-close the write side so the backend knows the client is done,
		// then arm a linger deadline so the response goroutine drains any
		// late segments (e.g. tracebacks) before timing out.
		halfCloseBackend()
		_ = backendConn.SetReadDeadline(time.Now().Add(tcpLingerTimeout))
	}()

	// Backend -> Client (response direction) — same path as the request so inline
	// Python filters can see, rewrite, and drop responses too (a {"drop": True}
	// on a response closes the connection before the bytes reach the client).
	// defer closeBoth ensures full teardown when the response side completes,
	// whether by reading all data, by a write error to the client, or by
	// hitting the linger deadline set by the request goroutine above.
	go func() {
		defer wg.Done()
		defer closeBoth()
		m.sniffCopyWithRules(clientConn, responseFrames, svc, sessionID, dstIP, dstPort, srcIP, srcPort, sniffer.DirectionResponse, closeBoth)
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		closeBoth()
	}
}

// sniffCopyWithRules reads from src chunk by chunk, evaluates drop/alert rules
// and inline Python filters on each chunk, and forwards to dst. If a drop
// matches, closeBoth is called to tear down both connections immediately; an
// inline rewrite swaps the forwarded bytes. Each chunk is logged as a separate
// packet. Used for both directions: the regex dropper engine runs on requests
// only, while inline Python filters (pyBlock) run on requests and responses.
func (m *Manager) sniffCopyWithRules(dst io.Writer, src *framing.Reader, svc *storage.Service, sessionID string, srcIP string, srcPort int, dstIP string, dstPort int, dir sniffer.Direction, closeBoth func()) {
	for {
		chunk, readErr := src.Next()
		if len(chunk) > 0 {
			forward, shouldDrop := m.inspectTransportMessage(svc, sessionID, srcIP, srcPort, dstIP, dstPort, dir, chunk)
			if shouldDrop {
				log.Printf("[%s] TCP DROP: message blocked before forwarding", svc.Name)
				closeBoth()
				return
			}
			if _, writeErr := dst.Write(forward); writeErr != nil {
				return
			}
		}
		if readErr != nil && readErr != io.EOF {
			log.Printf("[%s] TCP framing/read error: %v", svc.Name, readErr)
		}
		if readErr != nil {
			return
		}
	}
}

// inspectTransportMessage is shared by TCP and UDP. It evaluates every
// consumer against one canonical decoded view, persists one packet and returns
// the exact bytes that may be forwarded.
func (m *Manager) inspectTransportMessage(svc *storage.Service, sessionID, srcIP string, srcPort int, dstIP string, dstPort int, dir sniffer.Direction, wire []byte) ([]byte, bool) {
	observedAt := time.Now()
	pyEventID := sniffer.MakePyFilterEventID(sessionID, dir, observedAt)
	message := flowmodel.NewMessage(wire)
	message.Decoded = appdecode.Decode(svc.RuntimeSpec(), message.Payload)
	flagRegex, flagScanner := m.currentFlagMatchers()
	flaggedAtBoundary := sniffer.CheckFlagged(flagRegex, flagScanner, "", "", message.Payload)
	_, _, flagCountAtBoundary := sniffer.CountFlags(flagRegex, flagScanner, "", "", message.Payload)
	containsFlagIDAtBoundary, matchedFlagIDsAtBoundary, _ := sniffer.CheckFlagID(m.currentFlagIDChecker(), "", "", message.Payload)
	view := flowmodel.PacketView{
		Service: svc.ID, Session: sessionID, OccurredAt: observedAt,
		Source: flowmodel.Endpoint{IP: srcIP, Port: srcPort}, Destination: flowmodel.Endpoint{IP: dstIP, Port: dstPort},
		ProtocolName: string(svc.Protocol), DirectionName: string(dir), Payload: message.Payload,
		BodyText: string(message.Payload), Raw: message.Wire, Decoded: message.Decoded,
		FlaggedValue: flaggedAtBoundary, ContainsFlagIDValue: containsFlagIDAtBoundary,
	}

	var matchedRules []sniffer.MatchedRuleInfo
	var alertRules []dropper.Rule
	shouldDrop := false
	if engine := m.engineFor(svc); engine != nil && dir == sniffer.DirectionRequest {
		result := engine.EvaluateView(view)
		for _, rule := range result.AllMatched {
			matchedRules = append(matchedRules, sniffer.MatchedRuleInfo{ID: rule.ID, Name: rule.Name, Action: string(rule.Action), Pattern: rule.Pattern, Scope: string(rule.Scope)})
		}
		shouldDrop, alertRules = result.ShouldDrop, result.AlertRules
	}

	var pyAlerts []*sniffer.Alert
	var pyFlow map[string]any
	var pyResult sniffer.PyResult
	rewritten := false
	if pyBlock := m.currentPyBlockFn(); pyBlock != nil {
		pyFlow = map[string]any{
			"service": svc.ID, "session": sessionID, "event_id": pyEventID, "direction": string(dir), "src": srcIP, "dst": dstIP,
			"sport": srcPort, "dport": dstPort, "protocol": string(svc.Protocol), "body": string(message.Payload),
			"body_b64": base64.StdEncoding.EncodeToString(message.Payload), "decoded": message.Decoded,
			"flagged": flaggedAtBoundary, "contains_flagid": containsFlagIDAtBoundary,
			"matched_flagids": matchedFlagIDsAtBoundary, "flag_count_body": flagCountAtBoundary,
			"admitted": !shouldDrop, "timestamp": float64(observedAt.UnixNano()) / float64(time.Second),
		}
		res := pyBlock(pyFlow)
		pyResult = res
		for _, alert := range res.Alerts {
			matchedRules = append(matchedRules, sniffer.MatchedRuleInfo{ID: "pyfilter:" + alert.Script, Name: "Python alert (" + alert.Script + ")", Action: "alert", Pattern: alert.Reason, Scope: "python"})
			pyAlerts = append(pyAlerts, &sniffer.Alert{RuleID: "pyfilter:" + alert.Script, ServiceID: svc.ID, SrcIP: srcIP, Timestamp: time.Now(), PatternMatched: alert.Reason})
		}
		for _, bm := range res.Blocks {
			matchedRules = append(matchedRules, sniffer.MatchedRuleInfo{ID: "pyfilter:" + bm.Script, Name: "Python block (" + bm.Script + ")", Action: "drop", Pattern: bm.Reason, Scope: "python"})
			pyAlerts = append(pyAlerts, &sniffer.Alert{RuleID: "pyfilter:" + bm.Script, ServiceID: svc.ID, SrcIP: srcIP, Timestamp: time.Now(), PatternMatched: bm.Reason})
			shouldDrop = true
		}
		if res.Rewritten && !shouldDrop {
			message.Wire = append([]byte(nil), res.NewBody...)
			message.Payload = message.Wire
			message.Decoded = appdecode.Decode(svc.RuntimeSpec(), message.Payload)
			rewritten = true
		}
	}

	mustPersist := m.packetStore != nil && (m.shouldCapture() || shouldDrop || len(alertRules) > 0 || len(pyAlerts) > 0)
	if mustPersist || rewritten {
		flagRegex, flagScanner = m.currentFlagMatchers()
		flagged := sniffer.CheckFlagged(flagRegex, flagScanner, "", "", message.Payload)
		containsFlagID, matchedFlagIDs, flagIDRound := false, []string(nil), 0
		_, _, flagCountBody := sniffer.CountFlags(flagRegex, flagScanner, "", "", message.Payload)
		if m.shouldApplyFlagIDsOnIngest() {
			containsFlagID, matchedFlagIDs, flagIDRound = sniffer.CheckFlagID(m.currentFlagIDChecker(), "", "", message.Payload)
		}
		pyResult.Reconcile(pyFlow, message.Payload, !shouldDrop, false, flagged, containsFlagID,
			matchedFlagIDs, flagCountBody, 0, 0)
		if !mustPersist {
			return message.Wire, shouldDrop
		}
		if matchedRules == nil {
			matchedRules = []sniffer.MatchedRuleInfo{}
		}
		now := time.Now()
		pkt := &sniffer.Packet{
			ServiceID: svc.ID, SessionID: sessionID, Timestamp: now, SrcIP: srcIP, SrcPort: srcPort, DstIP: dstIP, DstPort: dstPort,
			Protocol: string(svc.Protocol), Direction: dir, Body: append([]byte(nil), message.Payload...), Decoded: message.Decoded,
			MatchedRules: matchedRules, Flagged: flagged, ContainsFlagID: containsFlagID, MatchedFlagIDs: matchedFlagIDs,
			FlagIDRound: flagIDRound, Verdict: sniffer.VerdictFor(dir, matchedRules, shouldDrop, rewritten, true),
			FlagCountBody: flagCountBody, PyFilterEventID: pyEventID,
		}
		alerts := make([]*sniffer.Alert, 0, len(alertRules)+len(pyAlerts))
		for _, rule := range alertRules {
			alerts = append(alerts, &sniffer.Alert{RuleID: rule.ID, ServiceID: svc.ID, SrcIP: srcIP, Timestamp: now, PatternMatched: rule.Pattern})
		}
		alerts = append(alerts, pyAlerts...)
		if err := m.packetStore.Enqueue(pkt, alerts); err != nil {
			log.Printf("[%s] sniffer: failed to log packet: %v", svc.Name, err)
		}
	}
	return message.Wire, shouldDrop
}
