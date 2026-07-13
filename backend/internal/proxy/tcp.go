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
	sessionID := sniffer.MakeSessionID(svc.ID, srcIP, srcPort)

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
	engine := m.engineFor(svc)

	for {
		chunk, readErr := src.Next()
		if len(chunk) > 0 {
			flaggedAtBoundary := sniffer.CheckFlagged(m.flagRegex, m.flagScanner, "", "", chunk)
			containsFlagIDAtBoundary, _, _ := sniffer.CheckFlagID(m.currentFlagIDChecker(), "", "", chunk)
			view := flowmodel.PacketView{
				Service: svc.ID, Session: sessionID, OccurredAt: time.Now(),
				Source:       flowmodel.Endpoint{IP: srcIP, Port: srcPort},
				Destination:  flowmodel.Endpoint{IP: dstIP, Port: dstPort},
				ProtocolName: string(svc.Protocol), DirectionName: string(dir),
				Payload: chunk, BodyText: string(chunk), Raw: chunk,
				FlaggedValue: flaggedAtBoundary, ContainsFlagIDValue: containsFlagIDAtBoundary,
			}

			// Evaluate rules on this chunk. The regex dropper engine is
			// request-only (its rules and IP/port scopes are written for
			// requests); the response direction relies on inline Python
			// filters below.
			var matchedRules []sniffer.MatchedRuleInfo
			shouldDrop := false
			var alertRules []dropper.Rule

			if engine != nil && dir == sniffer.DirectionRequest {
				result := engine.EvaluateView(view)
				for _, rule := range result.AllMatched {
					matchedRules = append(matchedRules, sniffer.MatchedRuleInfo{
						ID:      rule.ID,
						Name:    rule.Name,
						Action:  string(rule.Action),
						Pattern: rule.Pattern,
						Scope:   string(rule.Scope),
					})
				}
				shouldDrop = result.ShouldDrop
				alertRules = result.AlertRules
			}

			// Inline (synchronous) Python filters on this chunk: they can block
			// (close the connection) or rewrite the bytes before we forward them.
			// Exact bytes ride as base64 so binary payloads survive JSON.
			var pyBlockAlerts []*sniffer.Alert
			rewritten := false
			if pyBlock := m.currentPyBlockFn(); pyBlock != nil {
				// Tag flag/flagID presence up front so inline filters can use
				// flow.flagged / flow.contains_flagid without parsing.
				flow := map[string]any{
					"service":         svc.ID,
					"direction":       string(dir),
					"src":             srcIP,
					"dst":             dstIP,
					"sport":           srcPort,
					"dport":           dstPort,
					"protocol":        string(svc.Protocol),
					"body":            string(chunk),
					"body_b64":        base64.StdEncoding.EncodeToString(chunk),
					"flagged":         flaggedAtBoundary,
					"contains_flagid": containsFlagIDAtBoundary,
				}
				res := pyBlock(flow)
				for _, bm := range res.Blocks {
					matchedRules = append(matchedRules, sniffer.MatchedRuleInfo{
						ID:      "pyfilter:" + bm.Script,
						Name:    "Python block (" + bm.Script + ")",
						Action:  "drop",
						Pattern: bm.Reason,
						Scope:   "python",
					})
					pyBlockAlerts = append(pyBlockAlerts, &sniffer.Alert{
						RuleID:         "pyfilter:" + bm.Script,
						ServiceID:      svc.ID,
						SrcIP:          srcIP,
						Timestamp:      time.Now(),
						PatternMatched: bm.Reason,
					})
					shouldDrop = true
				}
				if res.Rewritten && !shouldDrop {
					rewritten = true
					chunk = res.NewBody // forward + log the rewritten bytes
				}
			}

			captureEnabled := m.shouldCapture()
			mustPersist := captureEnabled || shouldDrop || len(alertRules) > 0 || len(pyBlockAlerts) > 0

			// Log this chunk as a packet
			if m.packetStore != nil && mustPersist {
				now := time.Now()
				flagged := sniffer.CheckFlagged(m.flagRegex, m.flagScanner, "", "", chunk)
				containsFlagID, matchedFlagIDs, flagIDRound := false, []string(nil), 0
				if m.shouldApplyFlagIDsOnIngest() {
					containsFlagID, matchedFlagIDs, flagIDRound = sniffer.CheckFlagID(m.currentFlagIDChecker(), "", "", chunk)
				}
				if matchedRules == nil {
					matchedRules = []sniffer.MatchedRuleInfo{}
				}
				data := make([]byte, len(chunk))
				copy(data, chunk)
				pkt := &sniffer.Packet{
					ServiceID:      svc.ID,
					SessionID:      sessionID,
					Timestamp:      now,
					SrcIP:          srcIP,
					SrcPort:        srcPort,
					DstIP:          dstIP,
					DstPort:        dstPort,
					Protocol:       string(svc.Protocol),
					Direction:      dir,
					Body:           data,
					MatchedRules:   matchedRules,
					Flagged:        flagged,
					ContainsFlagID: containsFlagID,
					MatchedFlagIDs: matchedFlagIDs,
					FlagIDRound:    flagIDRound,
					Verdict:        sniffer.VerdictFor(dir, matchedRules, shouldDrop, rewritten, true),
				}
				alertTemplates := make([]*sniffer.Alert, 0, len(alertRules)+len(pyBlockAlerts))
				for _, rule := range alertRules {
					alertTemplates = append(alertTemplates, &sniffer.Alert{
						RuleID:         rule.ID,
						ServiceID:      svc.ID,
						SrcIP:          srcIP,
						Timestamp:      now,
						PatternMatched: rule.Pattern,
					})
				}
				alertTemplates = append(alertTemplates, pyBlockAlerts...)
				if err := m.packetStore.Enqueue(pkt, alertTemplates); err != nil {
					log.Printf("[%s] sniffer: failed to log TCP packet: %v", svc.Name, err)
				}
			}

			if shouldDrop {
				log.Printf("[%s] TCP DROP: %d rule(s) matched on chunk", svc.Name, len(matchedRules))
				closeBoth()
				return
			}

			// Forward chunk to backend
			if _, writeErr := dst.Write(chunk); writeErr != nil {
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
