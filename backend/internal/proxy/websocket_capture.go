package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/SimoneErrigo/Janus/backend/internal/dropper"
	flowmodel "github.com/SimoneErrigo/Janus/backend/internal/flow"
	"github.com/SimoneErrigo/Janus/backend/internal/sniffer"
	"github.com/SimoneErrigo/Janus/backend/internal/storage"
)

const maxWebSocketMessageCapture = 1 << 20 // 1 MB per reassembled message

const (
	webSocketOpcodeContinuation byte = 0x0
	webSocketOpcodeText         byte = 0x1
	webSocketOpcodeBinary       byte = 0x2
)

// configureWebSocketReverseProxy makes WS/WSS upgrades observable without
// changing their wire semantics. The standard ReverseProxy owns the tunnel;
// wrapping its upgraded backend connection lets us see bytes in both
// directions while still forwarding them unchanged.
func (m *Manager) configureWebSocketReverseProxy(ctx context.Context, reverseProxy *httputil.ReverseProxy, svc *storage.Service) {
	if svc.RuntimeSpec().Application.Profile != storage.ApplicationWebSocket {
		return
	}

	// WebSocket extensions are optional but may transform payload bytes and set
	// RSV bits, making generic filtering impossible without extension-specific
	// codecs. Strip the extension offer while preserving subprotocols: every
	// RFC 6455 service then falls back to standard, filterable frames.
	director := reverseProxy.Director
	reverseProxy.Director = func(r *http.Request) {
		director(r)
		r.Header.Del("Sec-WebSocket-Extensions")
	}

	previousModifyResponse := reverseProxy.ModifyResponse
	reverseProxy.ModifyResponse = func(resp *http.Response) error {
		if previousModifyResponse != nil {
			if err := previousModifyResponse(resp); err != nil {
				return err
			}
		}
		if resp.StatusCode != http.StatusSwitchingProtocols ||
			!strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
			return nil
		}

		backendConn, ok := resp.Body.(io.ReadWriteCloser)
		if !ok {
			return fmt.Errorf("websocket upgrade response has a non-writable body")
		}

		meta := websocketCaptureMeta{
			listenerIP:   svc.ListenAddr,
			listenerPort: svc.ListenPort,
		}
		if resp.Request != nil {
			meta.clientIP, meta.clientPort = splitWebSocketRemoteAddr(resp.Request.RemoteAddr)
			if resp.Request.URL != nil {
				meta.url = resp.Request.URL.RequestURI()
			}
		}
		if resp.Request != nil {
			meta.sessionID, _ = sniffer.ConnectionSessionFromContext(resp.Request.Context())
		}
		if meta.sessionID == "" {
			meta.sessionID = sniffer.MakeConnectionSessionID(svc.ID, meta.clientIP, meta.clientPort)
		}

		captured := &websocketCaptureConn{ReadWriteCloser: backendConn, done: make(chan struct{})}
		captured.toBackend = newWebSocketFrameParser(true,
			func(opcode byte, payload []byte) websocketMessageDecision {
				decision := m.processWebSocketMessage(svc, meta, sniffer.DirectionRequest, opcode, payload)
				if decision.Close {
					captured.terminate.Store(true)
				}
				return decision
			},
			func(opcode byte, size uint64) {
				m.recordOversizedWebSocketMessage(svc, meta, sniffer.DirectionRequest, opcode, size)
			},
		)
		captured.fromBackend = newWebSocketFrameParser(false,
			func(opcode byte, payload []byte) websocketMessageDecision {
				decision := m.processWebSocketMessage(svc, meta, sniffer.DirectionResponse, opcode, payload)
				if decision.Close {
					captured.terminate.Store(true)
				}
				return decision
			},
			func(opcode byte, size uint64) {
				m.recordOversizedWebSocketMessage(svc, meta, sniffer.DirectionResponse, opcode, size)
			},
		)
		resp.Body = captured
		go func() {
			select {
			case <-ctx.Done():
				_ = captured.Close()
			case <-captured.done:
			}
		}()
		return nil
	}
}

type websocketCaptureMeta struct {
	clientIP     string
	clientPort   int
	listenerIP   string
	listenerPort int
	sessionID    string
	url          string
}

// websocketCaptureConn is a message-aware full-duplex gate. ReverseProxy
// writes client frames to the backend and reads server frames from it. Each
// side buffers a complete application message, applies the filter decision,
// and emits either the original frames, one rewritten frame, or no frame.
type websocketCaptureConn struct {
	io.ReadWriteCloser
	toBackend   *websocketFrameParser
	fromBackend *websocketFrameParser

	readOutput  bytes.Buffer
	readScratch [32 * 1024]byte
	readErr     error
	closeOnce   sync.Once
	terminate   atomic.Bool
	done        chan struct{}
}

func (c *websocketCaptureConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		err = c.ReadWriteCloser.Close()
		close(c.done)
	})
	return err
}

func (c *websocketCaptureConn) Read(p []byte) (int, error) {
	for {
		if c.readOutput.Len() > 0 {
			return c.readOutput.Read(p)
		}
		if c.readErr != nil {
			err := c.readErr
			c.readErr = nil
			return 0, err
		}

		n, err := c.ReadWriteCloser.Read(c.readScratch[:])
		if n > 0 {
			c.readOutput.Write(c.fromBackend.Feed(c.readScratch[:n]))
			if c.terminate.Load() {
				_ = c.Close()
				return 0, net.ErrClosed
			}
		}
		if err != nil {
			c.readErr = err
		}
	}
}

func (c *websocketCaptureConn) Write(p []byte) (int, error) {
	output := c.toBackend.Feed(p)
	if c.terminate.Load() {
		_ = c.Close()
		return 0, net.ErrClosed
	}
	for len(output) > 0 {
		n, err := c.ReadWriteCloser.Write(output)
		if n > 0 {
			output = output[n:]
		}
		if err != nil {
			return 0, err
		}
		if n == 0 {
			return 0, io.ErrShortWrite
		}
	}
	// The input has been accepted into the message buffer even when no output
	// is ready yet (for example, midway through a fragmented message).
	return len(p), nil
}

type websocketMessageDecision struct {
	Payload   []byte
	Drop      bool
	Close     bool
	Rewritten bool
}

func websocketEndpoints(meta websocketCaptureMeta, dir sniffer.Direction) (srcIP string, srcPort int, dstIP string, dstPort int) {
	srcIP, srcPort = meta.clientIP, meta.clientPort
	dstIP, dstPort = meta.listenerIP, meta.listenerPort
	if dir == sniffer.DirectionResponse {
		srcIP, srcPort, dstIP, dstPort = dstIP, dstPort, srcIP, srcPort
	}
	return srcIP, srcPort, dstIP, dstPort
}

func websocketMessageHeaders(opcode byte) (string, map[string]string) {
	opcodeName := "binary"
	headers := map[string]string{"X-Janus-WebSocket-Opcode": opcodeName}
	if opcode == webSocketOpcodeText {
		opcodeName = "text"
		headers["X-Janus-WebSocket-Opcode"] = opcodeName
		headers["Content-Type"] = "text/plain; charset=utf-8"
	}
	return opcodeName, headers
}

// processWebSocketMessage runs the same rule/PyFilter path used by the other
// proxies, but at WebSocket message boundaries and on the unmasked payload.
// The returned decision is applied before bytes reach the opposite peer.
func (m *Manager) processWebSocketMessage(svc *storage.Service, meta websocketCaptureMeta, dir sniffer.Direction, opcode byte, payload []byte) websocketMessageDecision {
	observedAt := time.Now()
	pyEventID := sniffer.MakePyFilterEventID(meta.sessionID, dir, observedAt)
	body := append([]byte(nil), payload...)
	opcodeName, headers := websocketMessageHeaders(opcode)
	srcIP, srcPort, dstIP, dstPort := websocketEndpoints(meta, dir)
	flagRegex, flagScanner := m.currentFlagMatchers()
	pyFlagged := sniffer.CheckFlagged(flagRegex, flagScanner, "", "", body)
	_, _, pyFlagCount := sniffer.CountFlags(flagRegex, flagScanner, "", "", body)
	pyContainsFlagID, pyMatchedFlagIDs, _ := sniffer.CheckFlagID(m.currentFlagIDChecker(), "", "", body)

	var matchedRules []sniffer.MatchedRuleInfo
	shouldDrop := false
	shouldClose := false
	var alertRules []dropper.Rule
	if engine := m.engineFor(svc); engine != nil && dir == sniffer.DirectionRequest {
		view := flowmodel.PacketView{
			Service: svc.ID, Session: meta.sessionID, OccurredAt: time.Now(),
			Source:       flowmodel.Endpoint{IP: srcIP, Port: srcPort},
			Destination:  flowmodel.Endpoint{IP: dstIP, Port: dstPort},
			ProtocolName: string(svc.Protocol), DirectionName: string(dir),
			MethodName: "WS", URLValue: meta.url, HeaderValues: headers,
			Payload: body, BodyText: string(body), Raw: body,
			FlaggedValue: pyFlagged, ContainsFlagIDValue: pyContainsFlagID,
		}
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

	// Calculate the original-message tags for inline Python filters. Persisted
	// flag metadata is recalculated below after any rewrite.
	var pyBlockAlerts []*sniffer.Alert
	var pyFlow map[string]any
	var pyResult sniffer.PyResult
	rewritten := false
	if pyBlock := m.currentPyBlockFn(); pyBlock != nil {
		pyFlow = map[string]any{
			"service":          svc.ID,
			"session":          meta.sessionID,
			"event_id":         pyEventID,
			"direction":        string(dir),
			"method":           "WS",
			"url":              meta.url,
			"status":           0,
			"src":              srcIP,
			"dst":              dstIP,
			"sport":            srcPort,
			"dport":            dstPort,
			"protocol":         string(svc.Protocol),
			"headers":          headers,
			"body":             string(body),
			"body_b64":         base64.StdEncoding.EncodeToString(body),
			"flagged":          pyFlagged,
			"contains_flagid":  pyContainsFlagID,
			"matched_flagids":  pyMatchedFlagIDs,
			"flag_count_body":  pyFlagCount,
			"admitted":         !shouldDrop,
			"timestamp":        float64(observedAt.UnixNano()) / float64(time.Second),
			"websocket_opcode": opcodeName,
		}
		result := pyBlock(pyFlow)
		pyResult = result
		for _, alert := range result.Alerts {
			matchedRules = append(matchedRules, sniffer.MatchedRuleInfo{ID: "pyfilter:" + alert.Script, Name: "Python alert (" + alert.Script + ")", Action: "alert", Pattern: alert.Reason, Scope: "python"})
			pyBlockAlerts = append(pyBlockAlerts, &sniffer.Alert{RuleID: "pyfilter:" + alert.Script, ServiceID: svc.ID, SrcIP: srcIP, Timestamp: time.Now(), PatternMatched: alert.Reason})
		}
		for _, block := range result.Blocks {
			shouldClose = shouldClose || block.Close
			matchedRules = append(matchedRules, sniffer.MatchedRuleInfo{
				ID:      "pyfilter:" + block.Script,
				Name:    "Python block (" + block.Script + ")",
				Action:  "drop",
				Pattern: block.Reason,
				Scope:   "python",
			})
			pyBlockAlerts = append(pyBlockAlerts, &sniffer.Alert{
				RuleID:         "pyfilter:" + block.Script,
				ServiceID:      svc.ID,
				SrcIP:          srcIP,
				Timestamp:      time.Now(),
				PatternMatched: block.Reason,
			})
			shouldDrop = true
		}
		if result.Rewritten && !shouldDrop {
			if opcode == webSocketOpcodeText && !utf8.Valid(result.NewBody) {
				log.Printf("[%s] WebSocket rewrite ignored: text payload is not valid UTF-8", svc.Name)
			} else {
				body = append([]byte(nil), result.NewBody...)
				rewritten = true
			}
		}
	}

	flagRegex, flagScanner = m.currentFlagMatchers()
	flagged := sniffer.CheckFlagged(flagRegex, flagScanner, "", "", body)
	_, _, flagCountBody := sniffer.CountFlags(flagRegex, flagScanner, "", "", body)
	containsFlagID, matchedFlagIDs, flagIDRound := false, []string(nil), 0
	if m.shouldApplyFlagIDsOnIngest() {
		containsFlagID, matchedFlagIDs, flagIDRound = sniffer.CheckFlagID(m.currentFlagIDChecker(), "", "", body)
	}
	pyResult.Reconcile(pyFlow, body, !shouldDrop, false, flagged, containsFlagID,
		matchedFlagIDs, flagCountBody, 0, 0)

	captureEnabled := m.packetStore != nil && m.shouldCapture()
	mustPersist := captureEnabled || shouldDrop || len(alertRules) > 0 || len(pyBlockAlerts) > 0
	if m.packetStore != nil && mustPersist {
		if matchedRules == nil {
			matchedRules = []sniffer.MatchedRuleInfo{}
		}
		now := observedAt
		pkt := &sniffer.Packet{
			ServiceID:       svc.ID,
			SessionID:       meta.sessionID,
			Timestamp:       now,
			SrcIP:           srcIP,
			SrcPort:         srcPort,
			DstIP:           dstIP,
			DstPort:         dstPort,
			Protocol:        string(svc.Protocol),
			Direction:       dir,
			Method:          "WS",
			URL:             meta.url,
			Headers:         headers,
			Body:            body,
			MatchedRules:    matchedRules,
			Flagged:         flagged,
			ContainsFlagID:  containsFlagID,
			MatchedFlagIDs:  matchedFlagIDs,
			FlagIDRound:     flagIDRound,
			FlagCountBody:   flagCountBody,
			PyFilterEventID: pyEventID,
			Verdict:         sniffer.VerdictFor(dir, matchedRules, shouldDrop, rewritten, true),
		}
		alerts := make([]*sniffer.Alert, 0, len(alertRules)+len(pyBlockAlerts))
		for _, rule := range alertRules {
			alerts = append(alerts, &sniffer.Alert{
				RuleID:         rule.ID,
				ServiceID:      svc.ID,
				SrcIP:          srcIP,
				Timestamp:      now,
				PatternMatched: rule.Pattern,
			})
		}
		alerts = append(alerts, pyBlockAlerts...)
		if err := m.packetStore.Enqueue(pkt, alerts); err != nil {
			log.Printf("[%s] sniffer: failed to log WebSocket %s message: %v", svc.Name, opcodeName, err)
		}
	}

	if shouldDrop {
		log.Printf("[%s] WebSocket DROP: %d filter(s) matched %s %s message", svc.Name, len(matchedRules), dir, opcodeName)
	}
	return websocketMessageDecision{Payload: body, Drop: shouldDrop, Close: shouldClose, Rewritten: rewritten}
}

func splitWebSocketRemoteAddr(remoteAddr string) (string, int) {
	host, portText, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr, 0
	}
	port, _ := strconv.Atoi(portText)
	return host, port
}

func (m *Manager) recordOversizedWebSocketMessage(svc *storage.Service, meta websocketCaptureMeta, dir sniffer.Direction, opcode byte, size uint64) {
	opcodeName, headers := websocketMessageHeaders(opcode)
	headers["X-Janus-WebSocket-Capture"] = "truncated"
	srcIP, srcPort, dstIP, dstPort := websocketEndpoints(meta, dir)
	message := fmt.Sprintf("WebSocket %s message forwarded without filtering: %d bytes exceeds %d-byte capture limit", opcodeName, size, maxWebSocketMessageCapture)

	if m.packetStore != nil && m.shouldCapture() {
		pkt := &sniffer.Packet{
			ServiceID: svc.ID, SessionID: meta.sessionID, Timestamp: time.Now(),
			SrcIP: srcIP, SrcPort: srcPort, DstIP: dstIP, DstPort: dstPort,
			Protocol: string(svc.Protocol), Direction: dir, Method: "WS", URL: meta.url,
			Headers: headers, BodyString: message,
			MatchedRules:     []sniffer.MatchedRuleInfo{},
			CaptureTruncated: true,
			Verdict:          sniffer.VerdictFor(dir, nil, false, false, true),
		}
		if err := m.packetStore.Enqueue(pkt, nil); err != nil {
			log.Printf("[%s] sniffer: failed to log oversized WebSocket metadata: %v", svc.Name, err)
		}
	}
	log.Printf("[%s] %s", svc.Name, message)
}

type websocketFrameParser struct {
	buffer []byte

	passPayload uint64

	fragmentOpcode  byte
	fragmentPayload []byte
	fragmentWire    []byte
	fragmentBypass  bool

	maskRewrites bool
	onMessage    func(opcode byte, payload []byte) websocketMessageDecision
	onOversized  func(opcode byte, size uint64)
}

func newWebSocketFrameParser(maskRewrites bool, onMessage func(opcode byte, payload []byte) websocketMessageDecision, onOversized func(opcode byte, size uint64)) *websocketFrameParser {
	return &websocketFrameParser{
		maskRewrites: maskRewrites,
		onMessage:    onMessage,
		onOversized:  onOversized,
	}
}

// Feed accepts arbitrary TCP chunk boundaries. It parses complete RFC 6455
// frames, removes client masking, passes control frames through immediately,
// and holds data frames until a complete text/binary message has been filtered.
func (p *websocketFrameParser) Feed(data []byte) []byte {
	var output []byte
	if len(data) == 0 {
		return output
	}

	if p.passPayload > 0 {
		consumed := uint64(len(data))
		if consumed > p.passPayload {
			consumed = p.passPayload
		}
		output = append(output, data[:int(consumed)]...)
		data = data[int(consumed):]
		p.passPayload -= consumed
		if len(data) == 0 {
			return output
		}
	}

	p.buffer = append(p.buffer, data...)
	for {
		if len(p.buffer) < 2 {
			return output
		}

		first, second := p.buffer[0], p.buffer[1]
		fin := first&0x80 != 0
		opcode := first & 0x0f
		masked := second&0x80 != 0
		payloadLen := uint64(second & 0x7f)
		headerLen := 2

		switch payloadLen {
		case 126:
			if len(p.buffer) < 4 {
				return output
			}
			payloadLen = uint64(binary.BigEndian.Uint16(p.buffer[2:4]))
			headerLen = 4
		case 127:
			if len(p.buffer) < 10 {
				return output
			}
			payloadLen = binary.BigEndian.Uint64(p.buffer[2:10])
			headerLen = 10
		}

		if masked {
			headerLen += 4
		}
		if len(p.buffer) < headerLen {
			return output
		}

		if payloadLen > maxWebSocketMessageCapture {
			reportedOpcode := opcode
			reportedSize := payloadLen
			if opcode == webSocketOpcodeContinuation && p.fragmentOpcode != 0 {
				reportedOpcode = p.fragmentOpcode
				reportedSize += uint64(len(p.fragmentPayload))
			}
			if p.onOversized != nil {
				p.onOversized(reportedOpcode, reportedSize)
			}
			output = append(output, p.beginOversizedFrame(opcode, fin)...)
			output = append(output, p.buffer[:headerLen]...)
			p.buffer = p.buffer[headerLen:]
			available := uint64(len(p.buffer))
			if available > payloadLen {
				available = payloadLen
			}
			output = append(output, p.buffer[:int(available)]...)
			p.buffer = p.buffer[int(available):]
			p.passPayload = payloadLen - available
			if p.passPayload > 0 {
				return output
			}
			continue
		}

		totalLen := headerLen + int(payloadLen)
		if len(p.buffer) < totalLen {
			return output
		}

		rawFrame := append([]byte(nil), p.buffer[:totalLen]...)
		payload := append([]byte(nil), p.buffer[headerLen:totalLen]...)
		if masked {
			maskOffset := headerLen - 4
			mask := p.buffer[maskOffset:headerLen]
			for i := range payload {
				payload[i] ^= mask[i%len(mask)]
			}
		}
		p.buffer = p.buffer[totalLen:]
		output = append(output, p.handleFrame(opcode, fin, payload, rawFrame)...)
	}
}

func (p *websocketFrameParser) handleFrame(opcode byte, fin bool, payload, rawFrame []byte) []byte {
	// Control frames do not carry application content and are never filtered.
	// Forward them immediately even while a fragmented data message is pending.
	if opcode&0x08 != 0 {
		return rawFrame
	}

	switch opcode {
	case webSocketOpcodeText, webSocketOpcodeBinary:
		var output []byte
		// A new data message before the previous fragmented message completed is
		// invalid. Fail open for the incomplete bytes so the peers, not Janus,
		// decide how to handle the protocol error.
		if p.fragmentOpcode != 0 && !p.fragmentBypass {
			output = append(output, p.fragmentWire...)
		}
		p.resetFragment()
		if fin {
			return append(output, p.applyDecision(opcode, payload, rawFrame)...)
		}
		p.fragmentOpcode = opcode
		p.fragmentPayload = append(p.fragmentPayload, payload...)
		p.fragmentWire = append(p.fragmentWire, rawFrame...)
		return output

	case webSocketOpcodeContinuation:
		if p.fragmentOpcode == 0 {
			// Stray continuation is invalid but should remain transparent.
			return rawFrame
		}
		if p.fragmentBypass {
			if fin {
				p.resetFragment()
			}
			return rawFrame
		}
		if len(payload) > maxWebSocketMessageCapture-len(p.fragmentPayload) {
			total := uint64(len(p.fragmentPayload) + len(payload))
			if p.onOversized != nil {
				p.onOversized(p.fragmentOpcode, total)
			}
			opcode := p.fragmentOpcode
			output := append(append([]byte(nil), p.fragmentWire...), rawFrame...)
			p.resetFragment()
			if !fin {
				p.fragmentOpcode = opcode
				p.fragmentBypass = true
			}
			return output
		}
		p.fragmentPayload = append(p.fragmentPayload, payload...)
		p.fragmentWire = append(p.fragmentWire, rawFrame...)
		if fin {
			output := p.applyDecision(p.fragmentOpcode, p.fragmentPayload, p.fragmentWire)
			p.resetFragment()
			return output
		}
		return nil

	default:
		// Reserved/unknown data opcode: preserve it unchanged.
		return rawFrame
	}
}

func (p *websocketFrameParser) applyDecision(opcode byte, payload, originalWire []byte) []byte {
	decision := websocketMessageDecision{Payload: payload}
	if p.onMessage != nil {
		decision = p.onMessage(opcode, payload)
	}
	if decision.Drop {
		return nil
	}
	if !decision.Rewritten {
		return originalWire
	}
	return encodeWebSocketMessage(opcode, decision.Payload, p.maskRewrites)
}

// beginOversizedFrame switches the current message to transparent pass-through
// and returns any fragments that had been held while waiting for filtering.
func (p *websocketFrameParser) beginOversizedFrame(opcode byte, fin bool) []byte {
	var held []byte
	switch opcode {
	case webSocketOpcodeText, webSocketOpcodeBinary:
		if p.fragmentOpcode != 0 && !p.fragmentBypass {
			held = append(held, p.fragmentWire...)
		}
		p.resetFragment()
		if !fin {
			p.fragmentOpcode = opcode
			p.fragmentBypass = true
		}
	case webSocketOpcodeContinuation:
		if p.fragmentOpcode != 0 && !p.fragmentBypass {
			held = append(held, p.fragmentWire...)
		}
		opcode := p.fragmentOpcode
		p.resetFragment()
		if !fin && opcode != 0 {
			p.fragmentOpcode = opcode
			p.fragmentBypass = true
		}
	}
	return held
}

func (p *websocketFrameParser) resetFragment() {
	p.fragmentOpcode = 0
	p.fragmentPayload = nil
	p.fragmentWire = nil
	p.fragmentBypass = false
}

func encodeWebSocketMessage(opcode byte, payload []byte, masked bool) []byte {
	second := byte(0)
	if masked {
		second = 0x80
	}
	frame := []byte{0x80 | opcode}
	switch {
	case len(payload) < 126:
		frame = append(frame, second|byte(len(payload)))
	case uint64(len(payload)) <= 0xffff:
		frame = append(frame, second|126, 0, 0)
		binary.BigEndian.PutUint16(frame[len(frame)-2:], uint16(len(payload)))
	default:
		frame = append(frame, second|127, 0, 0, 0, 0, 0, 0, 0, 0)
		binary.BigEndian.PutUint64(frame[len(frame)-8:], uint64(len(payload)))
	}
	if !masked {
		return append(frame, payload...)
	}

	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		// crypto/rand failures are extraordinarily rare. A non-zero fallback
		// still preserves protocol correctness and avoids breaking the service.
		mask = [4]byte{0x4a, 0x61, 0x6e, 0x75}
	}
	frame = append(frame, mask[:]...)
	for i, b := range payload {
		frame = append(frame, b^mask[i%len(mask)])
	}
	return frame
}
