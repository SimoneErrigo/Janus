package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"

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
func (m *Manager) configureWebSocketReverseProxy(reverseProxy *httputil.ReverseProxy, svc *storage.Service) {
	if svc.Protocol != storage.ProtocolWS && svc.Protocol != storage.ProtocolWSS {
		return
	}

	// Compression makes frame payloads opaque. Remove only permessage-deflate
	// from the client's offer (preserving unrelated extensions), so the backend
	// cannot negotiate compressed messages and Janus can always show text in
	// clear. The browser simply falls back to normal uncompressed frames.
	director := reverseProxy.Director
	reverseProxy.Director = func(r *http.Request) {
		director(r)
		removeWebSocketExtension(r.Header, "permessage-deflate")
	}

	previousModifyResponse := reverseProxy.ModifyResponse
	reverseProxy.ModifyResponse = func(resp *http.Response) error {
		if previousModifyResponse != nil {
			if err := previousModifyResponse(resp); err != nil {
				return err
			}
		}
		if resp.StatusCode != http.StatusSwitchingProtocols ||
			!strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") ||
			m.packetStore == nil {
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
		meta.sessionID = sniffer.MakeSessionID(svc.ID, meta.clientIP, meta.clientPort)

		resp.Body = &websocketCaptureConn{
			ReadWriteCloser: backendConn,
			toBackend: newWebSocketFrameParser(func(opcode byte, payload []byte) {
				m.captureWebSocketMessage(svc, meta, sniffer.DirectionRequest, opcode, payload)
			}),
			fromBackend: newWebSocketFrameParser(func(opcode byte, payload []byte) {
				m.captureWebSocketMessage(svc, meta, sniffer.DirectionResponse, opcode, payload)
			}),
		}
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

// websocketCaptureConn observes the two halves of the upgraded connection.
// ReverseProxy writes client frames to the backend and reads server frames
// from it, so the two parsers naturally correspond to request/response.
type websocketCaptureConn struct {
	io.ReadWriteCloser
	toBackend   *websocketFrameParser
	fromBackend *websocketFrameParser
}

func (c *websocketCaptureConn) Read(p []byte) (int, error) {
	n, err := c.ReadWriteCloser.Read(p)
	if n > 0 {
		c.fromBackend.Feed(p[:n])
	}
	return n, err
}

func (c *websocketCaptureConn) Write(p []byte) (int, error) {
	n, err := c.ReadWriteCloser.Write(p)
	if n > 0 {
		c.toBackend.Feed(p[:n])
	}
	return n, err
}

func (m *Manager) captureWebSocketMessage(svc *storage.Service, meta websocketCaptureMeta, dir sniffer.Direction, opcode byte, payload []byte) {
	if m.packetStore == nil || !m.shouldCapture() {
		return
	}

	body := append([]byte(nil), payload...)
	opcodeName := "binary"
	headers := map[string]string{"X-Janus-WebSocket-Opcode": opcodeName}
	if opcode == webSocketOpcodeText {
		opcodeName = "text"
		headers["X-Janus-WebSocket-Opcode"] = opcodeName
		headers["Content-Type"] = "text/plain; charset=utf-8"
	}

	srcIP, srcPort := meta.clientIP, meta.clientPort
	dstIP, dstPort := meta.listenerIP, meta.listenerPort
	if dir == sniffer.DirectionResponse {
		srcIP, srcPort, dstIP, dstPort = dstIP, dstPort, srcIP, srcPort
	}

	flagged := sniffer.CheckFlagged(m.flagRegex, m.flagScanner, "", "", body)
	containsFlagID, matchedFlagIDs, flagIDRound := false, []string(nil), 0
	if m.shouldApplyFlagIDsOnIngest() {
		containsFlagID, matchedFlagIDs, flagIDRound = sniffer.CheckFlagID(m.currentFlagIDChecker(), "", "", body)
	}

	pkt := &sniffer.Packet{
		ServiceID:      svc.ID,
		SessionID:      meta.sessionID,
		Timestamp:      time.Now(),
		SrcIP:          srcIP,
		SrcPort:        srcPort,
		DstIP:          dstIP,
		DstPort:        dstPort,
		Protocol:       string(svc.Protocol),
		Direction:      dir,
		Method:         "WS",
		URL:            meta.url,
		Headers:        headers,
		Body:           body,
		MatchedRules:   []sniffer.MatchedRuleInfo{},
		Flagged:        flagged,
		ContainsFlagID: containsFlagID,
		MatchedFlagIDs: matchedFlagIDs,
		FlagIDRound:    flagIDRound,
	}
	if err := m.packetStore.Enqueue(pkt, nil); err != nil {
		log.Printf("[%s] sniffer: failed to log WebSocket %s message: %v", svc.Name, opcodeName, err)
	}
}

func splitWebSocketRemoteAddr(remoteAddr string) (string, int) {
	host, portText, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr, 0
	}
	port, _ := strconv.Atoi(portText)
	return host, port
}

func removeWebSocketExtension(header http.Header, extensionName string) {
	values := header.Values("Sec-WebSocket-Extensions")
	if len(values) == 0 {
		return
	}

	kept := make([]string, 0, len(values))
	for _, value := range values {
		for _, extension := range strings.Split(value, ",") {
			extension = strings.TrimSpace(extension)
			if extension == "" {
				continue
			}
			name := extension
			if semicolon := strings.IndexByte(name, ';'); semicolon >= 0 {
				name = strings.TrimSpace(name[:semicolon])
			}
			if !strings.EqualFold(name, extensionName) {
				kept = append(kept, extension)
			}
		}
	}

	header.Del("Sec-WebSocket-Extensions")
	if len(kept) > 0 {
		header.Set("Sec-WebSocket-Extensions", strings.Join(kept, ", "))
	}
}

type websocketFrameParser struct {
	buffer []byte

	skipPayload uint64

	fragmentOpcode  byte
	fragment        []byte
	fragmentDropped bool

	onMessage func(opcode byte, payload []byte)
}

func newWebSocketFrameParser(onMessage func(opcode byte, payload []byte)) *websocketFrameParser {
	return &websocketFrameParser{onMessage: onMessage}
}

// Feed accepts arbitrary TCP chunk boundaries. It parses complete RFC 6455
// frames, removes client masking, ignores control frames, and reassembles
// fragmented text/binary messages before emitting them.
func (p *websocketFrameParser) Feed(data []byte) {
	if len(data) == 0 {
		return
	}

	if p.skipPayload > 0 {
		consumed := uint64(len(data))
		if consumed > p.skipPayload {
			consumed = p.skipPayload
		}
		data = data[int(consumed):]
		p.skipPayload -= consumed
		if len(data) == 0 {
			return
		}
	}

	p.buffer = append(p.buffer, data...)
	for {
		if p.skipPayload > 0 {
			consumed := uint64(len(p.buffer))
			if consumed > p.skipPayload {
				consumed = p.skipPayload
			}
			p.buffer = p.buffer[int(consumed):]
			p.skipPayload -= consumed
			if p.skipPayload > 0 || len(p.buffer) == 0 {
				return
			}
		}

		if len(p.buffer) < 2 {
			return
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
				return
			}
			payloadLen = uint64(binary.BigEndian.Uint16(p.buffer[2:4]))
			headerLen = 4
		case 127:
			if len(p.buffer) < 10 {
				return
			}
			payloadLen = binary.BigEndian.Uint64(p.buffer[2:10])
			headerLen = 10
		}

		if masked {
			headerLen += 4
		}
		if len(p.buffer) < headerLen {
			return
		}

		if payloadLen > maxWebSocketMessageCapture {
			p.handleDroppedFrame(opcode, fin)
			p.buffer = p.buffer[headerLen:]
			available := uint64(len(p.buffer))
			if available > payloadLen {
				available = payloadLen
			}
			p.buffer = p.buffer[int(available):]
			p.skipPayload = payloadLen - available
			continue
		}

		totalLen := headerLen + int(payloadLen)
		if len(p.buffer) < totalLen {
			return
		}

		payload := append([]byte(nil), p.buffer[headerLen:totalLen]...)
		if masked {
			maskOffset := headerLen - 4
			mask := p.buffer[maskOffset:headerLen]
			for i := range payload {
				payload[i] ^= mask[i%len(mask)]
			}
		}
		p.buffer = p.buffer[totalLen:]
		p.handleFrame(opcode, fin, payload)
	}
}

func (p *websocketFrameParser) handleFrame(opcode byte, fin bool, payload []byte) {
	switch opcode {
	case webSocketOpcodeText, webSocketOpcodeBinary:
		p.resetFragment()
		if fin {
			p.emit(opcode, payload)
			return
		}
		p.fragmentOpcode = opcode
		p.appendFragment(payload)

	case webSocketOpcodeContinuation:
		if p.fragmentOpcode == 0 {
			return
		}
		p.appendFragment(payload)
		if fin {
			if !p.fragmentDropped {
				p.emit(p.fragmentOpcode, p.fragment)
			}
			p.resetFragment()
		}

	default:
		// Close, ping and pong are transport control frames, not application
		// messages. They may be interleaved with a fragmented message.
	}
}

func (p *websocketFrameParser) appendFragment(payload []byte) {
	if p.fragmentDropped {
		return
	}
	if len(payload) > maxWebSocketMessageCapture-len(p.fragment) {
		p.fragment = nil
		p.fragmentDropped = true
		return
	}
	p.fragment = append(p.fragment, payload...)
}

func (p *websocketFrameParser) handleDroppedFrame(opcode byte, fin bool) {
	switch opcode {
	case webSocketOpcodeText, webSocketOpcodeBinary:
		p.resetFragment()
		if !fin {
			p.fragmentOpcode = opcode
			p.fragmentDropped = true
		}
	case webSocketOpcodeContinuation:
		if fin {
			p.resetFragment()
		} else if p.fragmentOpcode != 0 {
			p.fragment = nil
			p.fragmentDropped = true
		}
	}
}

func (p *websocketFrameParser) resetFragment() {
	p.fragmentOpcode = 0
	p.fragment = nil
	p.fragmentDropped = false
}

func (p *websocketFrameParser) emit(opcode byte, payload []byte) {
	if p.onMessage != nil {
		p.onMessage(opcode, payload)
	}
}
