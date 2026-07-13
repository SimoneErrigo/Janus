package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/SimoneErrigo/Janus/backend/internal/sniffer"
	"github.com/SimoneErrigo/Janus/backend/internal/storage"
)

func TestWebSocketProtocolsProxyFrames(t *testing.T) {
	tests := []struct {
		name       string
		protocol   storage.Protocol
		clientTLS  bool
		backendTLS bool
	}{
		{name: "ws to ws", protocol: storage.ProtocolWS},
		{name: "ws to wss", protocol: storage.ProtocolWS, backendTLS: true},
		{name: "wss to ws", protocol: storage.ProtocolWSS, clientTLS: true},
		{name: "wss to wss", protocol: storage.ProtocolWSS, clientTLS: true, backendTLS: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := newWebSocketEchoServer(t, tt.backendTLS)
			defer backend.Close()
			packetStore, err := sniffer.NewPacketStore(t.TempDir())
			if err != nil {
				t.Fatalf("NewPacketStore: %v", err)
			}
			defer packetStore.Close()

			port := freeTCPPort(t)
			svc := &storage.Service{
				ID:         strings.ReplaceAll(tt.name, " ", "-"),
				Name:       tt.name,
				ListenAddr: "127.0.0.1",
				ListenPort: port,
				TargetAddr: strings.TrimPrefix(strings.TrimPrefix(backend.URL, "http://"), "https://"),
				Protocol:   tt.protocol,
				TargetTLS:  tt.backendTLS,
				Enabled:    true,
			}
			if tt.clientTLS {
				svc.TLSMode = storage.TLSModeSelfSigned
			}

			manager := NewManager(packetStore, nil, nil, nil)
			if err := manager.StartService(svc); err != nil {
				t.Fatalf("StartService: %v", err)
			}
			defer manager.StopService(svc.ID)
			if status, ok := manager.Status(svc.ID); !ok || !status.Running {
				t.Fatalf("proxy status = %+v, registered=%v", status, ok)
			}

			conn := dialWebSocketProxy(t, fmt.Sprintf("127.0.0.1:%d", port), tt.clientTLS)
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}

			assertWebSocketEcho(t, conn, "/socket", "janus-websocket")
			messages := waitForWebSocketMessages(t, packetStore, svc.ID, 2)
			if messages[0].Direction != sniffer.DirectionRequest || messages[1].Direction != sniffer.DirectionResponse {
				t.Fatalf("message directions = [%s, %s], want [request, response]", messages[0].Direction, messages[1].Direction)
			}
			for _, message := range messages {
				if message.BodyString != "janus-websocket" {
					t.Errorf("captured %s body = %q, want clear websocket payload", message.Direction, message.BodyString)
				}
				if message.Headers["X-Janus-WebSocket-Opcode"] != "text" {
					t.Errorf("captured %s opcode = %q, want text", message.Direction, message.Headers["X-Janus-WebSocket-Opcode"])
				}
				if message.URL != "/socket" {
					t.Errorf("captured %s URL = %q, want /socket", message.Direction, message.URL)
				}
			}
			if messages[0].SessionID == "" || messages[0].SessionID != messages[1].SessionID {
				t.Errorf("captured session IDs = [%q, %q], want the same non-empty session", messages[0].SessionID, messages[1].SessionID)
			}
		})
	}
}

func TestWebSocketFrameParserUnmasksAndReassembles(t *testing.T) {
	type capturedMessage struct {
		opcode  byte
		payload []byte
	}
	var captured []capturedMessage
	parser := newWebSocketFrameParser(func(opcode byte, payload []byte) {
		captured = append(captured, capturedMessage{opcode: opcode, payload: append([]byte(nil), payload...)})
	})

	wire := append([]byte{}, testWebSocketFrame(false, webSocketOpcodeText, true, []byte("hello "))...)
	wire = append(wire, testWebSocketFrame(true, 0x9, true, []byte("ping"))...)
	wire = append(wire, testWebSocketFrame(true, webSocketOpcodeContinuation, true, []byte("world"))...)
	binaryPayload := bytes.Repeat([]byte{0xa5}, 130) // exercises the 16-bit extended length
	wire = append(wire, testWebSocketFrame(true, webSocketOpcodeBinary, false, binaryPayload)...)

	// Deliberately split at every byte to prove TCP chunk boundaries do not
	// need to line up with WebSocket frame boundaries.
	for _, b := range wire {
		parser.Feed([]byte{b})
	}

	if len(captured) != 2 {
		t.Fatalf("captured %d messages, want 2", len(captured))
	}
	if captured[0].opcode != webSocketOpcodeText || string(captured[0].payload) != "hello world" {
		t.Errorf("fragmented text = opcode %d payload %q, want text/hello world", captured[0].opcode, captured[0].payload)
	}
	if captured[1].opcode != webSocketOpcodeBinary || !bytes.Equal(captured[1].payload, binaryPayload) {
		t.Errorf("extended binary message was not reconstructed correctly")
	}
}

func TestWebSocketServerDisablesHTTPDeadlines(t *testing.T) {
	for _, protocol := range []storage.Protocol{storage.ProtocolWS, storage.ProtocolWSS} {
		server := newProxyHTTPServer(http.NotFoundHandler(), protocol)
		if server.ReadTimeout != 0 || server.WriteTimeout != 0 {
			t.Errorf("%s timeouts = read %s, write %s; want both disabled", protocol, server.ReadTimeout, server.WriteTimeout)
		}
	}

	server := newProxyHTTPServer(http.NotFoundHandler(), storage.ProtocolHTTP)
	if server.ReadTimeout == 0 || server.WriteTimeout == 0 {
		t.Error("regular HTTP proxy should retain defensive read/write timeouts")
	}
}

func TestWSSAdvertisesHTTP1Only(t *testing.T) {
	cfg, err := buildTLSConfig(&storage.Service{
		Protocol:   storage.ProtocolWSS,
		TLSMode:    storage.TLSModeSelfSigned,
		ListenAddr: "127.0.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != "http/1.1" {
		t.Fatalf("WSS ALPN protocols = %v, want [http/1.1]", cfg.NextProtos)
	}
}

func newWebSocketEchoServer(t *testing.T, useTLS bool) *httptest.Server {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "expected websocket upgrade", http.StatusBadRequest)
			return
		}
		if got := r.Header.Get("Sec-WebSocket-Extensions"); got != "x-janus-test" {
			t.Errorf("backend Sec-WebSocket-Extensions = %q, want only preserved x-janus-test", got)
			return
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Error("backend response writer does not support hijacking")
			return
		}
		conn, rw, err := hijacker.Hijack()
		if err != nil {
			t.Errorf("backend hijack: %v", err)
			return
		}
		defer conn.Close()
		if _, err := rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"); err != nil {
			t.Errorf("backend upgrade response: %v", err)
			return
		}
		if err := rw.Flush(); err != nil {
			t.Errorf("backend upgrade flush: %v", err)
			return
		}

		payload, err := readMaskedTextFrame(rw)
		if err != nil {
			t.Errorf("backend read frame: %v", err)
			return
		}
		if len(payload) > 125 {
			t.Errorf("test payload too large: %d", len(payload))
			return
		}
		frame := append([]byte{0x81, byte(len(payload))}, payload...)
		if _, err := conn.Write(frame); err != nil {
			t.Errorf("backend write frame: %v", err)
		}
	})

	if useTLS {
		return httptest.NewTLSServer(handler)
	}
	return httptest.NewServer(handler)
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func dialWebSocketProxy(t *testing.T, addr string, useTLS bool) net.Conn {
	t.Helper()
	if useTLS {
		conn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: 5 * time.Second},
			"tcp",
			addr,
			&tls.Config{InsecureSkipVerify: true},
		)
		if err != nil {
			t.Fatalf("TLS dial proxy: %v", err)
		}
		return conn
	}
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	return conn
}

func assertWebSocketEcho(t *testing.T, conn net.Conn, path, message string) {
	t.Helper()
	if _, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: challenge.local\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Extensions: permessage-deflate; client_max_window_bits, x-janus-test\r\n\r\n", path); err != nil {
		t.Fatalf("write upgrade request: %v", err)
	}

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read upgrade status: %v", err)
	}
	if !strings.Contains(statusLine, " 101 ") {
		t.Fatalf("upgrade status = %q, want 101", strings.TrimSpace(statusLine))
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read upgrade headers: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}

	if _, err := conn.Write(maskedTextFrame([]byte(message))); err != nil {
		t.Fatalf("write websocket frame: %v", err)
	}
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		t.Fatalf("read websocket frame header: %v", err)
	}
	if header[0] != 0x81 || header[1]&0x80 != 0 {
		t.Fatalf("response frame header = %x, want final unmasked text frame", header)
	}
	payload := make([]byte, int(header[1]&0x7f))
	if _, err := io.ReadFull(reader, payload); err != nil {
		t.Fatalf("read websocket frame payload: %v", err)
	}
	if string(payload) != message {
		t.Fatalf("echo payload = %q, want %q", payload, message)
	}
}

func maskedTextFrame(payload []byte) []byte {
	return testWebSocketFrame(true, webSocketOpcodeText, true, payload)
}

func testWebSocketFrame(fin bool, opcode byte, masked bool, payload []byte) []byte {
	first := opcode
	if fin {
		first |= 0x80
	}
	second := byte(0)
	if masked {
		second = 0x80
	}

	frame := []byte{first}
	switch {
	case len(payload) < 126:
		frame = append(frame, second|byte(len(payload)))
	case len(payload) <= 0xffff:
		frame = append(frame, second|126, 0, 0)
		binary.BigEndian.PutUint16(frame[len(frame)-2:], uint16(len(payload)))
	default:
		frame = append(frame, second|127, 0, 0, 0, 0, 0, 0, 0, 0)
		binary.BigEndian.PutUint64(frame[len(frame)-8:], uint64(len(payload)))
	}

	if !masked {
		return append(frame, payload...)
	}
	mask := [4]byte{0x12, 0x34, 0x56, 0x78}
	frame = append(frame, mask[:]...)
	for i, b := range payload {
		frame = append(frame, b^mask[i%len(mask)])
	}
	return frame
}

func waitForWebSocketMessages(t *testing.T, store *sniffer.PacketStore, serviceID string, want int) []*sniffer.Packet {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		packets, _, err := store.Query(sniffer.PacketQuery{
			ServiceID: serviceID,
			Method:    "WS",
			SortOrder: "asc",
			Limit:     20,
		})
		if err != nil {
			t.Fatalf("query websocket messages: %v", err)
		}
		if len(packets) >= want {
			return packets[:want]
		}
		if time.Now().After(deadline) {
			t.Fatalf("captured %d websocket messages, want %d", len(packets), want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func readMaskedTextFrame(reader io.Reader) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	if header[0] != 0x81 || header[1]&0x80 == 0 {
		return nil, fmt.Errorf("unexpected frame header %x", header)
	}
	length := int(header[1] & 0x7f)
	if length > 125 {
		return nil, fmt.Errorf("extended payload length is not supported in this test")
	}
	mask := make([]byte, 4)
	if _, err := io.ReadFull(reader, mask); err != nil {
		return nil, err
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, err
	}
	for i := range payload {
		payload[i] ^= mask[i%len(mask)]
	}
	return payload, nil
}
