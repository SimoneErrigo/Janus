package sniffer

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/SimoneErrigo/Janus/backend/internal/storage"
)

func TestHTTPMiddlewarePreservesWebSocketHijacking(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Error("capture response writer does not expose http.Hijacker")
			http.Error(w, "hijacking unavailable", http.StatusInternalServerError)
			return
		}
		conn, rw, err := hijacker.Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer conn.Close()
		if _, err := rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"); err != nil {
			t.Errorf("write upgrade response: %v", err)
			return
		}
		if err := rw.Flush(); err != nil {
			t.Errorf("flush upgrade response: %v", err)
			return
		}
		payload := make([]byte, 5)
		if _, err := io.ReadFull(rw, payload); err != nil {
			t.Errorf("read tunneled bytes: %v", err)
			return
		}
		if _, err := conn.Write(payload); err != nil {
			t.Errorf("echo tunneled bytes: %v", err)
		}
	})

	svc := &storage.Service{ID: "ws", Name: "WebSocket", Protocol: storage.ProtocolWS, ListenAddr: "127.0.0.1", ListenPort: 8080}
	handler := HTTPMiddleware(
		next,
		svc,
		nil,
		nil,
		nil,
		nil,
		func() FlagIDChecker { return nil },
		func() bool { return false },
		func() bool { return false },
		nil,
		nil,
	)
	server := httptest.NewServer(handler)
	defer server.Close()

	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprint(conn, "GET /socket HTTP/1.1\r\nHost: test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"); err != nil {
		t.Fatal(err)
	}

	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, " 101 ") {
		t.Fatalf("status = %q, want 101", strings.TrimSpace(status))
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}

	want := []byte("hello")
	if _, err := conn.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(reader, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("tunneled payload = %q, want %q", got, want)
	}
}
