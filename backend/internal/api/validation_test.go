package api

import (
	"strings"
	"testing"

	"github.com/SimoneErrigo/Janus/backend/internal/storage"
)

func TestValidateServiceWebSocketProtocols(t *testing.T) {
	base := storage.Service{
		ID:         "websocket-service",
		Name:       "WebSocket service",
		ListenAddr: "127.0.0.1",
		ListenPort: 8080,
		TargetAddr: "127.0.0.1:9080",
		Enabled:    true,
	}

	t.Run("ws", func(t *testing.T) {
		svc := base
		svc.Protocol = storage.ProtocolWS
		if err := validateService(&svc); err != nil {
			t.Fatalf("validateService(ws): %v", err)
		}
	})

	t.Run("wss", func(t *testing.T) {
		svc := base
		svc.Protocol = storage.ProtocolWSS
		svc.TLSMode = storage.TLSModeSelfSigned
		if err := validateService(&svc); err != nil {
			t.Fatalf("validateService(wss): %v", err)
		}
	})

	t.Run("wss requires listener TLS", func(t *testing.T) {
		svc := base
		svc.Protocol = storage.ProtocolWSS
		err := validateService(&svc)
		if err == nil || !strings.Contains(err.Error(), "tls_mode") {
			t.Fatalf("validateService(wss without TLS) error = %v, want tls_mode error", err)
		}
	})
}
