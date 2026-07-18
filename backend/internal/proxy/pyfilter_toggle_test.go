package proxy

import (
	"bytes"
	"testing"

	"github.com/SimoneErrigo/Janus/backend/internal/dropper"
	"github.com/SimoneErrigo/Janus/backend/internal/sniffer"
	"github.com/SimoneErrigo/Janus/backend/internal/storage"
)

func TestNativeTransportRulesRemainActiveWhenPythonPreflightIsDisabled(t *testing.T) {
	tests := []struct {
		name     string
		protocol storage.Protocol
		inspect  func(*Manager, *storage.Service, []byte) bool
	}{
		{
			name: "tcp", protocol: storage.ProtocolTCP,
			inspect: func(manager *Manager, service *storage.Service, body []byte) bool {
				forwarded, dropped := manager.inspectTransportMessage(service, "session", "192.0.2.1", 1234, "192.0.2.2", 8080, sniffer.DirectionRequest, body)
				if !bytes.Equal(forwarded, body) {
					t.Fatalf("TCP payload changed: got %q want %q", forwarded, body)
				}
				return dropped
			},
		},
		{
			name: "websocket", protocol: storage.ProtocolWS,
			inspect: func(manager *Manager, service *storage.Service, body []byte) bool {
				decision := manager.processWebSocketMessage(service, websocketCaptureMeta{
					clientIP: "192.0.2.1", clientPort: 1234, listenerIP: "192.0.2.2", listenerPort: 8080,
					sessionID: "session", url: "/socket",
				}, sniffer.DirectionRequest, webSocketOpcodeText, body)
				if !bytes.Equal(decision.Payload, body) {
					t.Fatalf("WebSocket payload changed: got %q want %q", decision.Payload, body)
				}
				return decision.Drop
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := dropper.NewRuleStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			service := &storage.Service{ID: tt.name, Name: tt.name, Protocol: tt.protocol}
			if err := rules.CreateRule(&dropper.Rule{
				ID: "native-drop", ServiceID: service.ID, Name: "native drop",
				Type: dropper.MatchString, Scope: dropper.ScopeBody, Pattern: "native-match",
				Action: dropper.ActionDrop, Enabled: true,
			}); err != nil {
				t.Fatal(err)
			}

			manager := NewManager(nil, rules, nil, nil)
			pythonCalls := 0
			manager.SetPyBlockFn(func(map[string]any) sniffer.PyResult {
				pythonCalls++
				return sniffer.PyResult{}
			})
			manager.SetPyShouldEvaluateFn(func(_, _, _ string) bool { return false })

			if dropped := tt.inspect(manager, service, []byte("native-match")); !dropped {
				t.Fatal("native Go drop rule did not run")
			}
			if pythonCalls != 0 {
				t.Fatalf("Python evaluator called %d time(s) despite disabled preflight", pythonCalls)
			}
		})
	}
}
