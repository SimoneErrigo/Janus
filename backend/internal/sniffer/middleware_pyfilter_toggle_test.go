package sniffer

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SimoneErrigo/Janus/backend/internal/dropper"
	"github.com/SimoneErrigo/Janus/backend/internal/storage"
)

type recordingPacketSink struct {
	packets []*Packet
	alerts  [][]*Alert
}

func (s *recordingPacketSink) Enqueue(packet *Packet, alerts []*Alert) error {
	copyPacket := *packet
	s.packets = append(s.packets, &copyPacket)
	s.alerts = append(s.alerts, append([]*Alert(nil), alerts...))
	return nil
}

func TestHTTPNativeRulesRemainActiveWhenPythonPreflightIsDisabled(t *testing.T) {
	for _, action := range []dropper.Action{dropper.ActionDrop, dropper.ActionAlert} {
		t.Run(string(action), func(t *testing.T) {
			rules, err := dropper.NewRuleStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if err := rules.CreateRule(&dropper.Rule{
				ID: "native-" + string(action), ServiceID: "svc", Name: "native rule",
				Type: dropper.MatchString, Scope: dropper.ScopeBody, Pattern: "native-match",
				Action: action, Enabled: true,
			}); err != nil {
				t.Fatal(err)
			}

			sink := &recordingPacketSink{}
			pythonCalls := 0
			nextCalled := false
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusNoContent)
			})
			svc := &storage.Service{ID: "svc", Name: "service", Protocol: storage.ProtocolHTTP, ListenAddr: "127.0.0.1", ListenPort: 8080}
			handler := HTTPMiddleware(
				next, svc, sink, dropper.NewEngine(rules), nil, nil,
				func() FlagIDChecker { return nil },
				func() bool { return false },
				func() bool { return false },
				func(map[string]any) PyResult {
					pythonCalls++
					return PyResult{}
				},
				func(_, _, _ string) bool { return false },
			)

			req := httptest.NewRequest(http.MethodPost, "http://janus.local/test", strings.NewReader("native-match"))
			resp := httptest.NewRecorder()
			handler.ServeHTTP(resp, req)

			if pythonCalls != 0 {
				t.Fatalf("Python evaluator called %d time(s) despite disabled preflight", pythonCalls)
			}
			wantNext := action == dropper.ActionAlert
			if nextCalled != wantNext {
				t.Fatalf("backend called=%t, want %t for native %s rule", nextCalled, wantNext, action)
			}
			if action == dropper.ActionDrop && resp.Code != http.StatusForbidden {
				t.Fatalf("native drop status=%d, want %d", resp.Code, http.StatusForbidden)
			}
			if len(sink.packets) != 1 {
				t.Fatalf("persisted packets=%d, want 1", len(sink.packets))
			}
			packet := sink.packets[0]
			if len(packet.MatchedRules) != 1 || packet.MatchedRules[0].ID != "native-"+string(action) {
				t.Fatalf("native matched rules=%+v", packet.MatchedRules)
			}
			if packet.PyFilterEventID != "" {
				t.Fatalf("disabled Python path allocated event id %q", packet.PyFilterEventID)
			}
			if action == dropper.ActionAlert && len(sink.alerts[0]) != 1 {
				t.Fatalf("native alert templates=%d, want 1", len(sink.alerts[0]))
			}
		})
	}
}
