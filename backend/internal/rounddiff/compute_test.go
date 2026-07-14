package rounddiff

import (
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/SimoneErrigo/Janus/backend/internal/sniffer"
)

// pkt is a small builder for test packets.
func pkt(id int64, dir sniffer.Direction, method, url string, status int, body string) *sniffer.Packet {
	return &sniffer.Packet{
		ID:         id,
		ServiceID:  "svc",
		Protocol:   "HTTP",
		Direction:  dir,
		Method:     method,
		URL:        url,
		Status:     status,
		BodyString: body,
		Timestamp:  time.Unix(1700000000+id, 0),
	}
}

// fixtureRounds returns a deterministic baseline (A) and analyzed (B) set that
// exercises: identical packets (must be skipped), a changed body, and a
// brand-new route carrying an attack payload.
func fixtureRounds() (a, b []*sniffer.Packet) {
	a = []*sniffer.Packet{
		pkt(1, sniffer.DirectionRequest, "POST", "/login", 0, `{"user":"alice","pass":"x"}`),
		pkt(2, sniffer.DirectionRequest, "POST", "/search", 0, `{"q":"hello"}`),
		pkt(3, sniffer.DirectionResponse, "", "", 200, "OK"),
	}
	b = []*sniffer.Packet{
		pkt(11, sniffer.DirectionRequest, "POST", "/login", 0, `{"user":"alice","pass":"x"}`), // identical -> skip
		pkt(12, sniffer.DirectionRequest, "POST", "/search", 0, `{"q":"' OR 1=1 --"}`),        // changed body + sqli
		pkt(13, sniffer.DirectionRequest, "POST", "/admin", 0, `{"cmd":"whoami"}`),            // new route
		pkt(14, sniffer.DirectionResponse, "", "", 200, "OK"),                                 // identical -> skip
	}
	return a, b
}

// TestComputeParity locks in the observable result so the two-phase refactor
// stays behavior-preserving. Values captured from the pre-refactor implementation.
func TestComputeParity(t *testing.T) {
	a, b := fixtureRounds()
	res := Compute(1, 2, a, b, Options{TopK: 24, IncludeDiff: true})

	if got := len(res.NovelPackets); got != 2 {
		t.Fatalf("want 2 novel packets, got %d: %+v", got, res.NovelPackets)
	}

	// Ordering by score desc: #13 (new route, score 1.0) then #12 (changed body).
	type want struct {
		id     int64
		route  string
		score  float64
		scope  string
		fields []string
		twin   int64
	}
	wants := []want{
		{13, "POST /admin", 1.0, "body", []string{"url", "body"}, 2},
		{12, "POST /search", 0.3529, "body", []string{"body"}, 2},
	}
	for i, w := range wants {
		np := res.NovelPackets[i]
		if np.PacketID != w.id {
			t.Errorf("novel[%d] id = %d, want %d", i, np.PacketID, w.id)
		}
		if np.RouteKey != w.route {
			t.Errorf("novel[%d] route = %q, want %q", i, np.RouteKey, w.route)
		}
		if math.Abs(np.Score-w.score) > 0.001 {
			t.Errorf("novel[%d] score = %.4f, want %.4f", i, np.Score, w.score)
		}
		if np.Scope != w.scope {
			t.Errorf("novel[%d] scope = %q, want %q", i, np.Scope, w.scope)
		}
		if fmt.Sprint(np.ChangeFields) != fmt.Sprint(w.fields) {
			t.Errorf("novel[%d] fields = %v, want %v", i, np.ChangeFields, w.fields)
		}
		if np.TwinPacketID != w.twin {
			t.Errorf("novel[%d] twin = %d, want %d", i, np.TwinPacketID, w.twin)
		}
		// IncludeDiff: body diff must be attached.
		if len(np.FieldDiffs) == 0 || len(np.Diff) == 0 {
			t.Errorf("novel[%d] expected field diffs + body diff, got fieldDiffs=%d diff=%d", i, len(np.FieldDiffs), len(np.Diff))
		}
	}

	// Suspicious buckets.
	if len(res.Suspicious) != 1 {
		t.Fatalf("want 1 suspicious bucket, got %d: %+v", len(res.Suspicious), res.Suspicious)
	}
	if res.Suspicious[0].Key != "body:sqli-syntax" || res.Suspicious[0].Count != 1 {
		t.Errorf("suspicious bucket = %q x%d, want body:sqli-syntax x1", res.Suspicious[0].Key, res.Suspicious[0].Count)
	}

	// Route deltas.
	if len(res.NewRoutes) != 1 || res.NewRoutes[0].Key != "POST /admin" {
		t.Errorf("new routes = %+v, want [POST /admin]", res.NewRoutes)
	}
	if len(res.GoneRoutes) != 0 || len(res.ChangedRoutes) != 0 {
		t.Errorf("gone=%d changed=%d, want 0/0", len(res.GoneRoutes), len(res.ChangedRoutes))
	}

	// Stats.
	if res.StatsA.Total != 3 || res.StatsB.Total != 4 {
		t.Errorf("stats totals: A=%d B=%d, want 3/4", res.StatsA.Total, res.StatsB.Total)
	}
}

// genChattyRound builds a large, mostly-repetitive packet set: `routes` distinct
// endpoints, `perRoute` packets each. Most packets repeat verbatim across rounds
// (the A/D checker pattern); a few in B carry a changed body.
func genChattyRound(routes, perRoute int, seed int64, mutate bool) []*sniffer.Packet {
	out := make([]*sniffer.Packet, 0, routes*perRoute)
	var id int64 = seed
	for r := 0; r < routes; r++ {
		url := fmt.Sprintf("/api/resource/%d", r)
		for i := 0; i < perRoute; i++ {
			id++
			body := fmt.Sprintf(`{"action":"read","resource":%d,"token":"abc123def456"}`, r)
			if mutate && i == 0 && r%5 == 0 {
				body = fmt.Sprintf(`{"action":"read","resource":%d,"token":"%d-changed-payload"}`, r, id)
			}
			out = append(out, pkt(id, sniffer.DirectionRequest, "POST", url, 0, body))
		}
	}
	return out
}

func BenchmarkCompute(b *testing.B) {
	a := genChattyRound(40, 50, 0, false)      // 2000 packets
	bb := genChattyRound(40, 50, 100000, true) // 2000 packets, some mutated
	opts := Options{TopK: 24, IncludeDiff: true}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Compute(1, 2, a, bb, opts)
	}
}
