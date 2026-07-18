package scoring

import (
	"testing"
	"time"

	flowmodel "github.com/SimoneErrigo/Janus/backend/internal/flow"
	"github.com/SimoneErrigo/Janus/backend/internal/rounddiff"
	"github.com/SimoneErrigo/Janus/backend/internal/sniffer"
)

func TestPacketSuspicionTagsIgnoresNegotiationHeaders(t *testing.T) {
	packet := &sniffer.Packet{
		Direction: sniffer.DirectionRequest,
		Headers: map[string]string{
			"Accept-Encoding": "gzip, /* */ br, UNION SELECT secret FROM flags",
			"Accept":          "text/html, /* */ application/json",
		},
	}
	if tags := packetSuspicionTags(packet); len(tags) != 0 {
		t.Fatalf("negotiation headers produced suspicion tags: %v", tags)
	}
}

func TestPacketSuspicionTagsStillInspectsApplicationInput(t *testing.T) {
	tests := []struct {
		name   string
		packet *sniffer.Packet
	}{
		{name: "body", packet: &sniffer.Packet{BodyString: `name=' OR 1=1 -- `}},
		{name: "url", packet: &sniffer.Packet{URL: `/search?q=../../etc/passwd`}},
		{name: "cookie", packet: &sniffer.Packet{Headers: map[string]string{"Cookie": `id=' OR 1=1 -- `}}},
		{name: "custom header", packet: &sniffer.Packet{Headers: map[string]string{"X-Query": `UNION SELECT secret FROM flags`}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if tags := packetSuspicionTags(test.packet); len(tags) == 0 {
				t.Fatal("application input was not tagged")
			}
		})
	}
}

func TestBaselineSafeIgnoresResponseSourcePatterns(t *testing.T) {
	packets := []*sniffer.Packet{
		{Direction: sniffer.DirectionRequest, URL: "/docs"},
		{Direction: sniffer.DirectionResponse, BodyString: `<script>renderExample()</script>`},
	}
	if !baselineSafe(packets) {
		t.Fatal("response source code should not contaminate the opening baseline")
	}
}

func TestSuspicionPointsTreatsGenericSyntaxAsWeakEvidence(t *testing.T) {
	weak := suspicionPoints(map[rounddiff.SuspicionTag]struct{}{rounddiff.TagSQLiSyntax: {}})
	strong := suspicionPoints(map[rounddiff.SuspicionTag]struct{}{rounddiff.TagCMDi: {}})
	if weak >= strong {
		t.Fatalf("generic syntax points %d must be lower than concrete exploit points %d", weak, strong)
	}
}

func TestScoreRequiresCorroboratedAttackEvidence(t *testing.T) {
	engine := testScoreEngine()
	packet := &sniffer.Packet{
		ServiceID: "svc", Direction: sniffer.DirectionRequest, Round: 6,
		URL: "/run?cmd=$(whoami)",
	}
	score := engine.score([]*sniffer.Packet{packet}, "novel")
	if score.Classification == "likely_exploit" {
		t.Fatalf("isolated pattern classified as exploit: %+v", score)
	}

	packet.Verdict = flowmodel.Verdict{Outcome: flowmodel.OutcomeWouldDrop}
	score = engine.score([]*sniffer.Packet{packet}, "novel")
	if score.Classification != "likely_exploit" {
		t.Fatalf("corroborated block-rule pattern classified as %q: %+v", score.Classification, score)
	}
}

func TestSubmitSkipsCopiesWhenScoringIsDisabled(t *testing.T) {
	engine := &Engine{in: make(chan *sniffer.Packet, 1)}
	packet := &sniffer.Packet{
		ID: 1, Body: []byte("body"),
		MatchedRules:   []sniffer.MatchedRuleInfo{{ID: "rule"}},
		MatchedFlagIDs: []string{"flag"},
	}

	engine.Submit(packet)
	if got := len(engine.in); got != 0 {
		t.Fatalf("disabled scorer admitted %d packets", got)
	}
	if allocations := testing.AllocsPerRun(100, func() { engine.Submit(packet) }); allocations != 0 {
		t.Fatalf("disabled Submit allocated %.2f objects per call", allocations)
	}

	engine.enabled = true
	engine.Submit(packet)
	queued := <-engine.in
	packet.Body[0] = 'X'
	packet.MatchedRules[0].ID = "changed"
	packet.MatchedFlagIDs[0] = "changed"
	if got := string(queued.Body); got != "body" {
		t.Fatalf("queued body was not copied: %q", got)
	}
	if got := queued.MatchedRules[0].ID; got != "rule" {
		t.Fatalf("queued rules were not copied: %q", got)
	}
	if got := queued.MatchedFlagIDs[0]; got != "flag" {
		t.Fatalf("queued flag IDs were not copied: %q", got)
	}
}

func TestSetEnabledDiscardsPendingScoringWork(t *testing.T) {
	engine := &Engine{
		config:  NewBaselineConfig(time.Unix(1, 0), 120, 1, 5, nil),
		in:      make(chan *sniffer.Packet, 4),
		reset:   make(chan resetRequest),
		disable: make(chan chan struct{}),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
		enabled: true,
		flows: map[string]*flowRun{
			"partial": {packets: []*sniffer.Packet{{ID: 1}}, lastSeen: time.Now()},
		},
		baseline: make(map[string]map[string]map[int]struct{}),
		overflow: make(map[string]map[string]map[int]struct{}),
		excluded: make(map[string]uint64),
		scored:   make(map[string]uint64),
	}
	engine.in <- &sniffer.Packet{ID: 2, ServiceID: "svc", SessionID: "session"}
	go engine.run()
	defer engine.Close()

	engine.SetEnabled(false)
	if engine.IsEnabled() {
		t.Fatal("scorer still reports enabled")
	}
	if engine.Status().Enabled {
		t.Fatal("status still reports scoring enabled")
	}
	if got := len(engine.in); got != 0 {
		t.Fatalf("disable left %d queued packets", got)
	}
	if got := len(engine.flows); got != 0 {
		t.Fatalf("disable left %d partial flows", got)
	}

	engine.Submit(&sniffer.Packet{ID: 3, Body: []byte("do not copy")})
	if got := len(engine.in); got != 0 {
		t.Fatalf("disabled scorer admitted %d new packets", got)
	}

	engine.SetEnabled(true)
	if !engine.IsEnabled() || !engine.Status().Enabled {
		t.Fatal("scorer did not report re-enabled")
	}
	engine.SetEnabled(false)
}

func TestNewWithEnabledFalseSkipsBaselineStorage(t *testing.T) {
	// A nil store makes any baseline discovery/replay call panic, so reaching a
	// clean disabled engine proves startup did not touch persistence.
	engine := NewWithEnabled(nil, NewBaselineConfig(time.Unix(1, 0), 120, 1, 5, nil), false)
	defer engine.Close()
	if engine.IsEnabled() {
		t.Fatal("scorer started enabled")
	}
}

func testScoreEngine() *Engine {
	config := NewBaselineConfig(time.Unix(1, 0), 120, 1, 5, nil)
	return &Engine{
		config: config,
		baseline: map[string]map[string]map[int]struct{}{
			"svc": {"trusted": {1: {}, 2: {}, 3: {}, 4: {}, 5: {}}},
		},
	}
}
