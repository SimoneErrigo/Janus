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

func testScoreEngine() *Engine {
	config := NewBaselineConfig(time.Unix(1, 0), 120, 1, 5, nil)
	return &Engine{
		config: config,
		baseline: map[string]map[string]map[int]struct{}{
			"svc": {"trusted": {1: {}, 2: {}, 3: {}, 4: {}, 5: {}}},
		},
	}
}
