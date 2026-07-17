package sniffer

import (
	"github.com/SimoneErrigo/Janus/backend/internal/filter"
	flowmodel "github.com/SimoneErrigo/Janus/backend/internal/flow"
)

// View converts persisted traffic into the same canonical representation used
// on the live enforcement path.
func (p *Packet) View() flowmodel.PacketView {
	dropped := p.Verdict.Outcome == flowmodel.OutcomeDropped
	return flowmodel.PacketView{
		PacketID: p.ID, Service: p.ServiceID, Session: p.SessionID,
		OccurredAt:   p.Timestamp,
		Source:       flowmodel.Endpoint{IP: p.SrcIP, Port: p.SrcPort},
		Destination:  flowmodel.Endpoint{IP: p.DstIP, Port: p.DstPort},
		ProtocolName: string(p.Protocol), DirectionName: string(p.Direction),
		MethodName: p.Method, URLValue: p.URL, StatusCode: p.Status,
		HeaderValues: p.Headers, Payload: p.Body, BodyText: p.BodyString,
		RoundNumber: p.Round, FlaggedValue: p.Flagged,
		ContainsFlagIDValue: p.ContainsFlagID, DroppedValue: dropped,
		Truncated: p.CaptureTruncated, Decoded: p.Decoded,
		AttackScoreValue: p.AttackScore, NormalScoreValue: p.NormalScore,
		ScoreCoverageValue: p.ScoreCoverage, ScoreConfidenceValue: p.ScoreConfidence,
		ClassificationValue: p.Classification, AnalystLabelValue: p.AnalystLabel,
	}
}

func AsView(p *Packet) filter.PacketView { return p.View() }
