// Package flow owns the canonical data-plane representation shared by live
// rules, persisted packet searches and extension runtimes.
package flow

import (
	"sort"
	"strings"
	"time"
)

type Endpoint struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// PacketView is built once at an enforcement boundary and then passed to all
// evaluators. Field names deliberately differ from accessor methods so it can
// directly satisfy filter.PacketView without another adapter.
type PacketView struct {
	PacketID             int64             `json:"packet_id,omitempty"`
	Service              string            `json:"service"`
	Session              string            `json:"session,omitempty"`
	OccurredAt           time.Time         `json:"timestamp"`
	Source               Endpoint          `json:"source"`
	Destination          Endpoint          `json:"destination"`
	ProtocolName         string            `json:"protocol"`
	DirectionName        string            `json:"direction"`
	MethodName           string            `json:"method,omitempty"`
	URLValue             string            `json:"url,omitempty"`
	StatusCode           int               `json:"status,omitempty"`
	HeaderValues         map[string]string `json:"headers,omitempty"`
	Payload              []byte            `json:"body,omitempty"`
	BodyText             string            `json:"body_string,omitempty"`
	Raw                  []byte            `json:"raw,omitempty"`
	RoundNumber          int               `json:"round,omitempty"`
	FlaggedValue         bool              `json:"flagged"`
	ContainsFlagIDValue  bool              `json:"contains_flagid"`
	DroppedValue         bool              `json:"dropped"`
	Truncated            bool              `json:"truncated,omitempty"`
	Decoded              map[string]any    `json:"decoded,omitempty"`
	AttackScoreValue     int               `json:"attack_score,omitempty"`
	NormalScoreValue     int               `json:"normal_score,omitempty"`
	ScoreCoverageValue   int               `json:"score_coverage,omitempty"`
	ScoreConfidenceValue int               `json:"score_confidence,omitempty"`
	ClassificationValue  string            `json:"classification,omitempty"`
	AnalystLabelValue    string            `json:"analyst_label,omitempty"`
}

func (v PacketView) ID() int64                     { return v.PacketID }
func (v PacketView) BodyString() string            { return v.BodyText }
func (v PacketView) BodyBytes() []byte             { return v.Payload }
func (v PacketView) URL() string                   { return v.URLValue }
func (v PacketView) Method() string                { return v.MethodName }
func (v PacketView) Status() int                   { return v.StatusCode }
func (v PacketView) Round() int                    { return v.RoundNumber }
func (v PacketView) Protocol() string              { return v.ProtocolName }
func (v PacketView) ServiceID() string             { return v.Service }
func (v PacketView) Direction() string             { return v.DirectionName }
func (v PacketView) SrcIP() string                 { return v.Source.IP }
func (v PacketView) DstIP() string                 { return v.Destination.IP }
func (v PacketView) SrcPort() int                  { return v.Source.Port }
func (v PacketView) DstPort() int                  { return v.Destination.Port }
func (v PacketView) Flagged() bool                 { return v.FlaggedValue }
func (v PacketView) ContainsFlagID() bool          { return v.ContainsFlagIDValue }
func (v PacketView) Dropped() bool                 { return v.DroppedValue }
func (v PacketView) DecodedFields() map[string]any { return v.Decoded }
func (v PacketView) ScoreInt(field string) int64 {
	switch field {
	case "attack_score":
		return int64(v.AttackScoreValue)
	case "normal_score":
		return int64(v.NormalScoreValue)
	case "score_coverage":
		return int64(v.ScoreCoverageValue)
	case "score_confidence":
		return int64(v.ScoreConfidenceValue)
	}
	return 0
}
func (v PacketView) Classification() string { return v.ClassificationValue }
func (v PacketView) AnalystLabel() string   { return v.AnalystLabelValue }

func (v PacketView) PeerIP() string {
	if v.DirectionName == "response" {
		return v.Destination.IP
	}
	return v.Source.IP
}

func (v PacketView) Header(name string) string {
	for key, value := range v.HeaderValues {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}

func (v PacketView) HeadersText() string {
	keys := make([]string, 0, len(v.HeaderValues))
	for key := range v.HeaderValues {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, key := range keys {
		b.WriteString(key)
		b.WriteString(": ")
		b.WriteString(v.HeaderValues[key])
		b.WriteByte('\n')
	}
	return b.String()
}

func (v PacketView) RawBytes() []byte {
	if v.Raw != nil {
		return v.Raw
	}
	return v.Payload
}
