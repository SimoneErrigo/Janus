package sniffer

import (
	"strings"

	"github.com/SimoneErrigo/Janus/backend/internal/filter"
)

// AsView wraps a *Packet so it satisfies filter.PacketView. Used for residual
// evaluation of a compiled DSL filter after the SQL fetch.
func AsView(p *Packet) filter.PacketView {
	return packetView{p: p}
}

type packetView struct{ p *Packet }

func (v packetView) ID() int64          { return v.p.ID }
func (v packetView) BodyString() string { return v.p.BodyString }
func (v packetView) BodyBytes() []byte  { return v.p.Body }
func (v packetView) URL() string        { return v.p.URL }
func (v packetView) Method() string     { return v.p.Method }
func (v packetView) Status() int        { return v.p.Status }
func (v packetView) Round() int {
	if v.p.Round > 0 {
		return v.p.Round
	}
	return v.p.FlagIDRound
}
func (v packetView) Protocol() string  { return v.p.Protocol }
func (v packetView) ServiceID() string { return v.p.ServiceID }
func (v packetView) Direction() string { return string(v.p.Direction) }
func (v packetView) SrcIP() string     { return v.p.SrcIP }
func (v packetView) DstIP() string     { return v.p.DstIP }
func (v packetView) PeerIP() string {
	if v.p.Direction == DirectionResponse {
		return v.p.DstIP
	}
	return v.p.SrcIP
}
func (v packetView) SrcPort() int { return v.p.SrcPort }
func (v packetView) DstPort() int { return v.p.DstPort }
func (v packetView) Header(name string) string {
	for k, val := range v.p.Headers {
		if strings.EqualFold(k, name) {
			return val
		}
	}
	return ""
}
func (v packetView) HeadersText() string {
	var b strings.Builder
	for k, val := range v.p.Headers {
		b.WriteString(k)
		b.WriteString(": ")
		b.WriteString(val)
		b.WriteByte('\n')
	}
	return b.String()
}
func (v packetView) RawBytes() []byte     { return v.p.Body } // residual eval has the assembled body, no raw frames
func (v packetView) Flagged() bool        { return v.p.Flagged }
func (v packetView) ContainsFlagID() bool { return v.p.ContainsFlagID }
func (v packetView) Dropped() bool {
	for _, mr := range v.p.MatchedRules {
		if mr.Action == "drop" || mr.Action == "both" {
			return true
		}
	}
	return false
}
