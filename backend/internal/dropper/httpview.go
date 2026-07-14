package dropper

import (
	"strings"

	"github.com/SimoneErrigo/Janus/backend/internal/filter"
)

// httpRequestView adapts dropper.HTTPRequest to filter.PacketView for the
// hot-path rules engine. Callers populate the protocol metadata they know;
// unavailable fields retain their zero value and simply do not match.
type httpRequestView struct{ req *HTTPRequest }

func newView(req *HTTPRequest) filter.PacketView {
	return httpRequestView{req: req}
}

func (v httpRequestView) ID() int64          { return 0 }
func (v httpRequestView) BodyString() string { return string(v.req.Body) }
func (v httpRequestView) BodyBytes() []byte  { return v.req.Body }
func (v httpRequestView) URL() string        { return v.req.URL }
func (v httpRequestView) Method() string     { return v.req.Method }
func (v httpRequestView) Status() int        { return v.req.Status }
func (v httpRequestView) Round() int         { return 0 }
func (v httpRequestView) Protocol() string   { return v.req.Protocol }
func (v httpRequestView) ServiceID() string  { return v.req.ServiceID }
func (v httpRequestView) Direction() string  { return v.req.Direction }
func (v httpRequestView) SrcIP() string      { return v.req.SrcIP }
func (v httpRequestView) DstIP() string      { return v.req.DstIP }
func (v httpRequestView) PeerIP() string {
	if v.req.Direction == "response" {
		return v.req.DstIP
	}
	return v.req.SrcIP
}
func (v httpRequestView) SrcPort() int { return v.req.SrcPort }
func (v httpRequestView) DstPort() int { return v.req.DstPort }

// Header looks up a single header value by case-insensitive name within the
// flattened header text the middleware passes in. Format expected: lines of
// "Name: Value" separated by \n (matches what HTTPMiddleware constructs).
func (v httpRequestView) Header(name string) string {
	if v.req.Headers == "" || name == "" {
		return ""
	}
	want := strings.ToLower(name)
	for _, line := range strings.Split(v.req.Headers, "\n") {
		if line == "" {
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		if strings.ToLower(strings.TrimSpace(line[:colon])) == want {
			return strings.TrimSpace(line[colon+1:])
		}
	}
	return ""
}

func (v httpRequestView) HeadersText() string           { return v.req.Headers }
func (v httpRequestView) RawBytes() []byte              { return v.req.RawBytes }
func (v httpRequestView) Flagged() bool                 { return v.req.Flagged }
func (v httpRequestView) ContainsFlagID() bool          { return v.req.ContainsFlagID }
func (v httpRequestView) Dropped() bool                 { return false }
func (v httpRequestView) DecodedFields() map[string]any { return nil }
