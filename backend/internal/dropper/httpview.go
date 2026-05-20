package dropper

import (
	"strings"

	"github.com/SimoneErrigo/Janus/backend/internal/filter"
)

// httpRequestView adapts dropper.HTTPRequest to filter.PacketView for the
// hot-path rules engine. Fields the proxy middleware doesn't carry today
// (src/dst/method/status/...) report empty/zero. Predicates referencing
// those simply won't match — none of the auto-migrated rules use them.
type httpRequestView struct{ req *HTTPRequest }

func newView(req *HTTPRequest) filter.PacketView {
	return httpRequestView{req: req}
}

func (v httpRequestView) BodyString() string { return string(v.req.Body) }
func (v httpRequestView) BodyBytes() []byte  { return v.req.Body }
func (v httpRequestView) URL() string        { return v.req.URL }
func (v httpRequestView) Method() string     { return "" }
func (v httpRequestView) Status() int        { return 0 }
func (v httpRequestView) Round() int         { return 0 }
func (v httpRequestView) Protocol() string   { return "" }
func (v httpRequestView) ServiceID() string  { return v.req.ServiceID }
func (v httpRequestView) Direction() string  { return "" }
func (v httpRequestView) SrcIP() string      { return "" }
func (v httpRequestView) DstIP() string      { return "" }
func (v httpRequestView) PeerIP() string     { return "" }
func (v httpRequestView) SrcPort() int       { return 0 }
func (v httpRequestView) DstPort() int       { return 0 }

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

func (v httpRequestView) HeadersText() string  { return v.req.Headers }
func (v httpRequestView) RawBytes() []byte     { return v.req.RawBytes }
func (v httpRequestView) Flagged() bool        { return false }
func (v httpRequestView) ContainsFlagID() bool { return false }
func (v httpRequestView) Dropped() bool        { return false }
