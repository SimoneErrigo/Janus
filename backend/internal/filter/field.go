package filter

// PacketView abstracts the bits of a packet/request the evaluator can read.
// Implementations:
//   - sniffer.Packet (residual eval after a SQL fetch)
//   - dropper.HTTPRequest (hot-path rule eval)
//
// Adapters live in the calling packages so internal/filter has no Janus-specific deps.
type PacketView interface {
	BodyString() string
	BodyBytes() []byte
	URL() string
	Method() string
	Status() int
	Round() int
	Protocol() string
	ServiceID() string
	Direction() string
	SrcIP() string
	DstIP() string
	PeerIP() string
	SrcPort() int
	DstPort() int
	// Header returns the value for a specific header name (case-insensitive).
	// Empty string when the header is absent or headers aren't available.
	Header(name string) string
	// HeadersText is a flat searchable text view of every header.
	// Used for `header contains/matches/...` (no sub-name).
	HeadersText() string
	RawBytes() []byte
	Flagged() bool
	ContainsFlagID() bool
	Dropped() bool
}

// FieldType drives op compatibility checks.
type FieldType int

const (
	TypeString FieldType = iota
	TypeInt
	TypeBool
	TypeBytes
	TypeHeaders // pseudo-type for `header` (multi-value) — supports contains/matches but accessed via Header(name)
)

// Field describes one queryable field.
type Field struct {
	Name      string
	Type      FieldType
	SQLColumn string // empty when not pushable to SQL
	// IsHeaderField marks `header` / `header.<name>`.
	IsHeaderField bool
}

// canonicalField resolves user-facing aliases to the canonical name used
// internally and in the registry.
func canonicalField(name string) string {
	switch name {
	case "headers":
		return "header"
	case "src", "src_ip":
		return "src"
	case "dst", "dst_ip":
		return "dst"
	case "peer", "peer_ip":
		return "peer"
	case "sport", "src_port":
		return "sport"
	case "dport", "dst_port":
		return "dport"
	case "proto", "protocol":
		return "proto"
	case "service", "service_id":
		return "service"
	}
	return name
}

// fields is the master registry. Adding a field = one entry here.
var fields = map[string]Field{
	"body":            {Name: "body", Type: TypeString, SQLColumn: "body_string"},
	"raw":             {Name: "raw", Type: TypeBytes, SQLColumn: ""},
	"url":             {Name: "url", Type: TypeString, SQLColumn: "url"},
	"method":          {Name: "method", Type: TypeString, SQLColumn: "method"},
	"status":          {Name: "status", Type: TypeInt, SQLColumn: "status"},
	"round":           {Name: "round", Type: TypeInt, SQLColumn: ""},
	"proto":           {Name: "proto", Type: TypeString, SQLColumn: "protocol"},
	"service":         {Name: "service", Type: TypeString, SQLColumn: "service_id"},
	"direction":       {Name: "direction", Type: TypeString, SQLColumn: "direction"},
	"src":             {Name: "src", Type: TypeString, SQLColumn: "src_ip"},
	"dst":             {Name: "dst", Type: TypeString, SQLColumn: "dst_ip"},
	"peer":            {Name: "peer", Type: TypeString, SQLColumn: ""}, // peer is direction-aware, eval-only
	"sport":           {Name: "sport", Type: TypeInt, SQLColumn: "src_port"},
	"dport":           {Name: "dport", Type: TypeInt, SQLColumn: "dst_port"},
	"header":          {Name: "header", Type: TypeHeaders, SQLColumn: "headers", IsHeaderField: true},
	"flagged":         {Name: "flagged", Type: TypeBool, SQLColumn: "flagged"},
	"contains_flagid": {Name: "contains_flagid", Type: TypeBool, SQLColumn: "contains_flagid"},
	"dropped":         {Name: "dropped", Type: TypeBool, SQLColumn: "has_drop_match"},
}

// LookupField returns the registered Field for a canonical name.
func LookupField(name string) (Field, bool) {
	f, ok := fields[canonicalField(name)]
	return f, ok
}

// opCompatible reports whether op is meaningful for the given field type.
func opCompatible(t FieldType, op Op) bool {
	switch t {
	case TypeString, TypeBytes, TypeHeaders:
		switch op {
		case OpContains, OpIContains, OpEq, OpNeq, OpMatches,
			OpStartsWith, OpEndsWith, OpIn:
			return true
		}
	case TypeInt:
		switch op {
		case OpEq, OpNeq, OpGT, OpLT, OpGTE, OpLTE, OpIn:
			return true
		}
	case TypeBool:
		switch op {
		case OpEq, OpNeq:
			return true
		}
	}
	return false
}

// readString pulls a string-shaped accessor for a string/bytes/headers field.
// For TypeHeaders without HeaderName, returns HeadersText().
func readString(p PacketView, field string, headerName string) string {
	switch field {
	case "body":
		return p.BodyString()
	case "raw":
		return string(p.RawBytes())
	case "url":
		return p.URL()
	case "method":
		return p.Method()
	case "proto":
		return p.Protocol()
	case "service":
		return p.ServiceID()
	case "direction":
		return p.Direction()
	case "src":
		return p.SrcIP()
	case "dst":
		return p.DstIP()
	case "peer":
		return p.PeerIP()
	case "header":
		if headerName != "" {
			return p.Header(headerName)
		}
		return p.HeadersText()
	}
	return ""
}

func readInt(p PacketView, field string) int64 {
	switch field {
	case "status":
		return int64(p.Status())
	case "round":
		return int64(p.Round())
	case "sport":
		return int64(p.SrcPort())
	case "dport":
		return int64(p.DstPort())
	}
	return 0
}

func readBool(p PacketView, field string) bool {
	switch field {
	case "flagged":
		return p.Flagged()
	case "contains_flagid":
		return p.ContainsFlagID()
	case "dropped":
		return p.Dropped()
	}
	return false
}
