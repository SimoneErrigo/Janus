package filter

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// PacketView abstracts the bits of a packet/request the evaluator can read.
// Implementations:
//   - sniffer.Packet (residual eval after a SQL fetch)
//   - dropper.HTTPRequest (hot-path rule eval)
//
// Adapters live in the calling packages so internal/filter has no Janus-specific deps.
type PacketView interface {
	// ID is the packet's autoincrement number (the "#" shown in the UI).
	// Returns 0 on the ingest hot path, where no row id exists yet.
	ID() int64
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
	case "packet_id", "pkt", "num", "no":
		return "id"
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
	"id":               {Name: "id", Type: TypeInt, SQLColumn: "id"},
	"body":             {Name: "body", Type: TypeString, SQLColumn: "body_string"},
	"raw":              {Name: "raw", Type: TypeBytes, SQLColumn: ""},
	"url":              {Name: "url", Type: TypeString, SQLColumn: "url"},
	"path":             {Name: "path", Type: TypeString, SQLColumn: ""},
	"method":           {Name: "method", Type: TypeString, SQLColumn: "method"},
	"status":           {Name: "status", Type: TypeInt, SQLColumn: "status"},
	"round":            {Name: "round", Type: TypeInt, SQLColumn: ""},
	"proto":            {Name: "proto", Type: TypeString, SQLColumn: "protocol"},
	"service":          {Name: "service", Type: TypeString, SQLColumn: "service_id"},
	"direction":        {Name: "direction", Type: TypeString, SQLColumn: "direction"},
	"src":              {Name: "src", Type: TypeString, SQLColumn: "src_ip"},
	"dst":              {Name: "dst", Type: TypeString, SQLColumn: "dst_ip"},
	"peer":             {Name: "peer", Type: TypeString, SQLColumn: ""}, // peer is direction-aware, eval-only
	"sport":            {Name: "sport", Type: TypeInt, SQLColumn: "src_port"},
	"dport":            {Name: "dport", Type: TypeInt, SQLColumn: "dst_port"},
	"header":           {Name: "header", Type: TypeHeaders, SQLColumn: "headers", IsHeaderField: true},
	"flagged":          {Name: "flagged", Type: TypeBool, SQLColumn: "flagged"},
	"contains_flagid":  {Name: "contains_flagid", Type: TypeBool, SQLColumn: "contains_flagid"},
	"dropped":          {Name: "dropped", Type: TypeBool, SQLColumn: "has_drop_match"},
	"attack_score":     {Name: "attack_score", Type: TypeInt, SQLColumn: "attack_score"},
	"normal_score":     {Name: "normal_score", Type: TypeInt, SQLColumn: "normal_score"},
	"score_coverage":   {Name: "score_coverage", Type: TypeInt, SQLColumn: "score_coverage"},
	"score_confidence": {Name: "score_confidence", Type: TypeInt, SQLColumn: "score_confidence"},
	"classification":   {Name: "classification", Type: TypeString, SQLColumn: "classification"},
	"analyst_label":    {Name: "analyst_label", Type: TypeString, SQLColumn: "analyst_label"},
}

// LookupField returns the registered Field for a canonical name.
func LookupField(name string) (Field, bool) {
	name = canonicalField(name)
	f, ok := fields[name]
	if ok {
		return f, true
	}
	for _, prefix := range []string{"decoded.", "json.", "query.", "form.", "cookie.", "dns.", "resp.", "mqtt."} {
		if strings.HasPrefix(name, prefix) && len(name) > len(prefix) {
			return Field{Name: name, Type: TypeString}, true
		}
	}
	return f, ok
}

// opCompatible reports whether op is meaningful for the given field type.
func opCompatible(t FieldType, op Op) bool {
	switch t {
	case TypeString, TypeBytes, TypeHeaders:
		switch op {
		case OpContains, OpIContains, OpEq, OpNeq, OpMatches,
			OpStartsWith, OpEndsWith, OpIn, OpExists, OpMissing:
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
	case "path":
		u, err := url.Parse(p.URL())
		if err == nil {
			return u.Path
		}
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
	case "classification":
		if view, ok := p.(interface{ Classification() string }); ok {
			return view.Classification()
		}
	case "analyst_label":
		if view, ok := p.(interface{ AnalystLabel() string }); ok {
			return view.AnalystLabel()
		}
	case "header":
		if headerName != "" {
			return p.Header(headerName)
		}
		return p.HeadersText()
	}
	if value, ok := readStructured(p, field); ok {
		return value
	}
	return ""
}

func readStructured(p PacketView, field string) (string, bool) {
	switch {
	case strings.HasPrefix(field, "query."):
		u, err := url.Parse(p.URL())
		if err != nil {
			return "", false
		}
		value, ok := u.Query()[strings.TrimPrefix(field, "query.")]
		return strings.Join(value, ","), ok
	case strings.HasPrefix(field, "form."):
		values, err := url.ParseQuery(p.BodyString())
		if err != nil {
			return "", false
		}
		value, ok := values[strings.TrimPrefix(field, "form.")]
		return strings.Join(value, ","), ok
	case strings.HasPrefix(field, "cookie."):
		req := &http.Request{Header: http.Header{"Cookie": []string{p.Header("Cookie")}}}
		cookie, err := req.Cookie(strings.TrimPrefix(field, "cookie."))
		if err != nil {
			return "", false
		}
		return cookie.Value, true
	case strings.HasPrefix(field, "json."):
		var root any
		if json.Unmarshal([]byte(p.BodyString()), &root) != nil {
			return "", false
		}
		return walkValue(root, strings.Split(strings.TrimPrefix(field, "json."), "."))
	default:
		path := field
		if strings.HasPrefix(path, "decoded.") {
			path = strings.TrimPrefix(path, "decoded.")
		}
		if strings.HasPrefix(field, "dns.") || strings.HasPrefix(field, "resp.") || strings.HasPrefix(field, "mqtt.") || strings.HasPrefix(field, "decoded.") {
			return walkValue(decodedFields(p), strings.Split(path, "."))
		}
	}
	return "", false
}

func decodedFields(p PacketView) map[string]any {
	if view, ok := p.(interface{ DecodedFields() map[string]any }); ok {
		return view.DecodedFields()
	}
	return nil
}

func walkValue(root any, path []string) (string, bool) {
	current := root
	for _, part := range path {
		object, ok := current.(map[string]any)
		if !ok {
			return "", false
		}
		current, ok = object[part]
		if !ok {
			return "", false
		}
	}
	switch value := current.(type) {
	case string:
		return value, true
	case nil:
		return "", false
	default:
		return fmt.Sprint(value), true
	}
}

func readInt(p PacketView, field string) int64 {
	switch field {
	case "id":
		return p.ID()
	case "status":
		return int64(p.Status())
	case "round":
		return int64(p.Round())
	case "sport":
		return int64(p.SrcPort())
	case "dport":
		return int64(p.DstPort())
	}
	if view, ok := p.(interface{ ScoreInt(string) int64 }); ok {
		return view.ScoreInt(field)
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
