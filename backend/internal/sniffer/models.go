package sniffer

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/SimoneErrigo/Janus/backend/internal/flagids"
	flowmodel "github.com/SimoneErrigo/Janus/backend/internal/flow"
)

// CanonicalTimestamp keeps SQLite TEXT ordering identical to chronological
// ordering. RFC3339Nano normally omits trailing fractional zeros, which makes
// e.g. an exact second sort after that second plus 100ms lexicographically.
func CanonicalTimestamp(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000000000Z")
}

// PacketChangeKind tells packet listeners why they should refresh (e.g. SSE clients).
type PacketChangeKind byte

const (
	PacketChangeInsert   PacketChangeKind = iota // new row
	PacketChangeMetadata                         // e.g. flag-ID backfill updated rows
)

// Direction indicates whether this is a request or response.
type Direction string

const (
	DirectionRequest  Direction = "request"
	DirectionResponse Direction = "response"
)

// MatchedRuleInfo holds info about a rule that matched a packet.
type MatchedRuleInfo struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Action  string `json:"action"`
	Pattern string `json:"pattern,omitempty"`
	Scope   string `json:"scope,omitempty"`
}

// Alert represents a triggered alert rule entry.
type Alert struct {
	ID             int64     `json:"id"`
	PacketID       int64     `json:"packet_id"`
	RuleID         string    `json:"rule_id"`
	ServiceID      string    `json:"service_id"`
	SrcIP          string    `json:"src_ip"`
	Timestamp      time.Time `json:"timestamp"`
	PatternMatched string    `json:"pattern_matched"`
	MatchedScope   string    `json:"matched_scope,omitempty"`
	RuleName       string    `json:"rule_name,omitempty"`
}

// AlertQuery defines filters for retrieving alerts.
type AlertQuery struct {
	ServiceID string
	RuleID    string
	SrcIP     string
	TimeFrom  *time.Time
	TimeTo    *time.Time
	Limit     int
	Offset    int

	// Negation filters
	NotServiceID string
	NotRuleID    string
	NotSrcIP     string
}

// Packet represents a captured request or response passing through the proxy.
type Packet struct {
	ID        int64     `json:"id"`
	ServiceID string    `json:"service_id"`
	SessionID string    `json:"session_id"` // groups req+res from the same TCP connection
	Timestamp time.Time `json:"timestamp"`
	SrcIP     string    `json:"src_ip"`
	SrcPort   int       `json:"src_port"`
	DstIP     string    `json:"dst_ip"`
	DstPort   int       `json:"dst_port"`
	Protocol  string    `json:"protocol"`
	Direction Direction `json:"direction"`

	// HTTP-specific fields (empty for raw TCP)
	Method  string            `json:"method,omitempty"`
	URL     string            `json:"url,omitempty"`
	Status  int               `json:"status,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`

	// Body as raw bytes (base64-encoded in JSON) and as string if valid UTF-8
	Body       []byte         `json:"body,omitempty"`
	BodyString string         `json:"body_string,omitempty"`
	Decoded    map[string]any `json:"decoded,omitempty"`
	// CaptureTruncated means Janus forwarded the full body but retained only
	// the configured capture prefix for inspection.
	CaptureTruncated bool `json:"capture_truncated,omitempty"`

	// Filtering metadata
	MatchedRules     []MatchedRuleInfo `json:"matched_rules"`
	Flagged          bool              `json:"flagged"`
	ContainsFlagID   bool              `json:"contains_flagid"`
	MatchedFlagIDs   []string          `json:"matched_flagids"`
	FlagIDRound      int               `json:"flagid_round"` // round of the AC automaton used to scan this packet
	FlagCountBody    int               `json:"flag_count_body"`
	FlagCountHeaders int               `json:"flag_count_headers"`
	FlagCountURL     int               `json:"flag_count_url"`
	// PyFilterEventID links the inline decision to the later async notification;
	// it is intentionally transient and never exposed or persisted.
	PyFilterEventID string `json:"-"`

	// Round is the scoreboard round this packet falls into, computed from the
	// poller's competition_start + round_duration. Populated at serve time
	// (not stored in the DB) so the frontend can render a Round column
	// without doing client-side date math or polling. Zero when the poller
	// hasn't been configured.
	Round int `json:"round,omitempty"`

	// Lite indicates this packet was returned from a summary list query without
	// full headers/body. Clients should refetch by ID when full detail is needed.
	Lite bool `json:"lite,omitempty"`

	// Verdict records what was requested and what actually happened on the
	// data plane. Older rows are reconstructed during reads.
	Verdict flowmodel.Verdict `json:"verdict"`

	AttackScore     int           `json:"attack_score"`
	NormalScore     int           `json:"normal_score"`
	ScoreCoverage   int           `json:"score_coverage"`
	ScoreConfidence int           `json:"score_confidence"`
	Classification  string        `json:"classification,omitempty"`
	ScoreReasons    []ScoreReason `json:"score_reasons,omitempty"`
	AnalystLabel    string        `json:"analyst_label,omitempty"`
}

type ScoreReason struct {
	Code   string `json:"code"`
	Label  string `json:"label"`
	Weight int    `json:"weight"`
}

type FlowScore struct {
	Attack, Normal, Coverage, Confidence int
	Classification                       string
	Reasons                              []ScoreReason
}

// ScoreUpdate is emitted after a deterministic flow score is persisted. Live
// clients can patch only these rows instead of refetching the traffic window.
type ScoreUpdate struct {
	PacketIDs []int64       `json:"packet_ids"`
	Score     FlowScoreView `json:"score"`
}

type FlowScoreView struct {
	Attack         int           `json:"attack_score"`
	Normal         int           `json:"normal_score"`
	Coverage       int           `json:"score_coverage"`
	Confidence     int           `json:"score_confidence"`
	Classification string        `json:"classification"`
	Reasons        []ScoreReason `json:"score_reasons"`
}

func NewScoreUpdate(packetIDs []int64, score FlowScore) ScoreUpdate {
	return ScoreUpdate{
		PacketIDs: append([]int64(nil), packetIDs...),
		Score: FlowScoreView{
			Attack: score.Attack, Normal: score.Normal, Coverage: score.Coverage,
			Confidence: score.Confidence, Classification: score.Classification,
			Reasons: append([]ScoreReason(nil), score.Reasons...),
		},
	}
}

type BaselineSignature struct {
	ServiceID, Signature string
	Rounds               []int
}

// FlagIDChecker checks if text contains any current flag ID value.
type FlagIDChecker interface {
	ContainsFlagID(text string) bool
	FindMatchingFlagIDs(text string) []flagids.FlagMatch
	CurrentRound() int
}

// MakeSessionID builds a session identifier from the client (external) side of the connection.
// With SNAT, src_ip is the same for all teams, but src_port is unique per TCP connection.
func MakeSessionID(serviceID, clientIP string, clientPort int) string {
	return fmt.Sprintf("%s/%s:%d", serviceID, clientIP, clientPort)
}

var connectionSessionSequence atomic.Uint64

// MakeConnectionSessionID identifies one concrete live transport lifecycle.
// The nonce prevents a recycled client port from inheriting old counters or
// Python-filter state while the process is still running.
func MakeConnectionSessionID(serviceID, clientIP string, clientPort int) string {
	return fmt.Sprintf("%s/%s:%d/%x-%x", serviceID, clientIP, clientPort, time.Now().UnixNano(), connectionSessionSequence.Add(1))
}

type connectionSessionContextKey struct{}

// WithConnectionSession attaches a live connection ID to every request served
// on that net/http connection (including an eventual WebSocket upgrade).
func WithConnectionSession(ctx context.Context, sessionID string) context.Context {
	if ctx == nil || sessionID == "" {
		return ctx
	}
	return context.WithValue(ctx, connectionSessionContextKey{}, sessionID)
}

// ConnectionSessionFromContext returns the ID installed by the proxy's
// http.Server.ConnContext.
func ConnectionSessionFromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	sessionID, ok := ctx.Value(connectionSessionContextKey{}).(string)
	return sessionID, ok && sessionID != ""
}

func MakePyFilterEventID(sessionID string, direction Direction, at time.Time) string {
	return fmt.Sprintf("%s/%s/%d", sessionID, direction, at.UnixNano())
}

// SavedFlow is a pinned/bookmarked flow snapshot.
type SavedFlow struct {
	ID             int64     `json:"id"`
	Name           string    `json:"name"`
	AnchorPacketID int64     `json:"anchor_packet_id"`
	PacketIDs      []int64   `json:"packet_ids"` // snapshot at save time
	CreatedBy      string    `json:"created_by"`
	CreatedAt      time.Time `json:"created_at"`
	Notes          string    `json:"notes,omitempty"`
}

// PacketQuery defines filters for retrieving packets.
type PacketQuery struct {
	ServiceID       string
	ServiceName     string // resolved to ServiceID(s) by the API layer
	SrcIP           string
	DstIP           string
	Protocol        string
	Method          string
	Direction       string // "request" or "response" (empty = no filter)
	SessionID       string // filter by session (same TCP connection)
	PeerIP          string // filter by peer IP (src_ip for requests, dst_ip for responses)
	URL             string // filter by URL substring
	TimeFrom        *time.Time
	TimeTo          *time.Time
	Contains        string // substring search across body, headers, url (legacy)
	ContainsBody    string // substring search in body_string only
	ContainsHeaders string // substring search in headers JSON; supports "Name: Value" syntax
	Regex           string // regex search across body, headers, url
	Flagged         *bool  // nil = no filter, true = only flagged, false = only unflagged
	ContainsFlagID  *bool  // nil = no filter, true = only with flagID, false = only without
	FlagIDRound     *int   // persisted round assigned by flag-ID scanning/backfill
	HasMatchedRules *bool  // nil = no filter, true = only with matched rules, false = only without
	Dropped         *bool  // nil = no filter, true = only packets dropped by a rule (action=drop|both)
	Summary         bool   // when true, list query skips body/headers/matched_flagids and returns Lite packets
	SortOrder       string // "asc" or "desc" (default "desc")
	Limit           int
	Offset          int
	CursorTimestamp string // opaque API cursor decoded to RFC3339Nano
	CursorID        int64

	// Negation filters — same semantics as their positive counterparts but inverted.
	NotServiceID       string
	NotSrcIP           string
	NotDstIP           string
	NotProtocol        string
	NotMethod          string
	NotDirection       string
	NotPeerIP          string
	NotURL             string
	NotContains        string // excludes packets whose body/headers/url contain this substring (legacy)
	NotContainsBody    string // excludes packets whose body_string contains this substring
	NotContainsHeaders string // excludes packets whose headers contain this (supports "Name: Value")
	NotRegex           string // excludes packets matching this regex (applied in Go, same path as Regex)

	// Per-user client-side hide filters.
	// ExcludeIDs omits any packet whose ID is in the list (user-level deletes).
	// HiddenBefore omits packets whose timestamp is earlier than this (user-level "Clear Packets").
	ExcludeIDs   []int64
	HiddenBefore *time.Time

	// Q is an optional unified expression-language filter (the new DSL).
	// When set, it is parsed and AND-combined with the legacy params above:
	// pushable predicates extend the SQL WHERE; the rest is evaluated in Go
	// after the fetch (same path as the regex residual).
	Q string
}

type QueryMeta struct {
	TotalExact    bool      `json:"total_exact"`
	Partial       bool      `json:"partial"`
	NextTimestamp time.Time `json:"-"`
	NextID        int64     `json:"-"`
}
