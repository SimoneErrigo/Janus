package sniffer

import (
	"fmt"
	"time"
)

// Direction indicates whether this is a request or response.
type Direction string

const (
	DirectionRequest  Direction = "request"
	DirectionResponse Direction = "response"
)

// MatchedRuleInfo holds info about a rule that matched a packet.
type MatchedRuleInfo struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Action string `json:"action"`
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
	Body       []byte `json:"body,omitempty"`
	BodyString string `json:"body_string,omitempty"`

	// Filtering metadata
	MatchedRules []MatchedRuleInfo `json:"matched_rules"`
	Flagged      bool              `json:"flagged"`
}

// MakeSessionID builds a session identifier from the client (external) side of the connection.
// With SNAT, src_ip is the same for all teams, but src_port is unique per TCP connection.
func MakeSessionID(serviceID, clientIP string, clientPort int) string {
	return fmt.Sprintf("%s/%s:%d", serviceID, clientIP, clientPort)
}

// PacketQuery defines filters for retrieving packets.
type PacketQuery struct {
	ServiceID   string
	ServiceName string // resolved to ServiceID(s) by the API layer
	SrcIP       string
	DstIP       string
	Protocol    string
	Method      string
	SessionID   string // filter by session (same TCP connection)
	PeerIP      string // filter by peer IP (src_ip for requests, dst_ip for responses)
	TimeFrom    *time.Time
	TimeTo      *time.Time
	Contains    string // substring search across body, headers, url
	Regex       string // regex search across body, headers, url
	Flagged     *bool  // nil = no filter, true = only flagged, false = only unflagged
	SortOrder   string // "asc" or "desc" (default "desc")
	Limit       int
	Offset      int
}
