package sniffer

import "time"

// Direction indicates whether this is a request or response.
type Direction string

const (
	DirectionRequest  Direction = "request"
	DirectionResponse Direction = "response"
)

// MatchedRuleInfo holds info about a rule that matched a packet.
type MatchedRuleInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Packet represents a captured request or response passing through the proxy.
type Packet struct {
	ID        int64     `json:"id"`
	ServiceID string    `json:"service_id"`
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

// PacketQuery defines filters for retrieving packets.
type PacketQuery struct {
	ServiceID   string
	ServiceName string // resolved to ServiceID(s) by the API layer
	SrcIP       string
	DstIP       string
	Protocol    string
	TimeFrom    *time.Time
	TimeTo      *time.Time
	Contains    string // substring search across body, headers, url
	Regex       string // regex search across body, headers, url
	Flagged     *bool  // nil = no filter, true = only flagged, false = only unflagged
	SortOrder   string // "asc" or "desc" (default "desc")
	Limit       int
	Offset      int
}
