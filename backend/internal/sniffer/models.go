package sniffer

import "time"

// Direction indicates whether this is a request or response.
type Direction string

const (
	DirectionRequest  Direction = "request"
	DirectionResponse Direction = "response"
)

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
}

// PacketQuery defines filters for retrieving packets.
type PacketQuery struct {
	ServiceID string
	TimeFrom  *time.Time
	TimeTo    *time.Time
	Limit     int
	Offset    int
}
