package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/SimoneErrigo/Janus/backend/internal/sniffer"
)

// packetEvent is a lightweight packet representation for SSE streaming.
// Excludes body/headers to keep events small.
type packetRuleEvent struct {
	ID     string `json:"id"`
	Name   string `json:"name,omitempty"`
	Action string `json:"action"`
}

type packetEvent struct {
	ID             int64             `json:"id"`
	ServiceID      string            `json:"service_id"`
	SessionID      string            `json:"session_id"`
	Timestamp      time.Time         `json:"timestamp"`
	SrcIP          string            `json:"src_ip"`
	SrcPort        int               `json:"src_port"`
	DstIP          string            `json:"dst_ip"`
	DstPort        int               `json:"dst_port"`
	Protocol       string            `json:"protocol"`
	Direction      sniffer.Direction `json:"direction"`
	Method         string            `json:"method,omitempty"`
	URL            string            `json:"url,omitempty"`
	Status         int               `json:"status,omitempty"`
	MatchedRules   []packetRuleEvent `json:"matched_rules"`
	Flagged        bool              `json:"flagged"`
	ContainsFlagID bool              `json:"contains_flagid"`
	BodySize       int               `json:"body_size"`
}

func toPacketEvent(p *sniffer.Packet) packetEvent {
	rules := make([]packetRuleEvent, 0, len(p.MatchedRules))
	for _, r := range p.MatchedRules {
		rules = append(rules, packetRuleEvent{ID: r.ID, Name: r.Name, Action: r.Action})
	}
	return packetEvent{
		ID: p.ID, ServiceID: p.ServiceID, SessionID: p.SessionID,
		Timestamp: p.Timestamp, SrcIP: p.SrcIP, SrcPort: p.SrcPort,
		DstIP: p.DstIP, DstPort: p.DstPort, Protocol: p.Protocol,
		Direction: p.Direction, Method: p.Method, URL: p.URL, Status: p.Status,
		MatchedRules: rules, Flagged: p.Flagged,
		ContainsFlagID: p.ContainsFlagID, BodySize: len(p.Body),
	}
}

// PacketStreamHub fans out packet-change signals to SSE subscribers.
// New packets are buffered and pushed as JSON every 100ms for smooth flow.
// Metadata changes (backfill) trigger a refresh signal.
type PacketStreamHub struct {
	mu   sync.Mutex
	subs map[chan sseMessage]struct{}

	// Packet buffer for streaming
	bufMu  sync.Mutex
	buffer []packetEvent

	metaDirty atomic.Int32 // 1 = metadata changed, trigger refresh
	stop      chan struct{}
}

type sseMessage struct {
	event string // "new-packets" or "packets"
	data  []byte // JSON payload or empty
}

const streamInterval = 100 * time.Millisecond

func NewPacketStreamHub() *PacketStreamHub {
	h := &PacketStreamHub{
		subs: make(map[chan sseMessage]struct{}),
		stop: make(chan struct{}),
	}
	go h.loop()
	return h
}

// PushPacket buffers a new packet for the next SSE broadcast.
func (h *PacketStreamHub) PushPacket(pkt *sniffer.Packet) {
	if h == nil || pkt == nil {
		return
	}
	evt := toPacketEvent(pkt)
	h.bufMu.Lock()
	h.buffer = append(h.buffer, evt)
	h.bufMu.Unlock()
}

// Notify signals that packet metadata changed (e.g. backfill).
// Subscribers will get a refresh signal.
func (h *PacketStreamHub) Notify() {
	if h == nil {
		return
	}
	h.metaDirty.Store(1)
}

func (h *PacketStreamHub) loop() {
	ticker := time.NewTicker(streamInterval)
	defer ticker.Stop()
	for {
		select {
		case <-h.stop:
			return
		case <-ticker.C:
			h.flush()
		}
	}
}

func (h *PacketStreamHub) flush() {
	// Grab buffered packets
	h.bufMu.Lock()
	packets := h.buffer
	h.buffer = nil
	h.bufMu.Unlock()

	// Send new-packets event if we have any
	if len(packets) > 0 {
		data, err := json.Marshal(packets)
		if err == nil {
			h.broadcast(sseMessage{event: "new-packets", data: data})
		}
	}

	// Send refresh signal if metadata changed
	if h.metaDirty.Swap(0) == 1 {
		h.broadcast(sseMessage{event: "packets", data: []byte("{}")})
	}
}

func (h *PacketStreamHub) broadcast(msg sseMessage) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- msg:
		default: // subscriber is slow, drop this message
		}
	}
}

func (h *PacketStreamHub) Stop() {
	if h == nil {
		return
	}
	select {
	case h.stop <- struct{}{}:
	default:
	}
}

func (h *PacketStreamHub) subscribe() (notify <-chan sseMessage, unsubscribe func()) {
	ch := make(chan sseMessage, 8)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		delete(h.subs, ch)
		h.mu.Unlock()
	}
}

func (s *Server) handlePacketStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := AuthTokenFromRequest(r)
	if token == "" || !validateToken(token) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if s.packetHub == nil {
		http.Error(w, "stream unavailable", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	notify, unsubscribe := s.packetHub.subscribe()
	defer unsubscribe()

	fmt.Fprintf(w, ": ok\n\n")
	flusher.Flush()

	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case msg := <-notify:
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", msg.event, msg.data)
			flusher.Flush()
		case <-ticker.C:
			fmt.Fprintf(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}
