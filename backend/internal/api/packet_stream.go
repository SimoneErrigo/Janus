package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	flowmodel "github.com/SimoneErrigo/Janus/backend/internal/flow"
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
	Dropped        bool              `json:"dropped"`
	FlagIDRound    int               `json:"flagid_round,omitempty"`
	BodySize       int               `json:"body_size"`
	// Round computed from the poller's competition_start + round_duration.
	// Same field name as the bulk REST API so the frontend can read it
	// uniformly regardless of which transport delivered the packet.
	Round int `json:"round,omitempty"`
}

// RoundResolver provides a packet's scoreboard round from its timestamp.
// The flagids.Poller satisfies this so we can avoid an import cycle.
type RoundResolver interface {
	RoundForTime(time.Time) int
}

func toPacketEvent(p *sniffer.Packet, rr RoundResolver) packetEvent {
	rules := make([]packetRuleEvent, 0, len(p.MatchedRules))
	for _, r := range p.MatchedRules {
		rules = append(rules, packetRuleEvent{ID: r.ID, Name: r.Name, Action: r.Action})
	}
	var round int
	if rr != nil {
		round = rr.RoundForTime(p.Timestamp)
	}
	if round == 0 && p.FlagIDRound > 0 {
		round = p.FlagIDRound
	}
	return packetEvent{
		ID: p.ID, ServiceID: p.ServiceID, SessionID: p.SessionID,
		Timestamp: p.Timestamp, SrcIP: p.SrcIP, SrcPort: p.SrcPort,
		DstIP: p.DstIP, DstPort: p.DstPort, Protocol: p.Protocol,
		Direction: p.Direction, Method: p.Method, URL: p.URL, Status: p.Status,
		MatchedRules: rules, Flagged: p.Flagged,
		ContainsFlagID: p.ContainsFlagID, Dropped: p.Verdict.Outcome == flowmodel.OutcomeDropped,
		FlagIDRound: p.FlagIDRound, BodySize: len(p.Body),
		Round: round,
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
	scores []sniffer.ScoreUpdate

	// Computes the round number for a packet's timestamp. Optional —
	// when nil the event's Round stays 0 and the frontend renders "—".
	roundResolver RoundResolver

	metaDirty atomic.Int32 // 1 = metadata changed, trigger refresh
	stopped   atomic.Bool
	stop      chan struct{}
	done      chan struct{}
	stopOnce  sync.Once
}

type sseMessage struct {
	event string // "new-packets" or "packets"
	data  []byte // JSON payload or empty
}

const streamInterval = 100 * time.Millisecond

// NewPacketStreamHub creates a hub that fans out new packets via SSE.
// rr is optional: when non-nil, each pushed packet is annotated with its
// scoreboard round so the frontend can render the Round column without
// polling.
func NewPacketStreamHub(rr RoundResolver) *PacketStreamHub {
	h := &PacketStreamHub{
		subs:          make(map[chan sseMessage]struct{}),
		roundResolver: rr,
		stop:          make(chan struct{}),
		done:          make(chan struct{}),
	}
	go h.loop()
	return h
}

// PushPacket buffers a new packet for the next SSE broadcast.
func (h *PacketStreamHub) PushPacket(pkt *sniffer.Packet) {
	if h == nil || pkt == nil || h.stopped.Load() {
		return
	}
	evt := toPacketEvent(pkt, h.roundResolver)
	h.bufMu.Lock()
	if h.stopped.Load() {
		h.bufMu.Unlock()
		return
	}
	h.buffer = append(h.buffer, evt)
	h.bufMu.Unlock()
}

// PushScoreUpdate buffers a metadata patch for the next broadcast. Unlike a
// generic refresh this lets Traffic update only the affected rows.
func (h *PacketStreamHub) PushScoreUpdate(update sniffer.ScoreUpdate) {
	if h == nil || len(update.PacketIDs) == 0 || h.stopped.Load() {
		return
	}
	h.bufMu.Lock()
	if h.stopped.Load() {
		h.bufMu.Unlock()
		return
	}
	h.scores = append(h.scores, update)
	h.bufMu.Unlock()
}

// Notify signals that packet metadata changed (e.g. backfill).
// Subscribers will get a refresh signal.
func (h *PacketStreamHub) Notify() {
	if h == nil || h.stopped.Load() {
		return
	}
	h.metaDirty.Store(1)
}

func (h *PacketStreamHub) loop() {
	defer close(h.done)
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
	scores := h.scores
	h.buffer = nil
	h.scores = nil
	h.bufMu.Unlock()

	// Send new-packets event if we have any
	if len(packets) > 0 {
		data, err := json.Marshal(packets)
		if err == nil {
			h.broadcast(sseMessage{event: "new-packets", data: data})
		}
	}
	if len(scores) > 0 {
		data, err := json.Marshal(scores)
		if err == nil {
			h.broadcast(sseMessage{event: "score-updates", data: data})
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
	h.stopOnce.Do(func() {
		h.stopped.Store(true)
		close(h.stop)
	})
	<-h.done
	h.bufMu.Lock()
	h.buffer = nil
	h.scores = nil
	h.bufMu.Unlock()
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
		case <-s.packetHub.stop:
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
