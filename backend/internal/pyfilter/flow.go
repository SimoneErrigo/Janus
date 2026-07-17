package pyfilter

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	trackedConnectionTTL  = 5 * time.Minute
	maxTrackedConnections = 4096
	maxRateSamples        = 128
	maxRecentMessages     = 32
	maxTrackedEvents      = 32768
)

// flowTracker is shared by the live manager. Explicit event IDs let the async
// capture of an inline message reuse the exact pre-message snapshot and update
// its final admitted size without double-counting it.
type flowTracker struct {
	mu          sync.Mutex
	connections map[string]*connectionStats
	events      map[string]*trackedRecord
	sequence    uint64
}

type connectionStats struct {
	started, last           time.Time
	messagesIn, messagesOut int64
	bytesIn, bytesOut       int64
	flagsIn, flagsOut       int64
	knownIn, knownOut       int64
	requestTimes            []float64
	responseTimes           []float64
	recent                  []recordedShape
}

type messageShape struct {
	Direction string `json:"direction"`
	Size      string `json:"size"`
	Gap       string `json:"gap"`
	Protocol  string `json:"protocol"`
	Hint      string `json:"hint,omitempty"`
}

type recordedShape struct {
	ID string
	messageShape
}

type trackedFlow struct {
	record     *trackedRecord
	direction  string
	size       int64
	flags      int64
	knownFlags int64
	when       time.Time
	shape      messageShape
}

type trackedRecord struct {
	id, direction           string
	stats                   *connectionStats
	when                    time.Time
	size, flags, knownFlags int64
	shape                   messageShape
	snapshot                map[string]any
	committed, admitted     bool
}

func (t *flowTracker) prepare(raw Flow) (Flow, trackedFlow) {
	now := flowTimestamp(raw)
	flow := canonicalFlow(raw, now)
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.connections == nil {
		t.connections = make(map[string]*connectionStats)
		t.events = make(map[string]*trackedRecord)
	}
	t.expire(now)
	eventID := stringValue(flow["event_id"])
	if eventID == "" {
		t.sequence++
		eventID = fmt.Sprintf("%s/%d/%d", flow["connection_id"], now.UnixNano(), t.sequence)
	}
	flow["event_id"] = eventID
	direction := stringValue(flow["direction"])
	size := int64Value(flow["size"])
	flags := int64Value(flow["flag_count"])
	knownFlags := int64Value(flow["known_flag_count"])
	if existing := t.events[eventID]; existing != nil {
		snapshot := cloneMap(existing.snapshot)
		idle := int64Value(snapshot["idle_ms"])
		shape := messageShape{Direction: direction, Size: sizeBucket(size), Gap: durationBucket(idle), Protocol: stringValue(flow["protocol"]), Hint: decodedHint(flow["decoded"])}
		snapshot["current"] = shape
		flow["connection"] = snapshot
		return flow, trackedFlow{record: existing, direction: direction, size: size, flags: flags, knownFlags: knownFlags, when: now, shape: shape}
	}

	id, _ := flow["connection_id"].(string)
	stats := t.connections[id]
	if stats == nil {
		if len(t.connections) >= maxTrackedConnections {
			t.evictOldest()
		}
		stats = &connectionStats{started: now}
		t.connections[id] = stats
	}

	idle := int64(0)
	if !stats.last.IsZero() {
		idle = max(0, now.Sub(stats.last).Milliseconds())
	}
	age := max(0, now.Sub(stats.started).Milliseconds())
	connection := map[string]any{
		"id":              id,
		"now":             float64(now.UnixNano()) / float64(time.Second),
		"age_ms":          age,
		"idle_ms":         idle,
		"messages":        stats.messagesIn + stats.messagesOut,
		"messages_in":     stats.messagesIn,
		"messages_out":    stats.messagesOut,
		"bytes_in":        stats.bytesIn,
		"bytes_out":       stats.bytesOut,
		"flags_in":        stats.flagsIn,
		"flags_out":       stats.flagsOut,
		"known_flags_in":  stats.knownIn,
		"known_flags_out": stats.knownOut,
		"request_times":   recentSamples(stats.requestTimes, now),
		"response_times":  recentSamples(stats.responseTimes, now),
		"recent":          publicShapes(stats.recent),
	}
	currentShape := messageShape{
		Direction: stringValue(flow["direction"]), Size: sizeBucket(int64Value(flow["size"])),
		Gap: durationBucket(idle), Protocol: stringValue(flow["protocol"]), Hint: decodedHint(flow["decoded"]),
	}
	connection["current"] = currentShape
	flow["connection"] = connection
	if len(t.events) >= maxTrackedEvents {
		t.evictOldestEvent()
	}
	record := &trackedRecord{id: eventID, direction: direction, stats: stats, when: now, size: size, flags: flags, knownFlags: knownFlags, shape: currentShape, snapshot: cloneMap(connection)}
	t.events[eventID] = record
	return flow, trackedFlow{record: record, direction: direction, size: size, flags: flags, knownFlags: knownFlags, when: now, shape: currentShape}
}

// commit records the current message after evaluation. A blocking verdict is
// intentionally not counted, so connection.flags_out means traffic previously
// admitted by the data plane, never the message currently being decided.
func (t *flowTracker) commit(event trackedFlow, admitted bool) {
	if event.record == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	record := event.record
	stats := record.stats
	wasCommitted, wasAdmitted := record.committed, record.admitted
	if record.committed && record.admitted {
		applyCounters(stats, record.direction, -record.size, -record.flags, -record.knownFlags, -1)
		removeSample(stats, record.direction, record.when)
	}
	record.direction, record.size, record.flags, record.knownFlags = event.direction, event.size, event.flags, event.knownFlags
	record.when, record.shape, record.committed, record.admitted = event.when, event.shape, true, admitted
	shapeIndex := -1
	for i := range stats.recent {
		if stats.recent[i].ID == record.id {
			shapeIndex = i
			break
		}
	}
	if !admitted {
		if shapeIndex >= 0 {
			stats.recent = append(stats.recent[:shapeIndex], stats.recent[shapeIndex+1:]...)
		}
		updateLastSample(stats)
		return
	}
	applyCounters(stats, event.direction, event.size, event.flags, event.knownFlags, 1)
	addSample(stats, event.direction, event.when)
	updateLastSample(stats)
	shape := recordedShape{ID: record.id, messageShape: event.shape}
	if shapeIndex >= 0 {
		stats.recent[shapeIndex] = shape
	} else {
		// A delayed async correction may arrive after this event has already
		// fallen out of the 32-shape window. Its aggregate counters still need
		// correction, but re-appending it would make an old message look newest.
		if wasCommitted && wasAdmitted {
			return
		}
		stats.recent = append(stats.recent, shape)
		if len(stats.recent) > maxRecentMessages {
			stats.recent = append([]recordedShape(nil), stats.recent[len(stats.recent)-maxRecentMessages:]...)
		}
	}
}

// forget releases the heavy pre-message snapshot after the final async copy
// has reconciled counters. Until Submit arrives, the record remains available
// to deduplicate the inline and persisted representations of the same event.
func (t *flowTracker) forget(event trackedFlow) {
	if event.record == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.events[event.record.id] == event.record {
		delete(t.events, event.record.id)
	}
}

func applyCounters(stats *connectionStats, direction string, size, flags, known, messages int64) {
	if direction == "response" {
		stats.messagesOut += messages
		stats.bytesOut += size
		stats.flagsOut += flags
		stats.knownOut += known
	} else {
		stats.messagesIn += messages
		stats.bytesIn += size
		stats.flagsIn += flags
		stats.knownIn += known
	}
}

func addSample(stats *connectionStats, direction string, when time.Time) {
	stamp := float64(when.UnixNano()) / float64(time.Second)
	if direction == "response" {
		stats.responseTimes = appendSample(stats.responseTimes, stamp)
	} else {
		stats.requestTimes = appendSample(stats.requestTimes, stamp)
	}
}

func updateLastSample(stats *connectionStats) {
	latest := float64(0)
	if n := len(stats.requestTimes); n > 0 {
		latest = stats.requestTimes[n-1]
	}
	if n := len(stats.responseTimes); n > 0 && stats.responseTimes[n-1] > latest {
		latest = stats.responseTimes[n-1]
	}
	if latest == 0 {
		stats.last = time.Time{}
		return
	}
	stats.last = time.Unix(0, int64(latest*float64(time.Second)))
}

func removeSample(stats *connectionStats, direction string, when time.Time) {
	want := float64(when.UnixNano()) / float64(time.Second)
	samples := &stats.requestTimes
	if direction == "response" {
		samples = &stats.responseTimes
	}
	for i, stamp := range *samples {
		if stamp == want {
			*samples = append((*samples)[:i], (*samples)[i+1:]...)
			return
		}
	}
}

func publicShapes(recent []recordedShape) []messageShape {
	out := make([]messageShape, len(recent))
	for i := range recent {
		out[i] = recent[i].messageShape
	}
	return out
}

func sizeBucket(size int64) string {
	switch {
	case size <= 0:
		return "0"
	case size <= 32:
		return "1-32"
	case size <= 128:
		return "33-128"
	case size <= 512:
		return "129-512"
	case size <= 2048:
		return "513-2k"
	case size <= 8192:
		return "2k-8k"
	default:
		return "8k+"
	}
}

func durationBucket(milliseconds int64) string {
	switch {
	case milliseconds < 10:
		return "<10ms"
	case milliseconds < 50:
		return "10-49ms"
	case milliseconds < 200:
		return "50-199ms"
	case milliseconds < 1000:
		return "200-999ms"
	case milliseconds < 5000:
		return "1-5s"
	default:
		return "5s+"
	}
}

func decodedHint(value any) string {
	decoded, ok := value.(map[string]any)
	if !ok {
		return ""
	}
	for _, key := range []string{"command", "type", "name", "opcode", "method", "topic"} {
		if hint := strings.TrimSpace(stringValue(decoded[key])); hint != "" {
			return boundedHint(key + ":" + hint)
		}
	}
	keys := make([]string, 0, min(4, len(decoded)))
	for key := range decoded {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if len(keys) > 4 {
		keys = keys[:4]
	}
	return boundedHint(strings.Join(keys, ","))
}

func boundedHint(value string) string {
	const maxHintBytes = 96
	if len(value) > maxHintBytes {
		return value[:maxHintBytes]
	}
	return value
}

func (t *flowTracker) expire(now time.Time) {
	cutoff := now.Add(-trackedConnectionTTL)
	for id, stats := range t.connections {
		last := stats.last
		if last.IsZero() {
			last = stats.started
		}
		if last.Before(cutoff) {
			delete(t.connections, id)
		}
	}
	for id, event := range t.events {
		if event.when.Before(cutoff) {
			delete(t.events, id)
		}
	}
}

func (t *flowTracker) evictOldest() {
	var oldestID string
	var oldest time.Time
	var oldestStats *connectionStats
	for id, stats := range t.connections {
		seen := stats.last
		if seen.IsZero() {
			seen = stats.started
		}
		if oldestID == "" || seen.Before(oldest) {
			oldestID, oldest, oldestStats = id, seen, stats
		}
	}
	delete(t.connections, oldestID)
	for id, event := range t.events {
		if event.stats == oldestStats {
			delete(t.events, id)
		}
	}
}

func (t *flowTracker) evictOldestEvent() {
	var oldestID string
	var oldest time.Time
	for id, event := range t.events {
		if oldestID == "" || event.when.Before(oldest) {
			oldestID, oldest = id, event.when
		}
	}
	delete(t.events, oldestID)
}

func appendSample(samples []float64, value float64) []float64 {
	samples = append(samples, value)
	sort.Float64s(samples)
	if len(samples) > maxRateSamples {
		samples = append([]float64(nil), samples[len(samples)-maxRateSamples:]...)
	}
	return samples
}

func cloneMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for key, value := range in {
		switch typed := value.(type) {
		case []float64:
			out[key] = append([]float64(nil), typed...)
		case []messageShape:
			out[key] = append([]messageShape(nil), typed...)
		default:
			out[key] = value
		}
	}
	return out
}

func recentSamples(samples []float64, now time.Time) []float64 {
	cutoff := float64(now.Add(-trackedConnectionTTL).UnixNano()) / float64(time.Second)
	first := sort.Search(len(samples), func(i int) bool { return samples[i] >= cutoff })
	return append([]float64(nil), samples[first:]...)
}

// canonicalFlow is the single wire shape used by every protocol, the async
// capture path and the tester. It clones caller-owned values before queueing or
// handing them to Python, then fills safe defaults for protocol-independent
// scripts.
func canonicalFlow(raw Flow, now time.Time) Flow {
	flow := cloneFlow(raw)
	_, bodyCompleteSupplied := flow["body_complete"]
	defaults := map[string]any{
		"id": int64(0), "service": "", "session": "", "protocol": "",
		"direction": "", "method": "", "url": "", "status": 0, "round": 0,
		"src": "", "dst": "", "sport": 0, "dport": 0,
		"headers": map[string]string{}, "decoded": map[string]any{},
		"body": "", "websocket_opcode": "", "admitted": true, "enforceable": true,
		"flagged": false, "contains_flagid": false, "truncated": false, "body_complete": true,
	}
	for key, value := range defaults {
		if _, ok := flow[key]; !ok || flow[key] == nil {
			flow[key] = value
		}
	}
	if !bodyCompleteSupplied {
		flow["body_complete"] = !boolValue(flow["truncated"])
	}
	if !boolValue(flow["body_complete"]) {
		flow["truncated"] = true
	}

	body := stringValue(flow["body"])
	if bodyB64 := stringValue(flow["body_b64"]); bodyB64 == "" {
		flow["body_b64"] = base64.StdEncoding.EncodeToString([]byte(body))
	} else if decoded, err := base64.StdEncoding.DecodeString(bodyB64); err == nil {
		if _, ok := flow["body"]; !ok || body == "" {
			flow["body"] = string(decoded)
		}
		body = string(decoded)
	}
	flow["size"] = len(body)
	if explicit, ok := numberValue(flow["size_bytes"]); ok {
		flow["size"] = int64(explicit)
	}

	matchedIDs := stringSlice(flow["matched_flagids"])
	flow["matched_flagids"] = matchedIDs
	bodyFlags := nonNegativeInt(flow["flag_count_body"])
	headerFlags := nonNegativeInt(flow["flag_count_headers"])
	urlFlags := nonNegativeInt(flow["flag_count_url"])
	totalFlags := bodyFlags + headerFlags + urlFlags
	if explicit := nonNegativeInt(flow["flag_count"]); explicit > totalFlags {
		totalFlags = explicit
	}
	if totalFlags == 0 && boolValue(flow["flagged"]) {
		totalFlags = 1
		if bodyFlags+headerFlags+urlFlags == 0 {
			bodyFlags = 1 // legacy packets only stored a boolean; retain a safe lower bound
		}
	}
	known := int64(len(matchedIDs))
	if explicit := nonNegativeInt(flow["known_flag_count"]); explicit > known {
		known = explicit
	}
	if known == 0 && boolValue(flow["contains_flagid"]) {
		known = 1
	}
	flow["flag_count"], flow["known_flag_count"] = totalFlags, known
	flow["flag_count_body"], flow["flag_count_headers"], flow["flag_count_url"] = bodyFlags, headerFlags, urlFlags
	flow["flags"] = map[string]any{
		"count": totalFlags, "known_count": known, "body_count": bodyFlags,
		"header_count": headerFlags, "url_count": urlFlags, "matched_ids": matchedIDs,
	}

	if _, ok := flow["timestamp"]; !ok || int64Value(flow["timestamp"]) <= 0 {
		flow["timestamp"] = now.Unix()
	}
	flow["connection_id"] = connectionID(flow)
	return flow
}

func cloneFlow(raw Flow) Flow {
	out := make(Flow, len(raw)+8)
	for key, value := range raw {
		switch typed := value.(type) {
		case map[string]string:
			cloned := make(map[string]string, len(typed))
			for k, v := range typed {
				cloned[k] = v
			}
			out[key] = cloned
		case map[string]any:
			cloned := make(map[string]any, len(typed))
			for k, v := range typed {
				cloned[k] = v
			}
			out[key] = cloned
		case []string:
			out[key] = append([]string(nil), typed...)
		case []byte:
			out[key] = append([]byte(nil), typed...)
		default:
			out[key] = value
		}
	}
	return out
}

func connectionID(flow Flow) string {
	service := stringValue(flow["service"])
	if session := stringValue(flow["session"]); session != "" {
		return service + "/session/" + session
	}
	a := fmt.Sprintf("%s:%d", stringValue(flow["src"]), int64Value(flow["sport"]))
	b := fmt.Sprintf("%s:%d", stringValue(flow["dst"]), int64Value(flow["dport"]))
	if a > b {
		a, b = b, a
	}
	return service + "/endpoints/" + a + "-" + b
}

func flowTimestamp(flow Flow) time.Time {
	if value, ok := numberValue(flow["timestamp"]); ok && value > 0 {
		return time.Unix(0, int64(value*float64(time.Second)))
	}
	if text := stringValue(flow["timestamp"]); text != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, text); err == nil {
			return parsed
		}
	}
	return time.Now()
}

func numberValue(value any) (float64, bool) {
	switch typed := value.(type) {
	case int:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
	case json.Number:
		v, err := typed.Float64()
		return v, err == nil
	case string:
		v, err := strconv.ParseFloat(typed, 64)
		return v, err == nil
	default:
		return 0, false
	}
}

func int64Value(value any) int64     { n, _ := numberValue(value); return int64(n) }
func nonNegativeInt(value any) int64 { return max(0, int64Value(value)) }
func stringValue(value any) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return text
	}
	return fmt.Sprint(value)
}
func boolValue(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		v, _ := strconv.ParseBool(strings.TrimSpace(typed))
		return v
	default:
		return int64Value(value) != 0
	}
}
func stringSlice(value any) []string {
	var values []string
	switch typed := value.(type) {
	case []string:
		values = typed
	case []any:
		values = make([]string, 0, len(typed))
		for _, item := range typed {
			if text := stringValue(item); text != "" {
				values = append(values, text)
			}
		}
	default:
		return []string{}
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
