package flagids

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	roundFetchGrace      = time.Second
	roundCatchupInterval = 2 * time.Second
	maxFetchErrorBackoff = time.Minute
)

// Poller periodically fetches flag IDs from the competition API.
type Poller struct {
	mu       sync.RWMutex
	apiURL   string
	teamID   string
	interval time.Duration
	enabled  bool
	format   string // competition format (e.g. "cyberchallenge")

	// Round-aware storage: roundNum -> serviceName -> []flagIdValue
	roundFlags       map[int]map[string][]string
	currentRound     int
	matcher          *Matcher // Aho-Corasick automaton for O(text_length) matching
	lastSnapshotHash uint64   // hash of roundFlags snapshot, used to skip no-op refreshes

	// Competition timing
	roundDuration    time.Duration // duration of a single round
	competitionStart time.Time     // when the competition started (for round calculation)
	keepRounds       int           // how many rounds of flagIds to keep (default 5)

	// Legacy flat view (backward compat with GetFlagIDs / GetAllValues)
	flagIDs map[string][]string

	// Reverse map: flagIDValue -> descKey (e.g., "8b026611-..." -> "answer_id")
	valueKeyMap map[string]string

	lastFetch   time.Time
	lastError   string
	fetchErrors int

	// Callback after successful fetch with the new current round number
	onFetch func(currentRound int)

	// Loop lifecycle. Fetches are serialized so a manual refresh cannot race a
	// scheduled one; generations keep an obsolete in-flight response from
	// overwriting a newer configuration.
	lifecycleMu sync.Mutex
	cancel      context.CancelFunc
	running     bool
	generation  atomic.Uint64
	loopWG      sync.WaitGroup
	fetchMu     sync.Mutex
}

// PollerConfig holds the configurable fields for the poller.
type PollerConfig struct {
	Enabled          bool   `json:"enabled"`
	APIURL           string `json:"api_url"`
	TeamID           string `json:"team_id"`
	IntervalSec      int    `json:"poll_interval_seconds"`
	Format           string `json:"format"`
	RoundDurationSec int    `json:"round_duration_seconds,omitempty"`
	CompetitionStart string `json:"competition_start,omitempty"` // RFC3339
	KeepRounds       int    `json:"keep_rounds,omitempty"`
}

// Status holds the poller's current state.
type Status struct {
	Enabled          bool      `json:"enabled"`
	APIURL           string    `json:"api_url"`
	TeamID           string    `json:"team_id"`
	Format           string    `json:"format"`
	LastFetch        time.Time `json:"last_fetch"`
	NextFetch        time.Time `json:"next_fetch"`
	LastError        string    `json:"last_error,omitempty"`
	PollInterval     int       `json:"poll_interval_seconds"`
	CurrentRound     int       `json:"current_round"`
	ClockRound       int       `json:"clock_round"`
	FlagIDRound      int       `json:"flagids_round"`
	KeepRounds       int       `json:"keep_rounds"`
	RoundDurationSec int       `json:"round_duration_seconds,omitempty"`
	CompetitionStart string    `json:"competition_start,omitempty"` // RFC3339
}

// NewPoller creates a flag ID poller.
func NewPoller(apiURL, teamID string, intervalSec int, enabled bool, format string, roundDurationSec int, competitionStart time.Time, keepRounds int) *Poller {
	if intervalSec <= 0 {
		intervalSec = 5
	}
	if roundDurationSec <= 0 {
		roundDurationSec = 120 // default 2 minutes
	}
	if keepRounds <= 0 {
		keepRounds = 5
	}
	if format == "" {
		format = "cyberchallenge"
	}
	format = strings.ToLower(format)
	return &Poller{
		apiURL:           apiURL,
		teamID:           teamID,
		interval:         time.Duration(intervalSec) * time.Second,
		enabled:          enabled,
		format:           format,
		roundFlags:       make(map[int]map[string][]string),
		flagIDs:          make(map[string][]string),
		roundDuration:    time.Duration(roundDurationSec) * time.Second,
		competitionStart: competitionStart,
		keepRounds:       keepRounds,
	}
}

// Start begins the polling loop.
func (p *Poller) Start() {
	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()
	if p.running {
		return
	}
	p.mu.RLock()
	enabled, apiURL := p.enabled, p.apiURL
	teamID, interval, format := p.teamID, p.interval, p.format
	roundDuration, keepRounds := p.roundDuration, p.keepRounds
	p.mu.RUnlock()
	if !enabled || apiURL == "" {
		log.Println("Flag ID poller disabled")
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.running = true
	gen := p.generation.Add(1)
	p.loopWG.Add(1)
	go p.loop(ctx, gen)
	log.Printf("Flag ID poller started (url=%s, team=%s, interval=%s, format=%s, round_duration=%s, keep_rounds=%d)",
		apiURL, teamID, interval, format, roundDuration, keepRounds)
}

// Stop signals the poller to exit.
func (p *Poller) Stop() {
	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()
	if p.running {
		p.cancel()
		p.running = false
	}
	p.generation.Add(1)
	// Keep lifecycle operations serialized until the old generation is fully
	// gone. Otherwise Reconfigure could add a replacement loop concurrently
	// with this Wait and Stop could return while that loop was still running.
	p.loopWG.Wait()
}

// Reconfigure updates the poller config and restarts if enabled.
func (p *Poller) Reconfigure(cfg PollerConfig) {
	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()
	if p.running {
		p.cancel()
		p.running = false
	}
	gen := p.generation.Add(1)
	// Wait for the cancelled generation (including its backfill callback) before
	// publishing a new identity. This prevents old results from overlapping a
	// reconfigured poller.
	p.loopWG.Wait()

	p.mu.Lock()
	identityChanged := p.apiURL != cfg.APIURL || p.teamID != cfg.TeamID ||
		(cfg.Format != "" && p.format != strings.ToLower(cfg.Format)) ||
		(cfg.RoundDurationSec > 0 && p.roundDuration != time.Duration(cfg.RoundDurationSec)*time.Second)
	p.apiURL = cfg.APIURL
	p.teamID = cfg.TeamID
	if cfg.IntervalSec > 0 {
		p.interval = time.Duration(cfg.IntervalSec) * time.Second
	}
	if cfg.Format != "" {
		p.format = strings.ToLower(cfg.Format)
	}
	if cfg.RoundDurationSec > 0 {
		p.roundDuration = time.Duration(cfg.RoundDurationSec) * time.Second
	}
	if cfg.CompetitionStart == "" {
		identityChanged = identityChanged || !p.competitionStart.IsZero()
		p.competitionStart = time.Time{}
	} else {
		if t, err := time.Parse(time.RFC3339, cfg.CompetitionStart); err == nil {
			identityChanged = identityChanged || !p.competitionStart.Equal(t)
			p.competitionStart = t
		}
	}
	if cfg.KeepRounds > 0 {
		p.keepRounds = cfg.KeepRounds
	}
	p.enabled = cfg.Enabled
	if identityChanged {
		p.roundFlags = make(map[int]map[string][]string)
		p.flagIDs = make(map[string][]string)
		p.valueKeyMap = nil
		p.matcher = nil
		p.currentRound = 0
		p.lastSnapshotHash = 0
		p.fetchErrors = 0
	}
	p.mu.Unlock()

	if cfg.Enabled && cfg.APIURL != "" {
		ctx, cancel := context.WithCancel(context.Background())
		p.cancel = cancel
		p.running = true
		p.loopWG.Add(1)
		go p.loop(ctx, gen)
		log.Printf("Flag ID poller reconfigured (url=%s, team=%s, interval=%s, format=%s)", cfg.APIURL, cfg.TeamID, p.interval, p.format)
	} else {
		log.Println("Flag ID poller disabled via reconfigure")
	}
}

// GetConfig returns the current poller configuration.
func (p *Poller) GetConfig() PollerConfig {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var startStr string
	if !p.competitionStart.IsZero() {
		startStr = p.competitionStart.Format(time.RFC3339)
	}
	return PollerConfig{
		Enabled:          p.enabled,
		APIURL:           p.apiURL,
		TeamID:           p.teamID,
		IntervalSec:      int(p.interval.Seconds()),
		Format:           p.format,
		RoundDurationSec: int(p.roundDuration.Seconds()),
		CompetitionStart: startStr,
		KeepRounds:       p.keepRounds,
	}
}

// GetFlagIDs returns the current flag ID map (service_name -> values).
func (p *Poller) GetFlagIDs() map[string][]string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	cp := make(map[string][]string, len(p.flagIDs))
	for k, v := range p.flagIDs {
		vals := make([]string, len(v))
		copy(vals, v)
		cp[k] = vals
	}
	return cp
}

// GetAllValues returns all flag ID values flattened into a single list.
func (p *Poller) GetAllValues() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var all []string
	for _, vals := range p.flagIDs {
		all = append(all, vals...)
	}
	return all
}

// GetStatus returns the poller's current status.
func (p *Poller) GetStatus() Status {
	p.mu.RLock()
	defer p.mu.RUnlock()

	now := time.Now()
	var nextFetch time.Time
	if !p.lastFetch.IsZero() {
		nextFetch = now.Add(p.nextFetchDelayLocked(now))
	}

	var startStr string
	if !p.competitionStart.IsZero() {
		startStr = p.competitionStart.Format(time.RFC3339)
	}

	clockRound := p.roundForTimeLocked(now)

	return Status{
		Enabled:          p.enabled,
		APIURL:           p.apiURL,
		TeamID:           p.teamID,
		Format:           p.format,
		LastFetch:        p.lastFetch,
		NextFetch:        nextFetch,
		LastError:        p.lastError,
		PollInterval:     int(p.interval.Seconds()),
		CurrentRound:     p.currentRound,
		ClockRound:       clockRound,
		FlagIDRound:      p.currentRound,
		KeepRounds:       p.keepRounds,
		RoundDurationSec: int(p.roundDuration.Seconds()),
		CompetitionStart: startStr,
	}
}

// IsEnabled returns whether the poller is active.
func (p *Poller) IsEnabled() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.enabled
}

// SetOnFetch registers a callback invoked after each successful flag ID fetch
// with the current round number.
func (p *Poller) SetOnFetch(fn func(currentRound int)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.onFetch = fn
}

// FetchNow triggers an immediate flag ID fetch (blocking).
func (p *Poller) FetchNow() {
	p.fetch(context.Background(), p.generation.Load())
}

// CurrentRound returns the latest round number known to the poller.
func (p *Poller) CurrentRound() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.currentRound
}

// RoundForTime computes the scoreboard round that a given timestamp falls
// into, using competition_start + round_duration. Returns 0 when the poller
// has not been configured with both fields, or when the timestamp predates
// the competition start. This is used by the API layer to annotate packets
// with their round at serve time so the frontend doesn't need to do its own
// date math or poll for round transitions.
func (p *Poller) RoundForTime(t time.Time) int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.roundForTimeLocked(t)
}

func (p *Poller) roundForTimeLocked(t time.Time) int {
	if p.competitionStart.IsZero() || p.roundDuration <= 0 {
		return 0
	}
	if t.Before(p.competitionStart) {
		return 0
	}
	return int(t.Sub(p.competitionStart)/p.roundDuration) + 1
}

// RoundBounds returns the [start, end) time interval of the given scoreboard
// round, computed from competitionStart + roundDuration. The third return
// value is false when the poller has not been configured with both fields or
// when round is non-positive.
func (p *Poller) RoundBounds(round int) (time.Time, time.Time, bool) {
	if round <= 0 {
		return time.Time{}, time.Time{}, false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.competitionStart.IsZero() || p.roundDuration <= 0 {
		return time.Time{}, time.Time{}, false
	}
	start := p.competitionStart.Add(time.Duration(round-1) * p.roundDuration)
	end := start.Add(p.roundDuration)
	return start, end, true
}

func (p *Poller) nextFetchDelayLocked(now time.Time) time.Duration {
	delay := p.interval
	clockRound := p.roundForTimeLocked(now)
	if clockRound > p.currentRound {
		delay = minDuration(delay, roundCatchupInterval)
	}
	if !p.competitionStart.IsZero() && p.roundDuration > 0 && !now.Before(p.competitionStart) {
		elapsed := now.Sub(p.competitionStart)
		nextBoundary := p.competitionStart.Add((elapsed/p.roundDuration + 1) * p.roundDuration).Add(roundFetchGrace)
		if untilBoundary := nextBoundary.Sub(now); untilBoundary > 0 {
			delay = minDuration(delay, untilBoundary)
		}
	}
	if p.fetchErrors > 0 {
		shift := p.fetchErrors - 1
		if shift > 5 {
			shift = 5
		}
		retry := roundCatchupInterval * time.Duration(1<<shift)
		if retry > maxFetchErrorBackoff {
			retry = maxFetchErrorBackoff
		}
		if delay < retry {
			delay = retry
		}
	}
	if delay <= 0 {
		return roundCatchupInterval
	}
	return delay
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// ContainsFlagID checks if the given text contains any current flag ID value.
func (p *Poller) ContainsFlagID(text string) bool {
	p.mu.RLock()
	m := p.matcher
	p.mu.RUnlock()
	if m == nil {
		return false
	}
	return m.ContainsAny(text)
}

// FindMatchingFlagIDs returns all flag ID matches found in the given text,
// each tagged with the round number it belongs to.
func (p *Poller) FindMatchingFlagIDs(text string) []FlagMatch {
	if text == "" {
		return nil
	}
	p.mu.RLock()
	m := p.matcher
	p.mu.RUnlock()
	if m == nil {
		return nil
	}
	return m.FindMatches(text)
}

func (p *Poller) loop(ctx context.Context, generation uint64) {
	defer p.loopWG.Done()
	p.fetch(ctx, generation)

	for {
		p.mu.RLock()
		delay := p.nextFetchDelayLocked(time.Now())
		p.mu.RUnlock()
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			p.fetch(ctx, generation)
		}
	}
}

func (p *Poller) fetch(ctx context.Context, generation uint64) {
	p.fetchMu.Lock()
	defer p.fetchMu.Unlock()
	if generation != p.generation.Load() {
		return
	}
	p.mu.RLock()
	apiURL := p.apiURL
	teamID := p.teamID
	format := p.format
	roundDuration := p.roundDuration
	competitionStart := p.competitionStart
	keepRounds := p.keepRounds
	p.mu.RUnlock()

	fetchURL, err := url.Parse(apiURL)
	if err != nil || fetchURL.Scheme == "" || fetchURL.Host == "" {
		p.setFetchError(generation, fmt.Sprintf("invalid API URL %q", apiURL))
		return
	}
	// ForcAD and ENOWARS return every team's flag IDs in one document, so the
	// local team key is resolved client-side. Other formats use the query param
	// to scope the request to one team.
	if teamID != "" && format != "forcad" && format != "enowars" {
		query := fetchURL.Query()
		query.Set("team", teamID)
		fetchURL.RawQuery = query.Encode()
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fetchURL.String(), nil)
	if err != nil {
		p.setFetchError(generation, fmt.Sprintf("request error: %v", err))
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() == nil {
			p.setFetchError(generation, fmt.Sprintf("fetch error: %v", err))
		}
		return
	}
	defer resp.Body.Close()

	const maxResponseBytes = 32 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		p.setFetchError(generation, fmt.Sprintf("read error: %v", err))
		return
	}
	if len(body) > maxResponseBytes {
		p.setFetchError(generation, "response exceeds 32 MiB")
		return
	}

	if resp.StatusCode != http.StatusOK {
		message := strings.TrimSpace(string(body))
		if len(message) > 512 {
			message = message[:512]
		}
		p.setFetchError(generation, fmt.Sprintf("HTTP %d: %s", resp.StatusCode, message))
		return
	}

	// Parse with round awareness
	var roundFlags map[int]map[string][]string
	switch format {
	case "cyberchallenge":
		roundFlags, err = parseCyberChallengeRounded(body)
	case "saarctf":
		roundFlags, err = parseSaarCTFRounded(body, teamID)
	case "faustctf":
		roundFlags, err = parseFaustCTFRounded(body, teamID, roundDuration, competitionStart)
	case "forcad":
		roundFlags, err = parseForcADRounded(body, teamID, roundDuration, competitionStart)
	case "enowars":
		roundFlags, err = parseENOWARSRounded(body, teamID)
	default:
		roundFlags, err = parseCyberChallengeRounded(body)
	}

	if err != nil {
		p.setFetchError(generation, fmt.Sprintf("parse error: %v", err))
		return
	}
	if format == "enowars" {
		freshRound := highestRound(roundFlags)
		if countRoundFlagValues(roundFlags) == 0 {
			p.setFetchError(generation, "ENOWARS response contains no usable attack-info for the configured team")
			return
		}
		p.mu.RLock()
		previous := cloneRoundFlags(p.roundFlags)
		previousRound := p.currentRound
		p.mu.RUnlock()
		if previousRound > 0 && freshRound < previousRound {
			p.setFetchError(generation, fmt.Sprintf("stale ENOWARS response: latest round %d, keeping round %d", freshRound, previousRound))
			return
		}
		// attack.json may omit a temporarily unavailable service. Keep missing
		// service/round entries from the last valid snapshot; fresh entries win.
		roundFlags = mergeRoundFlags(previous, roundFlags)
	}

	// Determine current round (max round number seen)
	maxRound := highestRound(roundFlags)

	// Prune old rounds: keep only the last keepRounds rounds
	if maxRound > 0 {
		cutoff := maxRound - keepRounds + 1
		for r := range roundFlags {
			if r < cutoff {
				delete(roundFlags, r)
			}
		}
	}

	// Compute a deterministic snapshot hash before rebuilding matcher.
	// If unchanged, skip matcher rebuild and avoid triggering backfill.
	snapshotHash := hashRoundFlags(roundFlags)
	p.mu.RLock()
	prevHash := p.lastSnapshotHash
	p.mu.RUnlock()
	if snapshotHash == prevHash {
		if generation != p.generation.Load() {
			return
		}
		p.mu.Lock()
		p.lastFetch = time.Now()
		p.lastError = ""
		p.fetchErrors = 0
		p.mu.Unlock()
		log.Printf("Flag IDs unchanged: skipping matcher rebuild/backfill (round=%d)", maxRound)
		return
	}

	// Build Aho-Corasick automaton from all active round flagIds
	matcher := BuildMatcher(roundFlags)

	// Flatten into legacy map for backward compat (GetFlagIDs, API responses)
	flatFlagIDs := flattenRoundFlags(roundFlags)

	// Build reverse map: flagIDValue -> descKey (for exploit generator)
	// Only CyberChallenge format carries a stable "description key" mapping.
	var vkm map[string]string
	if format == "cyberchallenge" {
		vkm = parseValueKeyMap(body)
	}

	if generation != p.generation.Load() {
		return
	}
	p.mu.Lock()
	p.roundFlags = roundFlags
	p.currentRound = maxRound
	p.matcher = matcher
	p.lastSnapshotHash = snapshotHash
	p.flagIDs = flatFlagIDs
	p.valueKeyMap = vkm
	p.lastFetch = time.Now()
	p.lastError = ""
	p.fetchErrors = 0
	p.mu.Unlock()

	total := 0
	for _, v := range flatFlagIDs {
		total += len(v)
	}
	log.Printf("Flag IDs refreshed: %d services, %d values, round=%d, AC patterns=%d",
		len(flatFlagIDs), total, maxRound, matcher.PatternCount())

	// Notify callback (triggers smart backfill)
	p.mu.RLock()
	onFetch := p.onFetch
	curRound := p.currentRound
	p.mu.RUnlock()
	if onFetch != nil {
		onFetch(curRound)
	}
}

func (p *Poller) setFetchError(generation uint64, message string) {
	if generation != p.generation.Load() {
		return
	}
	p.mu.Lock()
	p.lastError = message
	p.lastFetch = time.Now()
	p.fetchErrors++
	failures := p.fetchErrors
	p.mu.Unlock()
	// Log the first error and then exponentially sparse repetitions. This keeps
	// a pre-game 404 or temporary outage from drowning the useful proxy logs.
	if failures == 1 || failures&(failures-1) == 0 {
		log.Printf("Flag ID fetch degraded (%d consecutive): %s", failures, message)
	}
}

func highestRound(roundFlags map[int]map[string][]string) int {
	maxRound := 0
	for round := range roundFlags {
		if round > maxRound {
			maxRound = round
		}
	}
	return maxRound
}

func countRoundFlagValues(roundFlags map[int]map[string][]string) int {
	total := 0
	for _, services := range roundFlags {
		for _, values := range services {
			total += len(values)
		}
	}
	return total
}

func cloneRoundFlags(source map[int]map[string][]string) map[int]map[string][]string {
	clone := make(map[int]map[string][]string, len(source))
	for round, services := range source {
		clone[round] = make(map[string][]string, len(services))
		for service, values := range services {
			clone[round][service] = append([]string(nil), values...)
		}
	}
	return clone
}

func mergeRoundFlags(previous, fresh map[int]map[string][]string) map[int]map[string][]string {
	merged := cloneRoundFlags(previous)
	for round, services := range fresh {
		if merged[round] == nil {
			merged[round] = make(map[string][]string)
		}
		for service, values := range services {
			merged[round][service] = append([]string(nil), values...)
		}
	}
	return merged
}

func hashRoundFlags(roundFlags map[int]map[string][]string) uint64 {
	h := fnv.New64a()

	rounds := make([]int, 0, len(roundFlags))
	for r := range roundFlags {
		rounds = append(rounds, r)
	}
	sort.Ints(rounds)

	for _, r := range rounds {
		_, _ = h.Write([]byte("r:"))
		_, _ = h.Write([]byte(strconv.Itoa(r)))
		_, _ = h.Write([]byte(";"))

		services := roundFlags[r]
		svcNames := make([]string, 0, len(services))
		for svc := range services {
			svcNames = append(svcNames, svc)
		}
		sort.Strings(svcNames)

		for _, svc := range svcNames {
			_, _ = h.Write([]byte("s:"))
			_, _ = h.Write([]byte(svc))
			_, _ = h.Write([]byte(";"))

			vals := append([]string(nil), services[svc]...)
			sort.Strings(vals)
			for _, v := range vals {
				_, _ = h.Write([]byte("v:"))
				_, _ = h.Write([]byte(v))
				_, _ = h.Write([]byte(";"))
			}
		}
	}
	return h.Sum64()
}

// flattenRoundFlags merges all rounds into a flat service -> []values map.
func flattenRoundFlags(roundFlags map[int]map[string][]string) map[string][]string {
	flat := make(map[string][]string)
	seen := make(map[string]map[string]bool) // service -> value -> seen
	for _, services := range roundFlags {
		for svc, vals := range services {
			if seen[svc] == nil {
				seen[svc] = make(map[string]bool)
			}
			for _, v := range vals {
				if !seen[svc][v] {
					seen[svc][v] = true
					flat[svc] = append(flat[svc], v)
				}
			}
		}
	}
	return flat
}

// GetValueKeyMap returns a copy of the reverse map: flagIDValue -> descKey.
// Example: "8b026611-..." -> "answer_id"
func (p *Poller) GetValueKeyMap() map[string]string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	cp := make(map[string]string, len(p.valueKeyMap))
	for k, v := range p.valueKeyMap {
		cp[k] = v
	}
	return cp
}

// parseValueKeyMap extracts a reverse map (flagIDValue -> descKey) from the raw API JSON.
func parseValueKeyMap(body []byte) map[string]string {
	var raw map[string]map[string]map[string]map[string]string
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil
	}
	result := make(map[string]string)
	for _, teams := range raw {
		for _, rounds := range teams {
			for _, descs := range rounds {
				for descKey, val := range descs {
					if val != "" {
						result[val] = descKey
					}
				}
			}
		}
	}
	return result
}

// parseCyberChallengeRounded parses the CyberChallenge flag ID format preserving round numbers:
// { "service_name": { "team_id": { "round_number": { "desc_key": "flag_id_value" } } } }
// Returns: roundNum -> serviceName -> []flagIdValue
func parseCyberChallengeRounded(body []byte) (map[int]map[string][]string, error) {
	// Use json.RawMessage at the leaf so we can accept strings, numbers,
	// booleans, or arrays/objects (some challenges expose numeric user IDs
	// or list-valued flag IDs). Each value is coerced to its string form.
	var raw map[string]map[string]map[string]map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	result := make(map[int]map[string][]string)
	for serviceName, teams := range raw {
		for _, rounds := range teams {
			roundNums := make([]string, 0, len(rounds))
			for r := range rounds {
				roundNums = append(roundNums, r)
			}
			sort.Strings(roundNums)

			for _, roundStr := range roundNums {
				descs := rounds[roundStr]
				roundNum, err := strconv.Atoi(roundStr)
				if err != nil {
					continue
				}
				if result[roundNum] == nil {
					result[roundNum] = make(map[string][]string)
				}
				seen := make(map[string]bool)
				for _, raw := range descs {
					for _, val := range flattenRawToStrings(raw) {
						if val != "" && !seen[val] {
							seen[val] = true
							result[roundNum][serviceName] = append(result[roundNum][serviceName], val)
						}
					}
				}
			}
		}
	}
	return result, nil
}

// flattenRawToStrings converts a JSON value into one or more string forms.
// Strings are returned as-is; numbers/bools are stringified; arrays and
// objects are walked recursively so list-valued or nested flag IDs are
// not silently dropped.
func flattenRawToStrings(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	switch trimmed[0] {
	case '"':
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil
		}
		return []string{s}
	case '[':
		var arr []json.RawMessage
		if err := json.Unmarshal(raw, &arr); err != nil {
			return nil
		}
		out := make([]string, 0, len(arr))
		for _, item := range arr {
			out = append(out, flattenRawToStrings(item)...)
		}
		return out
	case '{':
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err != nil {
			return nil
		}
		out := make([]string, 0, len(obj))
		for _, item := range obj {
			out = append(out, flattenRawToStrings(item)...)
		}
		return out
	default:
		// number, true, false → use the literal token
		return []string{trimmed}
	}
}

// parseSaarCTFRounded parses saarCTF's attack.json format:
//
//	{
//	  "teams": [ { "id": 1, "ip": "10.32.1.2", ... }, ... ],
//	  "flag_ids": {
//	    "service_1": {
//	      "10.32.1.2": { "15": ["u1","u2"], "16": "u3" }
//	    }
//	  }
//	}
//
// teamID is interpreted as the numeric team id (from teams[].id). If teams are missing,
// it falls back to using teamID as the map key under flag_ids (rare setups).
func parseSaarCTFRounded(body []byte, teamID string) (map[int]map[string][]string, error) {
	type saarTeam struct {
		ID int    `json:"id"`
		IP string `json:"ip"`
	}
	var raw struct {
		Teams   []saarTeam                                       `json:"teams"`
		FlagIDs map[string]map[string]map[string]json.RawMessage `json:"flag_ids"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	targetKey := ""
	if teamID != "" {
		if n, err := strconv.Atoi(teamID); err == nil {
			for _, t := range raw.Teams {
				if t.ID == n && t.IP != "" {
					targetKey = t.IP
					break
				}
			}
		}
	}
	if targetKey == "" && teamID != "" {
		// Fallback (in case the API keys by team id instead of IP)
		targetKey = teamID
	}

	result := make(map[int]map[string][]string)
	for serviceName, perKey := range raw.FlagIDs {
		rounds, ok := perKey[targetKey]
		if !ok {
			continue
		}
		for roundStr, msg := range rounds {
			roundNum, err := strconv.Atoi(roundStr)
			if err != nil {
				continue
			}
			if result[roundNum] == nil {
				result[roundNum] = make(map[string][]string)
			}

			// Values can be either a string or an array of strings
			var one string
			if err := json.Unmarshal(msg, &one); err == nil {
				if one != "" {
					result[roundNum][serviceName] = append(result[roundNum][serviceName], one)
				}
				continue
			}
			var many []string
			if err := json.Unmarshal(msg, &many); err == nil {
				for _, v := range many {
					if v != "" {
						result[roundNum][serviceName] = append(result[roundNum][serviceName], v)
					}
				}
			}
		}
	}
	return result, nil
}

// parseENOWARSRounded parses ENOWARS attack-info responses:
//
//	{
//	  "availableTeams": ["10.1.52.1"],
//	  "services": {
//	    "service_1": {
//	      "10.1.52.1": { "7": [["user73"]], "8": [["user96"]] }
//	    }
//	  }
//	}
//
// The configured team can be its full IP or the numeric team component used
// by the standard 10.1.<team>.1 addressing scheme.
func parseENOWARSRounded(body []byte, teamID string) (map[int]map[string][]string, error) {
	var raw struct {
		Services map[string]map[string]map[string]json.RawMessage `json:"services"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	if raw.Services == nil {
		return nil, fmt.Errorf("ENOWARS response is missing services")
	}

	keys := make(map[string]struct{})
	for _, perTeam := range raw.Services {
		for key := range perTeam {
			keys[key] = struct{}{}
		}
	}
	targetKey := resolveENOWARSTeamKey(teamID, keys)
	result := make(map[int]map[string][]string)
	if targetKey == "" {
		return nil, fmt.Errorf("configured ENOWARS team %q is not present in attack-info", teamID)
	}

	for serviceName, perTeam := range raw.Services {
		for roundStr, value := range perTeam[targetKey] {
			roundNum, err := strconv.Atoi(roundStr)
			if err != nil || roundNum <= 0 {
				continue
			}
			if result[roundNum] == nil {
				result[roundNum] = make(map[string][]string)
			}
			seen := make(map[string]bool)
			appendValue := func(item string) {
				if item != "" && !seen[item] {
					seen[item] = true
					result[roundNum][serviceName] = append(result[roundNum][serviceName], item)
				}
			}
			for _, item := range flattenRawToStrings(value) {
				appendValue(item)
				for _, alternate := range expandForcADValue(item) {
					appendValue(alternate)
				}
			}
		}
	}
	return result, nil
}

func resolveENOWARSTeamKey(teamID string, keys map[string]struct{}) string {
	if _, ok := keys[teamID]; ok {
		return teamID
	}
	if _, err := strconv.Atoi(teamID); err == nil {
		var matches []string
		for key := range keys {
			parts := strings.Split(key, ".")
			if len(parts) == 4 && parts[2] == teamID {
				matches = append(matches, key)
			}
		}
		if len(matches) == 1 {
			return matches[0]
		}
	}
	return resolveForcADTeamKey(teamID, keys)
}

// parseFaustCTFRounded parses FaustCTF's teams.json style:
//
//	{
//	  "teams": [123, 456, ...],
//	  "flag_ids": { "service1": { "123": ["a","b"], "789": ["x","y"] } }
//	}
//
// The API has no round numbers, so all values are assigned to the "current round"
// computed from competitionStart/roundDuration when available, otherwise round=1.
func parseFaustCTFRounded(body []byte, teamID string, roundDuration time.Duration, competitionStart time.Time) (map[int]map[string][]string, error) {
	var raw struct {
		FlagIDs map[string]map[string][]string `json:"flag_ids"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	roundNum := 1
	if !competitionStart.IsZero() && roundDuration > 0 {
		elapsed := time.Since(competitionStart)
		if elapsed >= 0 {
			roundNum = int(elapsed/roundDuration) + 1
			if roundNum < 1 {
				roundNum = 1
			}
		}
	}

	result := make(map[int]map[string][]string)
	result[roundNum] = make(map[string][]string)
	if teamID == "" {
		return result, nil
	}

	for serviceName, perTeam := range raw.FlagIDs {
		vals := perTeam[teamID]
		if len(vals) == 0 {
			continue
		}
		for _, v := range vals {
			if v != "" {
				result[roundNum][serviceName] = append(result[roundNum][serviceName], v)
			}
		}
	}
	return result, nil
}

// parseForcADRounded parses ForcAD's flag ID format:
// { "service_name": { "team_ip": ["value1", "value2", ...] } }
//
// teamID may be one of:
//   - the team's full IP (e.g. "10.0.0.3")
//   - a numeric team number (e.g. "3") — resolved against the last octet of the
//     IP keys present in the API response. If no last-octet match exists, any
//     octet match is accepted as long as it's unambiguous.
//   - any substring that uniquely identifies a team key.
//
// This way each team only needs to set OUR_TEAM_ID=<their number> and the
// poller figures out which IP key to read.
//
// Values are strings; some services (e.g. easyblog2) return JSON-encoded
// objects as strings — we flatten those into their inner leaf values so the
// Aho-Corasick matcher can hit the actual identifiers in network traffic.
//
// No round numbers in the API, so the current round is computed from
// competition timing.
func parseForcADRounded(body []byte, teamID string, roundDuration time.Duration, competitionStart time.Time) (map[int]map[string][]string, error) {
	// Accept arrays of any JSON value (string, object, number) at the leaf.
	var raw map[string]map[string][]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	roundNum := 1
	if !competitionStart.IsZero() && roundDuration > 0 {
		elapsed := time.Since(competitionStart)
		if elapsed >= 0 {
			roundNum = int(elapsed/roundDuration) + 1
			if roundNum < 1 {
				roundNum = 1
			}
		}
	}

	result := make(map[int]map[string][]string)
	result[roundNum] = make(map[string][]string)
	if teamID == "" {
		return result, nil
	}

	// Collect every IP key seen across services to resolve the team key once.
	keySet := make(map[string]struct{})
	for _, perTeam := range raw {
		for k := range perTeam {
			keySet[k] = struct{}{}
		}
	}
	resolvedKey := resolveForcADTeamKey(teamID, keySet)
	if resolvedKey == "" {
		// Nothing we can do without a key — return empty result for this round.
		return result, nil
	}

	for serviceName, perTeam := range raw {
		vals, ok := perTeam[resolvedKey]
		if !ok || len(vals) == 0 {
			continue
		}
		seen := make(map[string]bool)
		appendVal := func(v string) {
			if v == "" || seen[v] {
				return
			}
			seen[v] = true
			result[roundNum][serviceName] = append(result[roundNum][serviceName], v)
		}
		for _, msg := range vals {
			for _, v := range flattenRawToStrings(msg) {
				appendVal(v)
				for _, alt := range expandForcADValue(v) {
					appendVal(alt)
				}
			}
		}
	}
	return result, nil
}

// resolveForcADTeamKey picks the best matching key from the ForcAD API
// response given the user-configured teamID (which can be an IP, a team
// number, or any substring).
//
// Priority:
//  1. exact match (treats teamID as a full IP / key)
//  2. if teamID is numeric, match keys whose last IP octet equals teamID
//     (covers patterns like 10.0.0.<id>, 10.60.<id>.1, etc. — last octet is
//     most common in ForcAD vulnboxes)
//  3. if still no match and teamID is numeric, match keys where any octet
//     equals teamID — but only if exactly one key qualifies
//  4. fall back to a unique substring match
//
// Returns "" if nothing matched.
func resolveForcADTeamKey(teamID string, keys map[string]struct{}) string {
	if teamID == "" || len(keys) == 0 {
		return ""
	}
	// 1) exact
	if _, ok := keys[teamID]; ok {
		return teamID
	}

	// 2) last-octet match (most common ForcAD layout)
	if _, err := strconv.Atoi(teamID); err == nil {
		var lastOctetHits []string
		for k := range keys {
			parts := strings.Split(k, ".")
			if len(parts) >= 2 && parts[len(parts)-1] == teamID {
				lastOctetHits = append(lastOctetHits, k)
			}
		}
		if len(lastOctetHits) == 1 {
			return lastOctetHits[0]
		}
		// 2b) any other single octet (covers 10.60.<id>.1 style)
		var anyOctetHits []string
		for k := range keys {
			for _, p := range strings.Split(k, ".") {
				if p == teamID {
					anyOctetHits = append(anyOctetHits, k)
					break
				}
			}
		}
		if len(anyOctetHits) == 1 {
			return anyOctetHits[0]
		}
		// Ambiguous — pick the last-octet hit set deterministically if it's
		// non-empty, otherwise give up rather than guess wrong.
		if len(lastOctetHits) > 1 {
			sort.Strings(lastOctetHits)
			return lastOctetHits[0]
		}
	}

	// 3) substring fallback (e.g. "0.3" → "10.0.0.3")
	var contains []string
	for k := range keys {
		if strings.Contains(k, teamID) {
			contains = append(contains, k)
		}
	}
	if len(contains) == 1 {
		return contains[0]
	}
	return ""
}

// expandForcADValue returns additional matcher candidates derived from a raw
// ForcAD flag-id value. The original value is added by the caller; this helper
// produces alternates so the Aho-Corasick matcher hits identifiers that appear
// "naked" or differently encoded in service traffic.
//
// Two transforms are applied:
//
//  1. JSON-in-string: if the value looks like a JSON object/array, parse it
//     and yield every leaf string (covers easyblog1/easyblog2 that store
//     {"username": "..."} or {"username": "...", "filename": "..."}).
//
//  2. label-prefixed identifier(s): the value is split on ", " into segments
//     (handles "user: X, poll_id: Y"); each segment is then split on ": " or
//     ":" so we get the bare identifier. When the identifier is short
//     (< matcher min length, e.g. seaOfHackerz "user_id:436") we also emit
//     URL/JSON variants of the full pair so the matcher can hit
//     "user_id=436", `"user_id":436`, `"user_id": 436` in traffic.
func expandForcADValue(v string) []string {
	var out []string
	trimmed := strings.TrimSpace(v)
	if len(trimmed) >= 2 && (trimmed[0] == '{' || trimmed[0] == '[') {
		for _, leaf := range flattenRawToStrings(json.RawMessage(trimmed)) {
			if leaf == "" || leaf == v {
				continue
			}
			out = append(out, leaf)
			// A JSON leaf can still be a "label: id" pair — handle it too.
			out = append(out, extractLabelSegments(leaf)...)
		}
		return out
	}
	return extractLabelSegments(v)
}

// extractLabelSegments yields the identifiers embedded in a value formatted as
// one or more "label: value" or "label:value" pairs separated by ", ".
//
// For each pair we always emit the trailing identifier. If the identifier is
// shorter than 6 characters (matcher floor), we also emit URL/JSON variants
// of the full pair so short numeric IDs still have a chance of matching real
// traffic that uses query-string or JSON formatting.
func extractLabelSegments(s string) []string {
	var out []string
	for _, raw := range strings.Split(s, ", ") {
		seg := strings.TrimSpace(raw)
		if seg == "" {
			continue
		}

		label, value, ok := splitLabelValue(seg)
		if !ok {
			continue
		}
		if value != "" && value != s {
			out = append(out, value)
		}
		// Short values risk getting filtered by the matcher's 6-char floor —
		// emit qualified variants the gameserver might use in traffic.
		if len(value) > 0 && len(value) < 6 && isLabelWord(label) {
			out = append(out,
				label+"="+value,
				`"`+label+`":`+value,
				`"`+label+`": `+value,
			)
		}
	}
	return out
}

// splitLabelValue splits "<label>: <value>" or "<label>:<value>" into its
// parts. Returns ok=false if no plausible label/value boundary is found, or if
// the label is not a clean identifier (avoids splitting things like
// "10.0.0.1:1234" or "2026-05-21T15:00:00Z").
func splitLabelValue(seg string) (string, string, bool) {
	// Prefer ": " (with space) — it's the cleanest separator.
	if idx := strings.Index(seg, ": "); idx > 0 {
		return seg[:idx], strings.TrimSpace(seg[idx+2:]), true
	}
	// Fall back to ":" without space, but only if the label looks like a
	// word (a-zA-Z0-9_), to avoid mangling IPs, timestamps, URLs.
	if idx := strings.Index(seg, ":"); idx > 0 {
		label := seg[:idx]
		if isLabelWord(label) {
			return label, strings.TrimSpace(seg[idx+1:]), true
		}
	}
	return "", "", false
}

func isLabelWord(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-') {
			return false
		}
	}
	return true
}
