package flagids

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	roundFetchGrace      = time.Second
	roundCatchupInterval = 2 * time.Second
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

	lastFetch time.Time
	lastError string

	// Callback after successful fetch with the new current round number
	onFetch func(currentRound int)

	// Loop lifecycle
	loopMu  sync.Mutex
	stopCh  chan struct{}
	running bool
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
		stopCh:           make(chan struct{}),
	}
}

// Start begins the polling loop.
func (p *Poller) Start() {
	if !p.enabled {
		log.Println("Flag ID poller disabled")
		return
	}
	p.loopMu.Lock()
	p.stopCh = make(chan struct{})
	p.running = true
	p.loopMu.Unlock()
	go p.loop()
	log.Printf("Flag ID poller started (url=%s, team=%s, interval=%s, format=%s, round_duration=%s, keep_rounds=%d)",
		p.apiURL, p.teamID, p.interval, p.format, p.roundDuration, p.keepRounds)
}

// Stop signals the poller to exit.
func (p *Poller) Stop() {
	p.loopMu.Lock()
	defer p.loopMu.Unlock()
	if p.running {
		close(p.stopCh)
		p.running = false
	}
}

// Reconfigure updates the poller config and restarts if enabled.
func (p *Poller) Reconfigure(cfg PollerConfig) {
	p.loopMu.Lock()
	if p.running {
		close(p.stopCh)
		p.running = false
	}
	p.loopMu.Unlock()

	p.mu.Lock()
	p.apiURL = cfg.APIURL
	p.teamID = cfg.TeamID
	if cfg.IntervalSec > 0 {
		p.interval = time.Duration(cfg.IntervalSec) * time.Second
	}
	if cfg.Format != "" {
		p.format = cfg.Format
	}
	if cfg.RoundDurationSec > 0 {
		p.roundDuration = time.Duration(cfg.RoundDurationSec) * time.Second
	}
	if cfg.CompetitionStart != "" {
		if t, err := time.Parse(time.RFC3339, cfg.CompetitionStart); err == nil {
			p.competitionStart = t
		}
	}
	if cfg.KeepRounds > 0 {
		p.keepRounds = cfg.KeepRounds
	}
	p.enabled = cfg.Enabled
	p.mu.Unlock()

	if cfg.Enabled && cfg.APIURL != "" {
		p.loopMu.Lock()
		p.stopCh = make(chan struct{})
		p.running = true
		p.loopMu.Unlock()
		go p.loop()
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
	p.fetch()
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

func (p *Poller) loop() {
	p.loopMu.Lock()
	stopCh := p.stopCh
	p.loopMu.Unlock()

	p.fetch()

	for {
		p.mu.RLock()
		delay := p.nextFetchDelayLocked(time.Now())
		p.mu.RUnlock()
		timer := time.NewTimer(delay)
		select {
		case <-stopCh:
			timer.Stop()
			return
		case <-timer.C:
			p.fetch()
		}
	}
}

func (p *Poller) fetch() {
	p.mu.RLock()
	apiURL := p.apiURL
	teamID := p.teamID
	format := p.format
	p.mu.RUnlock()

	url := apiURL
	if teamID != "" {
		sep := "?"
		if strings.Contains(url, "?") {
			sep = "&"
		}
		url += sep + "team=" + teamID
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		p.mu.Lock()
		p.lastError = fmt.Sprintf("fetch error: %v", err)
		p.lastFetch = time.Now()
		p.mu.Unlock()
		log.Printf("Flag ID fetch error: %v", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		p.mu.Lock()
		p.lastError = fmt.Sprintf("read error: %v", err)
		p.lastFetch = time.Now()
		p.mu.Unlock()
		return
	}

	if resp.StatusCode != http.StatusOK {
		p.mu.Lock()
		p.lastError = fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(body))
		p.lastFetch = time.Now()
		p.mu.Unlock()
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
		roundFlags, err = parseFaustCTFRounded(body, teamID, p.roundDuration, p.competitionStart)
	case "forcad":
		roundFlags, err = parseForcADRounded(body, teamID, p.roundDuration, p.competitionStart)
	default:
		roundFlags, err = parseCyberChallengeRounded(body)
	}

	if err != nil {
		p.mu.Lock()
		p.lastError = fmt.Sprintf("parse error: %v", err)
		p.lastFetch = time.Now()
		p.mu.Unlock()
		log.Printf("Flag ID parse error: %v", err)
		return
	}

	// Determine current round (max round number seen)
	maxRound := 0
	for r := range roundFlags {
		if r > maxRound {
			maxRound = r
		}
	}

	p.mu.RLock()
	keepRounds := p.keepRounds
	p.mu.RUnlock()

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
		p.mu.Lock()
		p.lastFetch = time.Now()
		p.lastError = ""
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

	p.mu.Lock()
	p.roundFlags = roundFlags
	p.currentRound = maxRound
	p.matcher = matcher
	p.lastSnapshotHash = snapshotHash
	p.flagIDs = flatFlagIDs
	p.valueKeyMap = vkm
	p.lastFetch = time.Now()
	p.lastError = ""
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
		go onFetch(curRound)
	}
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
// teamID is the team's IP address (e.g., "10.0.0.2").
// No round numbers in the API, so the current round is computed from competition timing.
func parseForcADRounded(body []byte, teamID string, roundDuration time.Duration, competitionStart time.Time) (map[int]map[string][]string, error) {
	var raw map[string]map[string][]string
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

	for serviceName, perTeam := range raw {
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
