package flagids

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
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
	roundFlags   map[int]map[string][]string
	currentRound int
	matcher      *Matcher // Aho-Corasick automaton for O(text_length) matching

	// Competition timing
	roundDuration    time.Duration // duration of a single round
	competitionStart time.Time     // when the competition started (for round calculation)
	keepRounds       int           // how many rounds of flagIds to keep (default 5)

	// Legacy flat view (backward compat with GetFlagIDs / GetAllValues)
	flagIDs map[string][]string

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
	Enabled      bool      `json:"enabled"`
	APIURL       string    `json:"api_url"`
	TeamID       string    `json:"team_id"`
	Format       string    `json:"format"`
	LastFetch    time.Time `json:"last_fetch"`
	NextFetch    time.Time `json:"next_fetch"`
	LastError    string    `json:"last_error,omitempty"`
	PollInterval int       `json:"poll_interval_seconds"`
	CurrentRound int       `json:"current_round"`
	KeepRounds   int       `json:"keep_rounds"`
}

// NewPoller creates a flag ID poller.
func NewPoller(apiURL, teamID string, intervalSec int, enabled bool, roundDurationSec int, competitionStart time.Time, keepRounds int) *Poller {
	if intervalSec <= 0 {
		intervalSec = 5
	}
	if roundDurationSec <= 0 {
		roundDurationSec = 120 // default 2 minutes
	}
	if keepRounds <= 0 {
		keepRounds = 5
	}
	return &Poller{
		apiURL:           apiURL,
		teamID:           teamID,
		interval:         time.Duration(intervalSec) * time.Second,
		enabled:          enabled,
		format:           "cyberchallenge",
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

	var nextFetch time.Time
	if !p.lastFetch.IsZero() {
		nextFetch = p.lastFetch.Add(p.interval)
	}

	return Status{
		Enabled:      p.enabled,
		APIURL:       p.apiURL,
		TeamID:       p.teamID,
		Format:       p.format,
		LastFetch:    p.lastFetch,
		NextFetch:    nextFetch,
		LastError:    p.lastError,
		PollInterval: int(p.interval.Seconds()),
		CurrentRound: p.currentRound,
		KeepRounds:   p.keepRounds,
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

	p.mu.RLock()
	interval := p.interval
	p.mu.RUnlock()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
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

	// Build Aho-Corasick automaton from all active round flagIds
	matcher := BuildMatcher(roundFlags)

	// Flatten into legacy map for backward compat (GetFlagIDs, API responses)
	flatFlagIDs := flattenRoundFlags(roundFlags)

	p.mu.Lock()
	p.roundFlags = roundFlags
	p.currentRound = maxRound
	p.matcher = matcher
	p.flagIDs = flatFlagIDs
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

// parseCyberChallengeRounded parses the CyberChallenge flag ID format preserving round numbers:
// { "service_name": { "team_id": { "round_number": { "desc_key": "flag_id_value" } } } }
// Returns: roundNum -> serviceName -> []flagIdValue
func parseCyberChallengeRounded(body []byte) (map[int]map[string][]string, error) {
	var raw map[string]map[string]map[string]map[string]string
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	result := make(map[int]map[string][]string)
	for serviceName, teams := range raw {
		for _, rounds := range teams {
			// Collect round numbers and sort for deterministic order
			roundNums := make([]string, 0, len(rounds))
			for r := range rounds {
				roundNums = append(roundNums, r)
			}
			sort.Strings(roundNums)

			for _, roundStr := range roundNums {
				descs := rounds[roundStr]
				roundNum, err := strconv.Atoi(roundStr)
				if err != nil {
					continue // skip non-numeric round keys
				}
				if result[roundNum] == nil {
					result[roundNum] = make(map[string][]string)
				}
				seen := make(map[string]bool)
				for _, val := range descs {
					if val != "" && !seen[val] {
						seen[val] = true
						result[roundNum][serviceName] = append(result[roundNum][serviceName], val)
					}
				}
			}
		}
	}
	return result, nil
}

// parseCyberChallenge parses the CyberChallenge flag ID format into a flat map.
// Kept for backward compatibility.
func parseCyberChallenge(body []byte) (map[string][]string, error) {
	rounded, err := parseCyberChallengeRounded(body)
	if err != nil {
		return nil, err
	}
	return flattenRoundFlags(rounded), nil
}
