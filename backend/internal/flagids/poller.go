package flagids

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
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

	// Current flag ID map: service_name -> list of flag ID values
	flagIDs map[string][]string

	lastFetch time.Time
	lastError string

	// Callback after successful fetch (e.g. for backfilling old packets)
	onFetch func(values []string)

	// Loop lifecycle
	loopMu  sync.Mutex
	stopCh  chan struct{}
	running bool
}

// PollerConfig holds the configurable fields for the poller.
type PollerConfig struct {
	Enabled     bool   `json:"enabled"`
	APIURL      string `json:"api_url"`
	TeamID      string `json:"team_id"`
	IntervalSec int    `json:"poll_interval_seconds"`
	Format      string `json:"format"`
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
}

// NewPoller creates a flag ID poller.
func NewPoller(apiURL, teamID string, intervalSec int, enabled bool) *Poller {
	if intervalSec <= 0 {
		intervalSec = 30
	}
	return &Poller{
		apiURL:   apiURL,
		teamID:   teamID,
		interval: time.Duration(intervalSec) * time.Second,
		enabled:  enabled,
		format:   "cyberchallenge",
		flagIDs:  make(map[string][]string),
		stopCh:   make(chan struct{}),
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
	log.Printf("Flag ID poller started (url=%s, team=%s, interval=%s, format=%s)", p.apiURL, p.teamID, p.interval, p.format)
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
	// Stop current loop if running
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
	return PollerConfig{
		Enabled:     p.enabled,
		APIURL:      p.apiURL,
		TeamID:      p.teamID,
		IntervalSec: int(p.interval.Seconds()),
		Format:      p.format,
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
	}
}

// IsEnabled returns whether the poller is active.
func (p *Poller) IsEnabled() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.enabled
}

// SetOnFetch registers a callback invoked after each successful flag ID fetch
// with the flat list of all current flag ID values.
func (p *Poller) SetOnFetch(fn func(values []string)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.onFetch = fn
}

// ContainsFlagID checks if the given text contains any current flag ID value.
// Values shorter than 6 characters are skipped to avoid false positives.
func (p *Poller) ContainsFlagID(text string) bool {
	return len(p.FindMatchingFlagIDs(text)) > 0
}

// FindMatchingFlagIDs returns all flag ID values found in the given text.
// Values shorter than 6 characters are skipped to avoid false positives.
func (p *Poller) FindMatchingFlagIDs(text string) []string {
	if text == "" {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()

	var matched []string
	for _, vals := range p.flagIDs {
		for _, v := range vals {
			if len(v) >= 6 && strings.Contains(text, v) {
				matched = append(matched, v)
			}
		}
	}
	return matched
}

func (p *Poller) loop() {
	// Capture stop channel for this loop instance
	p.loopMu.Lock()
	stopCh := p.stopCh
	p.loopMu.Unlock()

	// Fetch immediately on start
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

	var flagIDs map[string][]string
	switch format {
	case "cyberchallenge":
		flagIDs, err = parseCyberChallenge(body)
	default:
		flagIDs, err = parseCyberChallenge(body)
	}

	if err != nil {
		p.mu.Lock()
		p.lastError = fmt.Sprintf("parse error: %v", err)
		p.lastFetch = time.Now()
		p.mu.Unlock()
		log.Printf("Flag ID parse error: %v", err)
		return
	}

	p.mu.Lock()
	p.flagIDs = flagIDs
	p.lastFetch = time.Now()
	p.lastError = ""
	p.mu.Unlock()

	total := 0
	for _, v := range flagIDs {
		total += len(v)
	}
	log.Printf("Flag IDs refreshed: %d services, %d values", len(flagIDs), total)

	// Notify callback (e.g. to backfill old packets with newly fetched flag IDs)
	p.mu.RLock()
	onFetch := p.onFetch
	p.mu.RUnlock()
	if onFetch != nil {
		var allValues []string
		for _, vals := range flagIDs {
			allValues = append(allValues, vals...)
		}
		go onFetch(allValues)
	}
}

// parseCyberChallenge parses the CyberChallenge flag ID format:
// { "service_name": { "team_id": { "round_number": { "desc_key": "flag_id_value" } } } }
func parseCyberChallenge(body []byte) (map[string][]string, error) {
	var raw map[string]map[string]map[string]map[string]string
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	flagIDs := make(map[string][]string)
	for serviceName, teams := range raw {
		seen := make(map[string]bool)
		for _, rounds := range teams {
			for _, descs := range rounds {
				for _, flagIDVal := range descs {
					if flagIDVal != "" && !seen[flagIDVal] {
						seen[flagIDVal] = true
						flagIDs[serviceName] = append(flagIDs[serviceName], flagIDVal)
					}
				}
			}
		}
	}
	return flagIDs, nil
}
