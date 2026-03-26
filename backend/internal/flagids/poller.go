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

	// Current flag ID map: service_name -> list of flag ID values
	flagIDs map[string][]string

	lastFetch time.Time
	lastError string
	stopCh    chan struct{}
}

// Status holds the poller's current state.
type Status struct {
	Enabled       bool      `json:"enabled"`
	LastFetch     time.Time `json:"last_fetch"`
	NextFetch     time.Time `json:"next_fetch"`
	LastError     string    `json:"last_error,omitempty"`
	PollInterval  int       `json:"poll_interval_seconds"`
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
	go p.loop()
	log.Printf("Flag ID poller started (url=%s, team=%s, interval=%s)", p.apiURL, p.teamID, p.interval)
}

// Stop signals the poller to exit.
func (p *Poller) Stop() {
	close(p.stopCh)
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
		LastFetch:    p.lastFetch,
		NextFetch:    nextFetch,
		LastError:    p.lastError,
		PollInterval: int(p.interval.Seconds()),
	}
}

// IsEnabled returns whether the poller is active.
func (p *Poller) IsEnabled() bool {
	return p.enabled
}

// ContainsFlagID checks if the given text contains any current flag ID value.
func (p *Poller) ContainsFlagID(text string) bool {
	if text == "" {
		return false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, vals := range p.flagIDs {
		for _, v := range vals {
			if v != "" && strings.Contains(text, v) {
				return true
			}
		}
	}
	return false
}

func (p *Poller) loop() {
	// Fetch immediately on start
	p.fetch()

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.fetch()
		}
	}
}

func (p *Poller) fetch() {
	url := p.apiURL
	if p.teamID != "" {
		sep := "?"
		if strings.Contains(url, "?") {
			sep = "&"
		}
		url += sep + "team=" + p.teamID
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

	// Parse the nested structure:
	// { "service_name": { "team_id": { "round_number": { "desc_key": "flag_id_value" } } } }
	var raw map[string]map[string]map[string]map[string]string
	if err := json.Unmarshal(body, &raw); err != nil {
		p.mu.Lock()
		p.lastError = fmt.Sprintf("parse error: %v", err)
		p.lastFetch = time.Now()
		p.mu.Unlock()
		log.Printf("Flag ID parse error: %v", err)
		return
	}

	// Flatten: for each service, collect all flag ID values across all rounds
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
}
