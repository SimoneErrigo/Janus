package cleanup

import (
	"log"
	"sync"
	"time"

	"github.com/SimoneErrigo/Janus/backend/internal/sniffer"
)

// Manager handles background cleanup of old packets and DB size management.
type Manager struct {
	mu           sync.RWMutex
	packetStore  *sniffer.PacketStore
	maxAgeMins   int
	maxDBSizeMB  int
	stopCh       chan struct{}
	runNowCh     chan chan Result
}

// Result holds the outcome of a cleanup run.
type Result struct {
	PacketsDeleted int64   `json:"packets_deleted"`
	AlertsDeleted  int64   `json:"alerts_deleted"`
	DurationMs     int64   `json:"duration_ms"`
	DBSizeMB       float64 `json:"db_size_mb"`
	Error          string  `json:"error,omitempty"`
}

// Settings holds the current cleanup policy.
type Settings struct {
	MaxAgeMinutes int `json:"max_age_minutes"`
	MaxDBSizeMB   int `json:"max_db_size_mb"`
}

// NewManager creates a cleanup manager with the given initial settings.
func NewManager(packetStore *sniffer.PacketStore, maxAgeMins, maxDBSizeMB int) *Manager {
	return &Manager{
		packetStore: packetStore,
		maxAgeMins:  maxAgeMins,
		maxDBSizeMB: maxDBSizeMB,
		stopCh:      make(chan struct{}),
		runNowCh:    make(chan chan Result),
	}
}

// Start launches the background cleanup goroutine (runs every 5 minutes).
func (m *Manager) Start() {
	go m.loop()
	log.Printf("Cleanup goroutine started (max_age=%dm, max_db_size=%dMB)", m.maxAgeMins, m.maxDBSizeMB)
}

// Stop signals the background goroutine to exit.
func (m *Manager) Stop() {
	close(m.stopCh)
}

// GetSettings returns the current cleanup policy.
func (m *Manager) GetSettings() Settings {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return Settings{
		MaxAgeMinutes: m.maxAgeMins,
		MaxDBSizeMB:   m.maxDBSizeMB,
	}
}

// UpdateSettings changes the cleanup policy at runtime.
func (m *Manager) UpdateSettings(s Settings) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.maxAgeMins = s.MaxAgeMinutes
	m.maxDBSizeMB = s.MaxDBSizeMB
	log.Printf("Cleanup settings updated: max_age=%dm, max_db_size=%dMB", m.maxAgeMins, m.maxDBSizeMB)
}

// RunNow triggers an immediate cleanup run and returns the result.
func (m *Manager) RunNow() Result {
	resultCh := make(chan Result, 1)
	m.runNowCh <- resultCh
	return <-resultCh
}

// DBSizeMB returns the current database size in MB.
func (m *Manager) DBSizeMB() float64 {
	size, err := m.packetStore.DBSize()
	if err != nil {
		return 0
	}
	return float64(size) / (1024 * 1024)
}

func (m *Manager) loop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.run()
		case resultCh := <-m.runNowCh:
			resultCh <- m.run()
		}
	}
}

func (m *Manager) run() Result {
	start := time.Now()
	var totalPkts, totalAlerts int64

	m.mu.RLock()
	maxAge := m.maxAgeMins
	maxSize := m.maxDBSizeMB
	m.mu.RUnlock()

	// Policy 1: age-based cleanup
	if maxAge > 0 {
		cutoff := time.Now().Add(-time.Duration(maxAge) * time.Minute)
		pkts, alerts, err := m.packetStore.DeleteOlderThan(cutoff)
		if err != nil {
			log.Printf("Cleanup error (age policy): %v", err)
			return Result{Error: err.Error()}
		}
		totalPkts += pkts
		totalAlerts += alerts
	}

	// Policy 2: size-based cleanup
	if maxSize > 0 {
		maxBytes := int64(maxSize) * 1024 * 1024
		pkts, alerts, err := m.packetStore.DeleteOldestUntilSize(maxBytes)
		if err != nil {
			log.Printf("Cleanup error (size policy): %v", err)
			return Result{
				PacketsDeleted: totalPkts,
				AlertsDeleted:  totalAlerts,
				Error:          err.Error(),
			}
		}
		totalPkts += pkts
		totalAlerts += alerts
	}

	duration := time.Since(start)
	dbSize := m.DBSizeMB()

	if totalPkts > 0 || totalAlerts > 0 {
		log.Printf("Cleanup: deleted %d packets, %d alerts in %dms (DB: %.1f MB)",
			totalPkts, totalAlerts, duration.Milliseconds(), dbSize)
	}

	return Result{
		PacketsDeleted: totalPkts,
		AlertsDeleted:  totalAlerts,
		DurationMs:     duration.Milliseconds(),
		DBSizeMB:       dbSize,
	}
}
