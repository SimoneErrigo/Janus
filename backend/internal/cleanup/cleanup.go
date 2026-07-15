package cleanup

import (
	"log"
	"sync"
	"time"

	"github.com/SimoneErrigo/Janus/backend/internal/sniffer"
)

// Manager handles background cleanup of old packets and DB size management.
type Manager struct {
	mu          sync.RWMutex
	runMu       sync.Mutex
	lifecycleMu sync.Mutex
	started     bool
	stopped     bool
	packetStore *sniffer.PacketStore
	maxAgeMins  int
	maxDBSizeMB int
	stopCh      chan struct{}
	doneCh      chan struct{}
	runNowCh    chan chan Result
}

// Result holds the outcome of a cleanup run.
type Result struct {
	PacketsDeleted int64   `json:"packets_deleted"`
	AlertsDeleted  int64   `json:"alerts_deleted"`
	DurationMs     int64   `json:"duration_ms"`
	DBSizeMB       float64 `json:"db_size_mb"`
	DBUsedMB       float64 `json:"db_used_mb"`
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
		doneCh:      make(chan struct{}),
		runNowCh:    make(chan chan Result),
	}
}

const (
	cleanupInterval   = 15 * time.Second
	cleanupBatchSize  = 500
	cleanupRunBudget  = 1500 * time.Millisecond
	maxCleanupBatches = 128
	cleanupYield      = 3 * time.Millisecond
)

// Start launches the background cleanup goroutine. Cleanup is frequent and
// incremental so no single run monopolizes SQLite's writer connection.
func (m *Manager) Start() {
	m.lifecycleMu.Lock()
	if m.started || m.stopped {
		m.lifecycleMu.Unlock()
		return
	}
	m.started = true
	m.lifecycleMu.Unlock()
	go m.loop()
	log.Printf("Cleanup goroutine started (max_age=%dm, max_db_size=%dMB)", m.maxAgeMins, m.maxDBSizeMB)
}

// Stop signals the background goroutine to exit.
func (m *Manager) Stop() {
	m.lifecycleMu.Lock()
	if !m.stopped {
		m.stopped = true
		close(m.stopCh)
	}
	started := m.started
	m.lifecycleMu.Unlock()
	if started {
		<-m.doneCh
	}
	// A direct RunNow/Purge call can run outside the background loop. Wait for
	// it as well so callers may safely close the packet store after Stop.
	m.runMu.Lock()
	m.runMu.Unlock()
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
// Concurrent manual/automatic runs are serialized to avoid competing DELETEs.
func (m *Manager) RunNow() Result {
	m.lifecycleMu.Lock()
	stopped := m.stopped
	m.lifecycleMu.Unlock()
	if stopped {
		return Result{Error: "cleanup manager is stopped"}
	}
	resultCh := make(chan Result, 1)
	select {
	case <-m.stopCh:
		return Result{Error: "cleanup manager is stopped"}
	case m.runNowCh <- resultCh:
		select {
		case result := <-resultCh:
			return result
		case <-m.stopCh:
			return Result{Error: "cleanup manager is stopped"}
		}
	default:
		// Do not queue behind an automatic cleanup while SQLite is already doing
		// bounded DELETE batches. Returning promptly keeps the control plane and
		// packet UI responsive; the active run is already enforcing the policy.
		if !m.runMu.TryLock() {
			return Result{Error: "cleanup already in progress", DBSizeMB: m.DBSizeMB()}
		}
		defer m.runMu.Unlock()
		m.lifecycleMu.Lock()
		stopped = m.stopped
		m.lifecycleMu.Unlock()
		if stopped {
			return Result{Error: "cleanup manager is stopped"}
		}
		return m.runLocked()
	}
}

// DBSizeMB returns the current database size in MB.
func (m *Manager) DBSizeMB() float64 {
	size, err := m.packetStore.DBSize()
	if err != nil {
		return 0
	}
	return float64(size) / (1024 * 1024)
}

// DBUsedMB is the logical SQLite space in use, excluding reusable free pages.
func (m *Manager) DBUsedMB() float64 {
	size, err := m.packetStore.DBUsedSize()
	if err != nil {
		return 0
	}
	return float64(size) / (1024 * 1024)
}

func (m *Manager) loop() {
	defer close(m.doneCh)
	ticker := time.NewTicker(cleanupInterval)
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

// PurgeAll deletes all packets and alerts regardless of policies.
func (m *Manager) PurgeAll() Result {
	m.runMu.Lock()
	defer m.runMu.Unlock()
	start := time.Now()
	pkts, alerts, err := m.packetStore.PurgeAll()
	if err != nil {
		log.Printf("PurgeAll error: %v", err)
		return Result{Error: err.Error()}
	}
	duration := time.Since(start)
	if pkts > 0 || alerts > 0 {
		m.packetStore.NotifyMetadataChange()
	}
	dbSize := m.DBSizeMB()
	log.Printf("PurgeAll: deleted %d packets, %d alerts in %dms (DB: %.1f MB)",
		pkts, alerts, duration.Milliseconds(), dbSize)
	return Result{
		PacketsDeleted: pkts,
		AlertsDeleted:  alerts,
		DurationMs:     duration.Milliseconds(),
		DBSizeMB:       dbSize,
		DBUsedMB:       m.DBUsedMB(),
	}
}

// PurgePackets deletes all packets (and their linked alerts) but no other data.
func (m *Manager) PurgePackets() Result {
	m.runMu.Lock()
	defer m.runMu.Unlock()
	start := time.Now()
	pkts, err := m.packetStore.PurgePackets()
	if err != nil {
		log.Printf("PurgePackets error: %v", err)
		return Result{Error: err.Error()}
	}
	duration := time.Since(start)
	if pkts > 0 {
		m.packetStore.NotifyMetadataChange()
	}
	dbSize := m.DBSizeMB()
	log.Printf("PurgePackets: deleted %d packets in %dms (DB: %.1f MB)",
		pkts, duration.Milliseconds(), dbSize)
	return Result{
		PacketsDeleted: pkts,
		DurationMs:     duration.Milliseconds(),
		DBSizeMB:       dbSize,
		DBUsedMB:       m.DBUsedMB(),
	}
}

// PurgeDroppedPackets deletes all packets that were dropped by a rule.
func (m *Manager) PurgeDroppedPackets() Result {
	m.runMu.Lock()
	defer m.runMu.Unlock()
	start := time.Now()
	pkts, err := m.packetStore.PurgeDroppedPackets()
	if err != nil {
		log.Printf("PurgeDroppedPackets error: %v", err)
		return Result{Error: err.Error()}
	}
	duration := time.Since(start)
	if pkts > 0 {
		m.packetStore.NotifyMetadataChange()
	}
	dbSize := m.DBSizeMB()
	log.Printf("PurgeDroppedPackets: deleted %d packets in %dms (DB: %.1f MB)",
		pkts, duration.Milliseconds(), dbSize)
	return Result{
		PacketsDeleted: pkts,
		DurationMs:     duration.Milliseconds(),
		DBSizeMB:       dbSize,
		DBUsedMB:       m.DBUsedMB(),
	}
}

func (m *Manager) run() Result {
	m.runMu.Lock()
	defer m.runMu.Unlock()
	return m.runLocked()
}

func (m *Manager) runLocked() Result {
	start := time.Now()
	var totalPkts, totalAlerts int64
	batches := 0

	m.mu.RLock()
	maxAge := m.maxAgeMins
	maxSize := m.maxDBSizeMB
	m.mu.RUnlock()

	// Policy 1: age-based cleanup
	if maxAge > 0 {
		cutoff := time.Now().Add(-time.Duration(maxAge) * time.Minute)
		for cleanupBudgetAvailable(start, batches) {
			pkts, alerts, err := m.packetStore.DeleteOlderThanBatch(cutoff, cleanupBatchSize)
			batches++
			if err != nil {
				log.Printf("Cleanup error (age policy): %v", err)
				return Result{PacketsDeleted: totalPkts, AlertsDeleted: totalAlerts, Error: err.Error()}
			}
			totalPkts += pkts
			totalAlerts += alerts
			if pkts < cleanupBatchSize {
				break
			}
			time.Sleep(cleanupYield)
		}
	}

	// Policy 2: size-based cleanup
	if maxSize > 0 {
		maxBytes := int64(maxSize) * 1024 * 1024
		// Aim below the threshold so cleanup does not oscillate on every insert.
		targetBytes := maxBytes * 9 / 10
		sizeBatches := 0
		for cleanupBudgetAvailable(start, batches) {
			usedBytes, err := m.packetStore.DBUsedSize()
			if err != nil {
				return Result{PacketsDeleted: totalPkts, AlertsDeleted: totalAlerts, Error: err.Error()}
			}
			if usedBytes <= targetBytes || (sizeBatches == 0 && usedBytes <= maxBytes) {
				break
			}
			pkts, alerts, err := m.packetStore.DeleteOldestBatch(cleanupBatchSize)
			batches++
			sizeBatches++
			if err != nil {
				log.Printf("Cleanup error (size policy): %v", err)
				return Result{PacketsDeleted: totalPkts, AlertsDeleted: totalAlerts, Error: err.Error()}
			}
			totalPkts += pkts
			totalAlerts += alerts
			if pkts == 0 {
				break
			}
			time.Sleep(cleanupYield)
		}
	}

	duration := time.Since(start)
	if totalPkts > 0 || totalAlerts > 0 {
		m.packetStore.CheckpointWAL()
		m.packetStore.NotifyMetadataChange()
	}
	dbSize := m.DBSizeMB()
	dbUsed := m.DBUsedMB()

	if totalPkts > 0 || totalAlerts > 0 {
		log.Printf("Cleanup: deleted %d packets, %d alerts in %dms (DB: %.1f MB physical, %.1f MB used)",
			totalPkts, totalAlerts, duration.Milliseconds(), dbSize, dbUsed)
	}

	return Result{
		PacketsDeleted: totalPkts,
		AlertsDeleted:  totalAlerts,
		DurationMs:     duration.Milliseconds(),
		DBSizeMB:       dbSize,
		DBUsedMB:       dbUsed,
	}
}

func cleanupBudgetAvailable(start time.Time, batches int) bool {
	return batches < maxCleanupBatches && (batches == 0 || time.Since(start) < cleanupRunBudget)
}
