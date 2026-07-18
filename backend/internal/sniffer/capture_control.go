package sniffer

import (
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	TrafficModeLive   = "live"
	TrafficModeStatic = "static"
)

var (
	ErrCaptureNotStatic     = errors.New("capture start is only available in static mode")
	ErrCaptureAlreadyActive = errors.New("static capture is already active")
	ErrCaptureNoServices    = errors.New("static capture requires at least one service")
)

type CaptureController struct {
	mu sync.RWMutex

	mode      string
	capturing bool

	captureStart    time.Time
	captureStop     time.Time
	captureServices []string
	captureSet      map[string]struct{}
	removedServices map[string]struct{}
}

// CaptureSnapshot is an immutable controller view. ServiceIDs is always a
// defensive, non-nil copy so callers can safely retain a completed session
// while another capture starts.
type CaptureSnapshot struct {
	Mode         string
	Capturing    bool
	CaptureStart time.Time
	CaptureStop  time.Time
	ServiceIDs   []string
}

func NewCaptureController(mode string) *CaptureController {
	c := &CaptureController{}
	c.SetMode(mode)
	return c
}

func normalizeMode(mode string) string {
	if mode == TrafficModeStatic {
		return TrafficModeStatic
	}
	return TrafficModeLive
}

func (c *CaptureController) SetMode(mode string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.mode = normalizeMode(mode)
	c.captureStart = time.Time{}
	c.captureStop = time.Time{}
	c.captureServices = nil
	c.captureSet = nil
	c.removedServices = nil
	if c.mode == TrafficModeLive {
		c.capturing = true
		return
	}
	// Static mode: user explicitly starts capture.
	c.capturing = false
}

func (c *CaptureController) Mode() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.mode
}

// StartCapture begins one static capture session. The selected services are
// normalized and snapshotted: later configuration edits cannot silently alter
// a capture that is already in progress.
func (c *CaptureController) StartCapture(serviceIDs []string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.mode != TrafficModeStatic {
		return ErrCaptureNotStatic
	}
	if c.capturing {
		return ErrCaptureAlreadyActive
	}

	services := normalizeCaptureServices(serviceIDs)
	if len(services) == 0 {
		return ErrCaptureNoServices
	}
	serviceSet := make(map[string]struct{}, len(services))
	for _, serviceID := range services {
		serviceSet[serviceID] = struct{}{}
	}

	c.capturing = true
	c.captureStart = time.Now()
	c.captureStop = time.Time{}
	c.captureServices = services
	c.captureSet = serviceSet
	c.removedServices = nil
	return nil
}

func (c *CaptureController) StopCapture() bool {
	_, stopped := c.StopCaptureWithSnapshot()
	return stopped
}

// StopCaptureWithSnapshot stops the active static session and returns its
// exact window and service scope under the same lock.
func (c *CaptureController) StopCaptureWithSnapshot() (CaptureSnapshot, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.mode != TrafficModeStatic {
		return CaptureSnapshot{}, false
	}
	if !c.capturing {
		return CaptureSnapshot{}, false
	}
	c.capturing = false
	c.captureStop = time.Now()
	return c.snapshotLocked(), true
}

func (c *CaptureController) IsCapturing() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.mode == TrafficModeLive {
		return true
	}
	return c.capturing
}

// ShouldCaptureService is the data-plane admission gate. Live mode captures
// every service. Static mode captures only members of the immutable session
// snapshot while that session is active.
func (c *CaptureController) ShouldCaptureService(serviceID string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.mode == TrafficModeLive {
		return true
	}
	if !c.capturing {
		return false
	}
	if _, removed := c.removedServices[serviceID]; removed {
		return false
	}
	_, selected := c.captureSet[serviceID]
	return selected
}

// CaptureServiceIDs returns a copy of the current or most recently completed
// static session scope. StopCapture deliberately preserves it so post-capture
// operations such as PCAP export can use the exact original selection.
func (c *CaptureController) CaptureServiceIDs() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.captureServices) == 0 {
		return []string{}
	}
	return append([]string(nil), c.captureServices...)
}

// Snapshot reads mode, session window and service scope atomically.
func (c *CaptureController) Snapshot() CaptureSnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.snapshotLocked()
}

// RemoveService tombstones a service for the remainder of an active static
// session. This prevents deleting and recreating the same ID from admitting a
// different service into an existing snapshot. The ID remains in the exported
// session scope so packets captured before deletion are not lost.
func (c *CaptureController) RemoveService(serviceID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.mode != TrafficModeStatic || !c.capturing {
		return
	}
	if _, selected := c.captureSet[serviceID]; !selected {
		return
	}
	if c.removedServices == nil {
		c.removedServices = make(map[string]struct{})
	}
	c.removedServices[serviceID] = struct{}{}
}

func (c *CaptureController) ShouldApplyFlagIDsOnIngest() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.mode == TrafficModeLive
}

func (c *CaptureController) CaptureWindow() (time.Time, time.Time, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.mode != TrafficModeStatic || c.captureStart.IsZero() {
		return time.Time{}, time.Time{}, false
	}
	to := c.captureStop
	if to.IsZero() {
		to = time.Now()
	}
	return c.captureStart, to, true
}

func normalizeCaptureServices(serviceIDs []string) []string {
	set := make(map[string]struct{}, len(serviceIDs))
	for _, raw := range serviceIDs {
		serviceID := strings.TrimSpace(raw)
		if serviceID != "" {
			set[serviceID] = struct{}{}
		}
	}
	services := make([]string, 0, len(set))
	for serviceID := range set {
		services = append(services, serviceID)
	}
	sort.Strings(services)
	return services
}

func (c *CaptureController) snapshotLocked() CaptureSnapshot {
	services := []string{}
	if len(c.captureServices) > 0 {
		services = append(services, c.captureServices...)
	}
	return CaptureSnapshot{
		Mode:         c.mode,
		Capturing:    c.capturing,
		CaptureStart: c.captureStart,
		CaptureStop:  c.captureStop,
		ServiceIDs:   services,
	}
}
