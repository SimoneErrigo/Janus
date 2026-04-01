package sniffer

import (
	"sync"
	"time"
)

const (
	TrafficModeLive   = "live"
	TrafficModeStatic = "static"
)

type CaptureController struct {
	mu sync.RWMutex

	mode      string
	capturing bool

	captureStart time.Time
	captureStop  time.Time
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
	if c.mode == TrafficModeLive {
		c.capturing = true
		c.captureStart = time.Time{}
		c.captureStop = time.Time{}
		return
	}
	// Static mode: user explicitly starts capture.
	c.capturing = false
	c.captureStart = time.Time{}
	c.captureStop = time.Time{}
}

func (c *CaptureController) Mode() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.mode
}

func (c *CaptureController) StartCapture() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.mode != TrafficModeStatic {
		return false
	}
	c.capturing = true
	c.captureStart = time.Now()
	c.captureStop = time.Time{}
	return true
}

func (c *CaptureController) StopCapture() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.mode != TrafficModeStatic {
		return false
	}
	if !c.capturing {
		return false
	}
	c.capturing = false
	c.captureStop = time.Now()
	return true
}

func (c *CaptureController) IsCapturing() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.mode == TrafficModeLive {
		return true
	}
	return c.capturing
}

func (c *CaptureController) ShouldCapture() bool {
	return c.IsCapturing()
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
