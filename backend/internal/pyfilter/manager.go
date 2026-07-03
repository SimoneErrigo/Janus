// Package pyfilter runs user-supplied Python "filter" addons against captured
// traffic, mitmproxy-style. Each script defines a top-level match(flow)
// function and may keep module-level state across calls, which makes stateful
// checks possible — e.g. "alert when the same user logs in more than once" or
// "flag requests whose body/header exceeds some size".
//
// Scripts run in a single long-lived python3 subprocess (the harness), driven
// by a line-delimited JSON protocol. The engine is deliberately decoupled from
// Janus types: it consumes a generic Flow (map) and reports Matches; the caller
// wires those into alerts. All evaluation happens off the proxy hot path.
package pyfilter

import (
	_ "embed"
	"errors"
	"fmt"
	"os/exec"
	"sync"
	"time"
)

//go:embed harness.py
var harness string

// Flow is the generic packet view handed to Python scripts.
type Flow = map[string]any

// Config configures a Manager.
type Config struct {
	// DataDir is where pyfilters.json is persisted.
	DataDir string
	// PythonPath optionally overrides interpreter auto-detection.
	PythonPath string
	// EvalTimeout bounds a single evaluation before the worker is killed.
	// Defaults to 2s.
	EvalTimeout time.Duration
	// QueueSize bounds the async Submit backlog. Defaults to 1024.
	QueueSize int
	// OnMatch is invoked (from a background goroutine) for every match produced
	// by Submit. Optional.
	OnMatch func(flow Flow, m Match)
}

// Status is a snapshot of engine health for the API/UI.
type Status struct {
	Available     bool   `json:"available"`      // python3 interpreter found
	PythonPath    string `json:"python_path,omitempty"`
	WorkerHealthy bool   `json:"worker_healthy"` // a live worker is running
	ScriptCount   int    `json:"script_count"`
	EnabledCount  int    `json:"enabled_count"`
	LastError     string `json:"last_error,omitempty"`
}

// Manager owns the script set and the Python worker.
type Manager struct {
	cfg        Config
	pythonPath string
	available  bool

	// scripts state
	smu     sync.Mutex
	scripts []Script
	gen     int // bumped on every script-set change
	path    string

	// live worker state
	wmu       sync.Mutex
	worker    *worker
	loadedGen int
	lastErr   string

	queue    chan Flow
	stopOnce sync.Once
	stopped  chan struct{}
}

// NewManager detects python3, loads persisted scripts, and starts the async
// evaluation pipeline. It never fails hard: when python3 is missing the engine
// simply reports Available=false and evaluates nothing.
func NewManager(cfg Config) *Manager {
	if cfg.EvalTimeout <= 0 {
		cfg.EvalTimeout = 2 * time.Second
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 1024
	}
	m := &Manager{
		cfg:       cfg,
		path:      cfg.DataDir + "/pyfilters.json",
		loadedGen: -1,
		queue:     make(chan Flow, cfg.QueueSize),
		stopped:   make(chan struct{}),
	}

	m.pythonPath = cfg.PythonPath
	if m.pythonPath == "" {
		m.pythonPath = detectPython()
	}
	m.available = m.pythonPath != ""

	if scripts, err := loadScripts(m.path); err == nil {
		m.scripts = scripts
	} else {
		m.scripts = []Script{}
		m.lastErr = "loading scripts: " + err.Error()
	}

	go m.runPipeline()
	return m
}

// detectPython returns the first available interpreter path, or "".
func detectPython() string {
	for _, name := range []string{"python3", "python"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

// --- script CRUD ---

// ListScripts returns a copy of the current script set.
func (m *Manager) ListScripts() []Script {
	m.smu.Lock()
	defer m.smu.Unlock()
	out := make([]Script, len(m.scripts))
	copy(out, m.scripts)
	return out
}

// GetScript returns one script by id.
func (m *Manager) GetScript(id string) (Script, bool) {
	m.smu.Lock()
	defer m.smu.Unlock()
	for _, s := range m.scripts {
		if s.ID == id {
			return s, true
		}
	}
	return Script{}, false
}

// CreateScript adds a new script. The id is derived from the name (uniquified).
func (m *Manager) CreateScript(name, code string, enabled bool) (Script, error) {
	if name == "" {
		return Script{}, errors.New("name is required")
	}
	m.smu.Lock()
	defer m.smu.Unlock()

	base := slugID(name)
	id := base
	for i := 2; m.indexOf(id) >= 0; i++ {
		id = fmt.Sprintf("%s-%d", base, i)
	}
	now := time.Now().Unix()
	s := Script{ID: id, Name: name, Code: code, Enabled: enabled, CreatedAt: now, UpdatedAt: now}
	m.scripts = append(m.scripts, s)
	m.persistAndBumpLocked()
	return s, nil
}

// UpdateScript mutates an existing script's name/code/enabled.
func (m *Manager) UpdateScript(id, name, code string, enabled bool) (Script, error) {
	m.smu.Lock()
	defer m.smu.Unlock()
	i := m.indexOf(id)
	if i < 0 {
		return Script{}, errNotFound
	}
	if name != "" {
		m.scripts[i].Name = name
	}
	m.scripts[i].Code = code
	m.scripts[i].Enabled = enabled
	m.scripts[i].UpdatedAt = time.Now().Unix()
	s := m.scripts[i]
	m.persistAndBumpLocked()
	return s, nil
}

// SetEnabled toggles a script on/off.
func (m *Manager) SetEnabled(id string, enabled bool) (Script, error) {
	m.smu.Lock()
	defer m.smu.Unlock()
	i := m.indexOf(id)
	if i < 0 {
		return Script{}, errNotFound
	}
	m.scripts[i].Enabled = enabled
	m.scripts[i].UpdatedAt = time.Now().Unix()
	s := m.scripts[i]
	m.persistAndBumpLocked()
	return s, nil
}

// DeleteScript removes a script by id.
func (m *Manager) DeleteScript(id string) error {
	m.smu.Lock()
	defer m.smu.Unlock()
	i := m.indexOf(id)
	if i < 0 {
		return errNotFound
	}
	m.scripts = append(m.scripts[:i], m.scripts[i+1:]...)
	m.persistAndBumpLocked()
	return nil
}

var errNotFound = errors.New("pyfilter: script not found")

// ErrNotFound is exposed so handlers can map it to 404.
func ErrNotFound() error { return errNotFound }

func (m *Manager) indexOf(id string) int {
	for i, s := range m.scripts {
		if s.ID == id {
			return i
		}
	}
	return -1
}

// persistAndBumpLocked writes scripts to disk and bumps the generation so the
// worker reloads before the next evaluation. Caller holds smu.
func (m *Manager) persistAndBumpLocked() {
	m.gen++
	if err := saveScripts(m.path, m.scripts); err != nil {
		m.lastErr = "saving scripts: " + err.Error()
	}
}

// enabledSpecsAndGen snapshots the enabled scripts and current generation.
func (m *Manager) enabledSpecsAndGen() ([]scriptSpec, int) {
	m.smu.Lock()
	defer m.smu.Unlock()
	specs := make([]scriptSpec, 0, len(m.scripts))
	for _, s := range m.scripts {
		if s.Enabled {
			specs = append(specs, scriptSpec{ID: s.ID, Name: s.Name, Code: s.Code})
		}
	}
	return specs, m.gen
}

func (m *Manager) hasEnabled() bool {
	m.smu.Lock()
	defer m.smu.Unlock()
	for _, s := range m.scripts {
		if s.Enabled {
			return true
		}
	}
	return false
}

// --- status ---

// Status returns a health snapshot.
func (m *Manager) Status() Status {
	m.smu.Lock()
	total := len(m.scripts)
	enabled := 0
	for _, s := range m.scripts {
		if s.Enabled {
			enabled++
		}
	}
	m.smu.Unlock()

	m.wmu.Lock()
	healthy := m.worker != nil && !m.worker.isDead()
	lastErr := m.lastErr
	m.wmu.Unlock()

	return Status{
		Available:     m.available,
		PythonPath:    m.pythonPath,
		WorkerHealthy: healthy,
		ScriptCount:   total,
		EnabledCount:  enabled,
		LastError:     lastErr,
	}
}

// --- evaluation ---

type evalReq struct {
	Cmd    string `json:"cmd"`
	ID     int64  `json:"id"`
	Packet Flow   `json:"packet"`
}

type evalResp struct {
	ID      int64   `json:"id"`
	Matches []Match `json:"matches"`
	Error   string  `json:"error"`
}

type loadReq struct {
	Cmd     string       `json:"cmd"`
	Scripts []scriptSpec `json:"scripts"`
}

type loadResp struct {
	Ok     bool              `json:"ok"`
	Errors map[string]string `json:"errors"`
}

// Evaluate runs all enabled scripts against flow synchronously and returns the
// matches. Returns nil when the engine is unavailable or has no enabled
// scripts. Safe for concurrent use (evaluations are serialized).
func (m *Manager) Evaluate(flow Flow) []Match {
	if !m.available || !m.hasEnabled() {
		return nil
	}
	m.wmu.Lock()
	defer m.wmu.Unlock()
	if err := m.ensureWorkerLocked(); err != nil {
		m.lastErr = err.Error()
		return nil
	}
	var resp evalResp
	if err := m.worker.roundtrip(evalReq{Cmd: "eval", Packet: flow}, m.cfg.EvalTimeout, &resp); err != nil {
		m.lastErr = err.Error()
		m.worker = nil // force respawn next time
		return nil
	}
	return resp.Matches
}

// ensureWorkerLocked spawns the worker if needed and (re)loads the enabled
// scripts when the generation changed. Caller holds wmu.
func (m *Manager) ensureWorkerLocked() error {
	if m.worker == nil || m.worker.isDead() {
		w, err := spawnWorker(m.pythonPath, harness)
		if err != nil {
			return err
		}
		m.worker = w
		m.loadedGen = -1
	}
	specs, gen := m.enabledSpecsAndGen()
	if gen != m.loadedGen {
		var resp loadResp
		if err := m.worker.roundtrip(loadReq{Cmd: "load", Scripts: specs}, m.cfg.EvalTimeout, &resp); err != nil {
			m.worker = nil
			return err
		}
		m.loadedGen = gen
		if len(resp.Errors) > 0 {
			m.lastErr = "script errors: " + firstError(resp.Errors)
		} else {
			m.lastErr = ""
		}
	}
	return nil
}

func firstError(errs map[string]string) string {
	for id, e := range errs {
		return id + ": " + e
	}
	return ""
}

// Submit queues a flow for asynchronous evaluation. Non-blocking: when the
// backlog is full the flow is dropped (live tagging is best-effort).
func (m *Manager) Submit(flow Flow) {
	if !m.available || !m.hasEnabled() {
		return
	}
	select {
	case m.queue <- flow:
	default:
	}
}

func (m *Manager) runPipeline() {
	for {
		select {
		case <-m.stopped:
			return
		case flow := <-m.queue:
			matches := m.Evaluate(flow)
			if m.cfg.OnMatch != nil {
				for _, mt := range matches {
					m.cfg.OnMatch(flow, mt)
				}
			}
		}
	}
}

// Test evaluates a single (possibly unsaved) script against a sample flow in an
// isolated worker, without touching the live worker or its state. Returns the
// matches, a compile/definition error message (if the script is invalid), and a
// transport error.
func (m *Manager) Test(name, code string, flow Flow) ([]Match, string, error) {
	if !m.available {
		return nil, "", errors.New("python interpreter not available")
	}
	w, err := spawnWorker(m.pythonPath, harness)
	if err != nil {
		return nil, "", err
	}
	defer w.stop()

	type testReq struct {
		Cmd    string     `json:"cmd"`
		ID     int64      `json:"id"`
		Script scriptSpec `json:"script"`
		Packet Flow       `json:"packet"`
	}
	var resp evalResp
	req := testReq{Cmd: "test", Script: scriptSpec{ID: "test", Name: name, Code: code}, Packet: flow}
	if err := w.roundtrip(req, m.cfg.EvalTimeout, &resp); err != nil {
		return nil, "", err
	}
	return resp.Matches, resp.Error, nil
}

// Close stops the pipeline and terminates the worker.
func (m *Manager) Close() {
	m.stopOnce.Do(func() {
		close(m.stopped)
	})
	m.wmu.Lock()
	if m.worker != nil {
		m.worker.stop()
		m.worker = nil
	}
	m.wmu.Unlock()
}
