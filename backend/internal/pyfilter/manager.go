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
	"encoding/base64"
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
	// EvalTimeout bounds a single async evaluation before the worker is killed.
	// Defaults to 2s.
	EvalTimeout time.Duration
	// BlockTimeout bounds a single synchronous (inline blocking) evaluation on
	// the request hot path. Kept short so a stuck script can never stall traffic
	// for long — on timeout the request fails open (is forwarded). Defaults to
	// 100ms.
	BlockTimeout time.Duration
	// QueueSize bounds the async Submit backlog. Defaults to 1024.
	QueueSize int
	// OnMatch is invoked (from a background goroutine) for every match produced
	// by Submit. Optional.
	OnMatch func(flow Flow, m Match)
}

// Status is a snapshot of engine health for the API/UI.
type Status struct {
	Available     bool   `json:"available"` // python3 interpreter found
	PythonPath    string `json:"python_path,omitempty"`
	WorkerHealthy bool   `json:"worker_healthy"` // a live worker is running
	ScriptCount   int    `json:"script_count"`
	EnabledCount  int    `json:"enabled_count"`
	BlockingCount int    `json:"blocking_count"` // enabled scripts that run inline
	LastError     string `json:"last_error,omitempty"`
}

// lane is one evaluation context: a long-lived worker that loads exactly one
// subset of the enabled scripts (blocking vs non-blocking). Keeping the two
// subsets in separate workers guarantees each script's match() runs in exactly
// one place, so stateful counters are never double-incremented.
type lane struct {
	blocking  bool          // loads enabled scripts whose Blocking == this
	timeout   time.Duration // per-eval timeout
	mu        sync.Mutex
	worker    *worker
	loadedGen int
}

// Manager owns the script set and the Python workers.
type Manager struct {
	cfg        Config
	pythonPath string
	available  bool

	// scripts state
	smu     sync.Mutex
	scripts []Script
	gen     int // bumped on every script-set change
	path    string

	// evaluation lanes
	async lane // non-blocking scripts (async Submit pipeline)
	block lane // blocking scripts (synchronous, request hot path)

	errMu   sync.Mutex
	lastErr string

	queue    chan Flow
	stopOnce sync.Once
	stopped  chan struct{}
}

func (m *Manager) setLastErr(s string) {
	m.errMu.Lock()
	m.lastErr = s
	m.errMu.Unlock()
}

func (m *Manager) lastErrStr() string {
	m.errMu.Lock()
	defer m.errMu.Unlock()
	return m.lastErr
}

// NewManager detects python3, loads persisted scripts, and starts the async
// evaluation pipeline. It never fails hard: when python3 is missing the engine
// simply reports Available=false and evaluates nothing.
func NewManager(cfg Config) *Manager {
	if cfg.EvalTimeout <= 0 {
		cfg.EvalTimeout = 2 * time.Second
	}
	if cfg.BlockTimeout <= 0 {
		cfg.BlockTimeout = 100 * time.Millisecond
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 1024
	}
	m := &Manager{
		cfg:     cfg,
		path:    cfg.DataDir + "/pyfilters.json",
		async:   lane{blocking: false, timeout: cfg.EvalTimeout, loadedGen: -1},
		block:   lane{blocking: true, timeout: cfg.BlockTimeout, loadedGen: -1},
		queue:   make(chan Flow, cfg.QueueSize),
		stopped: make(chan struct{}),
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
func (m *Manager) CreateScript(name, code string, enabled, blocking bool) (Script, error) {
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
	s := Script{ID: id, Name: name, Code: code, Enabled: enabled, Blocking: blocking, CreatedAt: now, UpdatedAt: now}
	m.scripts = append(m.scripts, s)
	m.persistAndBumpLocked()
	return s, nil
}

// UpdateScript mutates an existing script's name/code/enabled/blocking.
func (m *Manager) UpdateScript(id, name, code string, enabled, blocking bool) (Script, error) {
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
	m.scripts[i].Blocking = blocking
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
		m.setLastErr("saving scripts: " + err.Error())
	}
}

// enabledSpecsAndGen snapshots the enabled scripts in one lane's subset
// (Blocking == blocking) plus the current generation.
func (m *Manager) enabledSpecsAndGen(blocking bool) ([]scriptSpec, int) {
	m.smu.Lock()
	defer m.smu.Unlock()
	specs := make([]scriptSpec, 0, len(m.scripts))
	for _, s := range m.scripts {
		if s.Enabled && s.Blocking == blocking {
			specs = append(specs, scriptSpec{ID: s.ID, Name: s.Name, Code: s.Code})
		}
	}
	return specs, m.gen
}

func (m *Manager) hasEnabled(blocking bool) bool {
	m.smu.Lock()
	defer m.smu.Unlock()
	for _, s := range m.scripts {
		if s.Enabled && s.Blocking == blocking {
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
	enabled, blocking := 0, 0
	for _, s := range m.scripts {
		if s.Enabled {
			enabled++
			if s.Blocking {
				blocking++
			}
		}
	}
	m.smu.Unlock()

	return Status{
		Available:     m.available,
		PythonPath:    m.pythonPath,
		WorkerHealthy: m.async.healthy() || m.block.healthy(),
		ScriptCount:   total,
		EnabledCount:  enabled,
		BlockingCount: blocking,
		LastError:     m.lastErrStr(),
	}
}

func (l *lane) healthy() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.worker != nil && !l.worker.isDead()
}

// --- evaluation ---

type evalReq struct {
	Cmd    string `json:"cmd"`
	ID     int64  `json:"id"`
	Packet Flow   `json:"packet"`
}

type evalResp struct {
	ID      int64        `json:"id"`
	Matches []Match      `json:"matches"`
	Rewrite *rewriteWire `json:"rewrite"`
	Error   string       `json:"error"`
}

// rewriteWire carries a script's inline content rewrite (base64 of the new
// exact bytes) so binary/TCP payloads survive JSON transport.
type rewriteWire struct {
	ContentB64 string `json:"content_b64"`
}

// decodeRewrite turns a harness rewrite reply into new content bytes (nil when
// there was no rewrite or the payload is malformed).
func decodeRewrite(rw *rewriteWire) []byte {
	if rw == nil || rw.ContentB64 == "" {
		return nil
	}
	b, err := base64.StdEncoding.DecodeString(rw.ContentB64)
	if err != nil {
		return nil
	}
	return b
}

type loadReq struct {
	Cmd     string       `json:"cmd"`
	Scripts []scriptSpec `json:"scripts"`
}

type loadResp struct {
	Ok     bool              `json:"ok"`
	Errors map[string]string `json:"errors"`
}

// Evaluate runs the enabled non-blocking scripts against flow synchronously and
// returns the matches. Returns nil when the engine is unavailable or has no
// enabled non-blocking scripts. Used by the async Submit pipeline.
func (m *Manager) Evaluate(flow Flow) []Match {
	if !m.available || !m.hasEnabled(false) {
		return nil
	}
	matches, _ := m.evalLane(&m.async, flow) // async can't mutate — drop any rewrite
	return matches
}

// EvaluateBlocking runs the enabled blocking scripts against flow synchronously
// on the request hot path. It is bounded by a short timeout and fails open
// (nil, nil = no block, no rewrite) if the worker stalls or dies, so a bad
// script never stalls traffic. Returns the matches (each Block flag says whether
// to drop now) and, when a script rewrote the content inline, the new bytes to
// forward.
func (m *Manager) EvaluateBlocking(flow Flow) ([]Match, []byte) {
	if !m.available || !m.hasEnabled(true) {
		return nil, nil
	}
	return m.evalLane(&m.block, flow)
}

// evalLane ensures the lane's worker is up with the right scripts loaded, then
// runs one evaluation. On any transport error the worker is discarded (respawned
// next call) and (nil, nil) is returned.
func (m *Manager) evalLane(l *lane, flow Flow) ([]Match, []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := m.ensureLaneLocked(l); err != nil {
		m.setLastErr(err.Error())
		return nil, nil
	}
	var resp evalResp
	if err := l.worker.roundtrip(evalReq{Cmd: "eval", Packet: flow}, l.timeout, &resp); err != nil {
		m.setLastErr(err.Error())
		l.worker = nil // force respawn next time
		return nil, nil
	}
	return resp.Matches, decodeRewrite(resp.Rewrite)
}

// ensureLaneLocked spawns the lane's worker if needed and (re)loads its script
// subset when the generation changed. Caller holds l.mu.
func (m *Manager) ensureLaneLocked(l *lane) error {
	if l.worker == nil || l.worker.isDead() {
		w, err := spawnWorker(m.pythonPath, harness)
		if err != nil {
			return err
		}
		l.worker = w
		l.loadedGen = -1
	}
	specs, gen := m.enabledSpecsAndGen(l.blocking)
	if gen != l.loadedGen {
		var resp loadResp
		// Loading compiles+execs the scripts (top-level code runs); use the
		// generous eval timeout, not the tight per-request block timeout.
		if err := l.worker.roundtrip(loadReq{Cmd: "load", Scripts: specs}, m.cfg.EvalTimeout, &resp); err != nil {
			l.worker = nil
			return err
		}
		l.loadedGen = gen
		if len(resp.Errors) > 0 {
			m.setLastErr("script errors: " + firstError(resp.Errors))
		} else {
			m.setLastErr("")
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
	if !m.available || !m.hasEnabled(false) {
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

// testResp is the harness reply to a test command.
type testResp struct {
	ID      int64        `json:"id"`
	Steps   []stepResult `json:"steps"`
	Matches []Match      `json:"matches"`
	Error   string       `json:"error"`
}

type stepResult struct {
	Matches []Match      `json:"matches"`
	Rewrite *rewriteWire `json:"rewrite"`
}

// TestStep is one packet's result in a sequence test: its matches plus, when a
// script rewrote the content inline, the new bytes (so the tester can preview
// the rewrite).
type TestStep struct {
	Matches []Match
	Rewrite []byte
}

// TestSequence evaluates a (possibly unsaved) script against an ordered sequence
// of flows — a whole reconstructed flow, or a single packet — in an isolated
// worker, without touching the live worker or its state. match() is called on
// each flow in turn so stateful/correlating scripts see the sequence; repeat
// re-runs the whole sequence N times (>=1). Returns one match list per flow (in
// order, from the last pass), a compile/definition error message, and a
// transport error.
func (m *Manager) TestSequence(name, code string, flows []Flow, repeat int) ([]TestStep, string, error) {
	if !m.available {
		return nil, "", errors.New("python interpreter not available")
	}
	if repeat < 1 {
		repeat = 1
	}
	if len(flows) == 0 {
		flows = []Flow{{}}
	}
	w, err := spawnWorker(m.pythonPath, harness)
	if err != nil {
		return nil, "", err
	}
	defer w.stop()

	type testReq struct {
		Cmd     string     `json:"cmd"`
		ID      int64      `json:"id"`
		Script  scriptSpec `json:"script"`
		Repeat  int        `json:"repeat"`
		Packets []Flow     `json:"packets"`
	}
	var resp testResp
	req := testReq{Cmd: "test", Script: scriptSpec{ID: "test", Name: name, Code: code}, Repeat: repeat, Packets: flows}
	// The whole sequence runs inside one roundtrip; scale the timeout with work.
	timeout := m.cfg.EvalTimeout + time.Duration(repeat*len(flows))*10*time.Millisecond
	if err := w.roundtrip(req, timeout, &resp); err != nil {
		return nil, "", err
	}
	steps := make([]TestStep, len(resp.Steps))
	for i, s := range resp.Steps {
		steps[i] = TestStep{Matches: s.Matches, Rewrite: decodeRewrite(s.Rewrite)}
	}
	return steps, resp.Error, nil
}

// Test evaluates a script against a single flow, repeat times, returning the
// verdict from the last run. Convenience wrapper over TestSequence.
func (m *Manager) Test(name, code string, flow Flow, repeat int) ([]Match, string, error) {
	steps, scriptErr, err := m.TestSequence(name, code, []Flow{flow}, repeat)
	if err != nil || scriptErr != "" {
		return nil, scriptErr, err
	}
	if len(steps) == 0 {
		return nil, "", nil
	}
	return steps[len(steps)-1].Matches, "", nil
}

// Close stops the pipeline and terminates both lane workers.
func (m *Manager) Close() {
	m.stopOnce.Do(func() {
		close(m.stopped)
	})
	for _, l := range []*lane{&m.async, &m.block} {
		l.mu.Lock()
		if l.worker != nil {
			l.worker.stop()
			l.worker = nil
		}
		l.mu.Unlock()
	}
}
