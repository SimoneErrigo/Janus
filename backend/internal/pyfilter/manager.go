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
	"sort"
	"strings"
	"sync"
	"sync/atomic"
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
	Enabled       bool   `json:"enabled"`   // live traffic evaluation master switch
	PythonPath    string `json:"python_path,omitempty"`
	WorkerHealthy bool   `json:"worker_healthy"` // a live worker is running
	ScriptCount   int    `json:"script_count"`
	EnabledCount  int    `json:"enabled_count"`
	BlockingCount int    `json:"blocking_count"` // enabled scripts that run inline
	LastError     string `json:"last_error,omitempty"`
	QueueDepth    int    `json:"queue_depth"`
	QueueCapacity int    `json:"queue_capacity"`
	QueueDropped  uint64 `json:"queue_dropped"`
	Evaluated     uint64 `json:"evaluated"`
}

// lane is one evaluation context: a long-lived worker that loads exactly one
// subset of the enabled scripts (blocking vs non-blocking). Keeping the two
// subsets in separate workers guarantees each script's match() runs in exactly
// one place, so stateful counters are never double-incremented.
type lane struct {
	blocking  bool          // loads enabled scripts whose Blocking == this
	service   string        // blocking lanes compile only this service's scripts
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

	// runtimeEnabled is the live-traffic master switch. It is deliberately
	// separate from each script's Enabled flag: scripts remain persisted and
	// editable while live Python evaluation is paused. runtimeMu serializes
	// transitions so a concurrent enable cannot race a disable tearing workers
	// down underneath it.
	runtimeMu      sync.Mutex
	runtimeEnabled atomic.Bool

	// scripts state
	smu     sync.Mutex
	scripts []Script
	gen     int // bumped on every script-set change
	path    string
	loadErr error // keeps an unreadable store read-only until a clean restart

	// evaluation lanes
	async          lane // non-blocking scripts (async Submit pipeline)
	blockMu        sync.Mutex
	blockByService map[string]*lane
	prewarmMu      sync.Mutex
	serviceIDs     map[string]struct{}
	recoveryMu     sync.Mutex
	recoveryQueued map[string]struct{}
	recoveryQueue  chan string
	recoveryDone   chan struct{}

	errMu   sync.Mutex
	lastErr string

	queue        chan Flow
	queueMu      sync.Mutex // serializes Submit with closing the queue
	closeOnce    sync.Once
	closing      chan struct{} // closed when shutdown starts; bounds callbacks
	pipelineDone chan struct{}
	closedDone   chan struct{}
	closed       atomic.Bool
	tracker      flowTracker
	queueDropped atomic.Uint64
	evaluated    atomic.Uint64
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
		cfg:            cfg,
		path:           cfg.DataDir + "/pyfilters.json",
		async:          lane{blocking: false, timeout: cfg.EvalTimeout, loadedGen: -1},
		blockByService: make(map[string]*lane),
		serviceIDs:     make(map[string]struct{}),
		recoveryQueued: make(map[string]struct{}),
		recoveryQueue:  make(chan string, 64),
		recoveryDone:   make(chan struct{}),
		queue:          make(chan Flow, cfg.QueueSize),
		closing:        make(chan struct{}),
		pipelineDone:   make(chan struct{}),
		closedDone:     make(chan struct{}),
	}

	m.pythonPath = cfg.PythonPath
	if m.pythonPath == "" {
		m.pythonPath = detectPython()
	}
	m.available = m.pythonPath != ""
	m.runtimeEnabled.Store(true)

	if scripts, err := loadScripts(m.path); err == nil {
		m.scripts = scripts
	} else {
		m.scripts = []Script{}
		m.loadErr = err
		m.lastErr = "loading scripts: " + err.Error()
	}

	go m.runPipeline()
	go m.runPrewarmRecovery()
	return m
}

// RuntimeEnabled reports whether live traffic may be evaluated by Python.
// Script CRUD and isolated admin tests remain available while this is false.
func (m *Manager) RuntimeEnabled() bool {
	return m != nil && !m.closed.Load() && m.runtimeEnabled.Load()
}

// SetRuntimeEnabled toggles all live Python evaluation without changing any
// script's own Enabled flag. Disabling is an admission barrier: queued async
// flows are discarded, connection-tracker snapshots are released, and idle
// Python workers are stopped. An evaluation already inside Python is bounded by
// its lane timeout; its result/callback is suppressed after the switch flips.
func (m *Manager) SetRuntimeEnabled(enabled bool) {
	if m == nil {
		return
	}
	m.runtimeMu.Lock()
	defer m.runtimeMu.Unlock()
	if m.closed.Load() {
		m.runtimeEnabled.Store(false)
		return
	}
	if m.runtimeEnabled.Swap(enabled) == enabled {
		return
	}
	if enabled {
		// Script edits made while disabled deliberately skip prewarming. Bring
		// the current inline generation back before returning to live traffic.
		_ = m.PrewarmServices(nil)
		return
	}

	// Pair the second enabled check in Submit with queueMu so no producer can
	// enqueue after this drain has completed.
	m.queueMu.Lock()
	for {
		select {
		case _, ok := <-m.queue:
			if !ok {
				m.queueMu.Unlock()
				return
			}
		default:
			m.queueMu.Unlock()
			m.tracker.reset()
			m.stopEvaluationWorkers()
			return
		}
	}
}

func (m *Manager) stopEvaluationWorkers() {
	m.async.mu.Lock()
	discardLaneWorkerLocked(&m.async)
	m.async.loadedGen = -1
	m.async.mu.Unlock()

	m.blockMu.Lock()
	lanes := make([]*lane, 0, len(m.blockByService))
	for _, l := range m.blockByService {
		lanes = append(lanes, l)
	}
	m.blockMu.Unlock()
	for _, l := range lanes {
		l.mu.Lock()
		discardLaneWorkerLocked(l)
		l.loadedGen = -1
		l.mu.Unlock()
	}
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
	for i := range m.scripts {
		out[i] = cloneScript(m.scripts[i])
	}
	return out
}

// GetScript returns one script by id.
func (m *Manager) GetScript(id string) (Script, bool) {
	m.smu.Lock()
	defer m.smu.Unlock()
	for _, s := range m.scripts {
		if s.ID == id {
			return cloneScript(s), true
		}
	}
	return Script{}, false
}

// CreateScript adds a new script. The id is derived from the name (uniquified).
type ScriptOptions struct {
	Enabled                           bool
	Mode                              string
	ServiceIDs, Directions, Protocols []string
}

func (m *Manager) CreateScript(name, code string, enabled, blocking bool) (Script, error) {
	mode := "observe"
	if blocking {
		mode = "block"
	}
	return m.CreateScriptWith(name, code, ScriptOptions{Enabled: enabled, Mode: mode, ServiceIDs: []string{"*"}})
}

func (m *Manager) CreateScriptWith(name, code string, options ScriptOptions) (Script, error) {
	if name == "" {
		return Script{}, errors.New("name is required")
	}
	m.smu.Lock()

	base := slugID(name)
	id := base
	for i := 2; m.indexOf(id) >= 0; i++ {
		id = fmt.Sprintf("%s-%d", base, i)
	}
	now := time.Now().Unix()
	s := Script{ID: id, Name: name, Code: code, Enabled: options.Enabled, Mode: options.Mode, ServiceIDs: append([]string(nil), options.ServiceIDs...), Directions: append([]string(nil), options.Directions...), Protocols: append([]string(nil), options.Protocols...), CreatedAt: now, UpdatedAt: now}
	s.normalize()
	next := append(cloneScripts(m.scripts), s)
	if err := m.persistAndBumpLocked(next); err != nil {
		m.smu.Unlock()
		return Script{}, err
	}
	m.smu.Unlock()
	_ = m.PrewarmServices(append([]string{"*"}, s.ServiceIDs...))
	return cloneScript(s), nil
}

// UpdateScript mutates an existing script's name/code/enabled/blocking.
func (m *Manager) UpdateScript(id, name, code string, enabled, blocking bool) (Script, error) {
	mode := "observe"
	if blocking {
		mode = "block"
	}
	return m.UpdateScriptWith(id, name, code, ScriptOptions{Enabled: enabled, Mode: mode, ServiceIDs: []string{"*"}})
}

func (m *Manager) UpdateScriptWith(id, name, code string, options ScriptOptions) (Script, error) {
	m.smu.Lock()
	i := m.indexOf(id)
	if i < 0 {
		m.smu.Unlock()
		return Script{}, errNotFound
	}
	next := cloneScripts(m.scripts)
	if name != "" {
		next[i].Name = name
	}
	next[i].Code = code
	next[i].Enabled = options.Enabled
	next[i].Mode = options.Mode
	next[i].ServiceIDs = append([]string(nil), options.ServiceIDs...)
	next[i].Directions = append([]string(nil), options.Directions...)
	next[i].Protocols = append([]string(nil), options.Protocols...)
	next[i].normalize()
	next[i].UpdatedAt = time.Now().Unix()
	s := next[i]
	if err := m.persistAndBumpLocked(next); err != nil {
		m.smu.Unlock()
		return Script{}, err
	}
	m.smu.Unlock()
	_ = m.PrewarmServices(append([]string{"*"}, s.ServiceIDs...))
	return cloneScript(s), nil
}

// SetEnabled toggles a script on/off.
func (m *Manager) SetEnabled(id string, enabled bool) (Script, error) {
	m.smu.Lock()
	i := m.indexOf(id)
	if i < 0 {
		m.smu.Unlock()
		return Script{}, errNotFound
	}
	next := cloneScripts(m.scripts)
	next[i].Enabled = enabled
	next[i].UpdatedAt = time.Now().Unix()
	s := next[i]
	if err := m.persistAndBumpLocked(next); err != nil {
		m.smu.Unlock()
		return Script{}, err
	}
	m.smu.Unlock()
	_ = m.PrewarmServices(append([]string{"*"}, s.ServiceIDs...))
	return cloneScript(s), nil
}

// PrewarmServices registers service IDs and synchronously loads every enabled
// inline script that can match them. Passing nil (or "*") reloads all known
// services after script CRUD. Work is serialized so concurrent saves/starts do
// not spawn duplicate interpreters.
func (m *Manager) PrewarmServices(ids []string) error {
	if m.closed.Load() {
		return nil
	}
	m.prewarmMu.Lock()
	defer m.prewarmMu.Unlock()
	if m.closed.Load() {
		return nil
	}

	all := len(ids) == 0
	targetSet := make(map[string]struct{}, len(ids))
	for _, raw := range ids {
		id := strings.TrimSpace(raw)
		if id == "*" {
			all = true
			continue
		}
		if id == "" {
			continue
		}
		m.serviceIDs[id] = struct{}{}
		targetSet[id] = struct{}{}
	}
	// Registration is useful even while paused: a later runtime enable can
	// synchronously prewarm every already-running service before traffic reaches
	// Python. Only process creation/evaluation is gated by RuntimeEnabled.
	if !m.RuntimeEnabled() || !m.available {
		return nil
	}
	if all {
		for id := range m.serviceIDs {
			targetSet[id] = struct{}{}
		}
		m.blockMu.Lock()
		_, hasFallback := m.blockByService["*"]
		m.blockMu.Unlock()
		// Keep the legacy service-less evaluation path ready (used by direct
		// callers/tests) until real service IDs are registered at startup.
		if (len(targetSet) == 0 || hasFallback) && m.hasEnabledBlockingForService("*") {
			targetSet["*"] = struct{}{}
		}
	}
	targets := make([]string, 0, len(targetSet))
	for id := range targetSet {
		targets = append(targets, id)
	}
	sort.Strings(targets)

	var errs []error
	for _, id := range targets {
		if err := m.prewarmService(id); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", id, err))
		}
	}
	err := errors.Join(errs...)
	if err != nil {
		m.setLastErr("prewarming inline filters: " + err.Error())
	}
	return err
}

func (m *Manager) prewarmService(service string) error {
	if !m.RuntimeEnabled() {
		return nil
	}
	applicable := m.hasEnabledBlockingForService(service)
	m.blockMu.Lock()
	l := m.blockByService[service]
	if l == nil && applicable {
		l = &lane{blocking: true, service: service, timeout: m.cfg.BlockTimeout, loadedGen: -1}
		m.blockByService[service] = l
	}
	m.blockMu.Unlock()
	if l == nil {
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if !m.RuntimeEnabled() {
		return nil
	}
	// A disabled/removed last script leaves no executable hot-path work. Avoid
	// reviving a dead empty lane merely to load an empty script set.
	if !applicable && (l.worker == nil || l.worker.isDead()) {
		l.loadedGen = m.currentGeneration()
		return nil
	}
	return m.ensureLaneLocked(l, m.cfg.EvalTimeout)
}

func (m *Manager) hasEnabledBlockingForService(service string) bool {
	m.smu.Lock()
	defer m.smu.Unlock()
	for _, script := range m.scripts {
		if script.Enabled && script.Blocking &&
			(contains(script.ServiceIDs, "*") || contains(script.ServiceIDs, service)) {
			return true
		}
	}
	return false
}

func (m *Manager) hasServiceSpecificBlocking(service string) bool {
	m.smu.Lock()
	defer m.smu.Unlock()
	for _, script := range m.scripts {
		if script.Enabled && script.Blocking && !contains(script.ServiceIDs, "*") &&
			contains(script.ServiceIDs, service) {
			return true
		}
	}
	return false
}

func (m *Manager) currentGeneration() int {
	m.smu.Lock()
	defer m.smu.Unlock()
	return m.gen
}

func (m *Manager) schedulePrewarm(service string) {
	service = strings.TrimSpace(service)
	if service == "" || !m.RuntimeEnabled() {
		return
	}
	m.recoveryMu.Lock()
	if _, queued := m.recoveryQueued[service]; queued {
		m.recoveryMu.Unlock()
		return
	}
	m.recoveryQueued[service] = struct{}{}
	m.recoveryMu.Unlock()

	select {
	case m.recoveryQueue <- service:
	case <-m.closing:
		m.recoveryMu.Lock()
		delete(m.recoveryQueued, service)
		m.recoveryMu.Unlock()
	default:
		m.recoveryMu.Lock()
		delete(m.recoveryQueued, service)
		m.recoveryMu.Unlock()
	}
}

func (m *Manager) runPrewarmRecovery() {
	defer close(m.recoveryDone)
	for {
		select {
		case <-m.closing:
			return
		case service := <-m.recoveryQueue:
			_ = m.PrewarmServices([]string{service})
			m.recoveryMu.Lock()
			delete(m.recoveryQueued, service)
			m.recoveryMu.Unlock()
		}
	}
}

// DeleteScript removes a script by id.
func (m *Manager) DeleteScript(id string) error {
	m.smu.Lock()
	i := m.indexOf(id)
	if i < 0 {
		m.smu.Unlock()
		return errNotFound
	}
	next := cloneScripts(m.scripts)
	next = append(next[:i], next[i+1:]...)
	if err := m.persistAndBumpLocked(next); err != nil {
		m.smu.Unlock()
		return err
	}
	m.smu.Unlock()
	_ = m.PrewarmServices(nil)
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

// persistAndBumpLocked persists a candidate script set before publishing it.
// Caller holds smu; failed writes leave both the live set and generation intact.
func (m *Manager) persistAndBumpLocked(next []Script) error {
	if m.loadErr != nil {
		err := fmt.Errorf("pyfilter store is unreadable; refusing to overwrite it (fix or move the file, then restart): %w", m.loadErr)
		m.setLastErr(err.Error())
		return err
	}
	if err := saveScripts(m.path, next); err != nil {
		err = fmt.Errorf("saving scripts: %w", err)
		m.setLastErr(err.Error())
		return err
	}
	m.scripts = next
	m.gen++
	return nil
}

func cloneScript(s Script) Script {
	s.ServiceIDs = append([]string(nil), s.ServiceIDs...)
	s.Directions = append([]string(nil), s.Directions...)
	s.Protocols = append([]string(nil), s.Protocols...)
	return s
}

func cloneScripts(scripts []Script) []Script {
	out := make([]Script, len(scripts))
	for i := range scripts {
		out[i] = cloneScript(scripts[i])
	}
	return out
}

// enabledSpecsAndGen snapshots the enabled scripts in one lane's subset
// (Blocking == blocking) plus the current generation.
func (m *Manager) enabledSpecsAndGen(blocking bool, service string) ([]scriptSpec, int) {
	m.smu.Lock()
	defer m.smu.Unlock()
	specs := make([]scriptSpec, 0, len(m.scripts))
	for _, s := range m.scripts {
		if s.Enabled && s.Blocking == blocking {
			if service != "" && !contains(s.ServiceIDs, "*") && !contains(s.ServiceIDs, service) {
				continue
			}
			specs = append(specs, scriptSpec{ID: s.ID, Name: s.Name, Code: s.Code, ServiceIDs: s.ServiceIDs, Directions: s.Directions, Protocols: s.Protocols})
		}
	}
	return specs, m.gen
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
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

// ShouldEvaluateBlocking reports whether live inline processing is needed for
// the supplied scope. An empty direction intentionally ignores direction
// scopes: callers use that cheap query before building a flow so messages that
// do not themselves match can still update connection history for a later
// stateful script. HTTP passes an exact response direction separately when it
// decides whether response buffering is necessary.
func (m *Manager) ShouldEvaluateBlocking(service, direction, protocol string) bool {
	if !m.RuntimeEnabled() || !m.available {
		return false
	}
	m.smu.Lock()
	defer m.smu.Unlock()
	for _, script := range m.scripts {
		if !script.Enabled || !script.Blocking ||
			(!contains(script.ServiceIDs, "*") && !contains(script.ServiceIDs, service)) ||
			(direction != "" && len(script.Directions) > 0 && !contains(script.Directions, direction)) ||
			(len(script.Protocols) > 0 && !containsFold(script.Protocols, protocol)) {
			continue
		}
		return true
	}
	return false
}

// ShouldSubmitAsync reports whether a captured message for service/protocol is
// useful to any live non-blocking script. Direction is deliberately ignored so
// stateful scripts retain the whole connection history. Call this before
// converting a packet into Flow (which copies/stringifies/base64-encodes body
// data) and then call Submit only when it returns true.
func (m *Manager) ShouldSubmitAsync(service, protocol string) bool {
	if !m.RuntimeEnabled() || !m.available {
		return false
	}
	m.smu.Lock()
	defer m.smu.Unlock()
	for _, script := range m.scripts {
		if !script.Enabled || script.Blocking ||
			(!contains(script.ServiceIDs, "*") && !contains(script.ServiceIDs, service)) ||
			(len(script.Protocols) > 0 && !containsFold(script.Protocols, protocol)) {
			continue
		}
		return true
	}
	return false
}

func containsFold(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(value, want) {
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

	blockHealthy := false
	m.blockMu.Lock()
	for _, lane := range m.blockByService {
		if lane.healthy() {
			blockHealthy = true
			break
		}
	}
	m.blockMu.Unlock()
	return Status{
		Available:     m.available,
		Enabled:       m.RuntimeEnabled(),
		PythonPath:    m.pythonPath,
		WorkerHealthy: m.async.healthy() || blockHealthy,
		ScriptCount:   total,
		EnabledCount:  enabled,
		BlockingCount: blocking,
		LastError:     m.lastErrStr(),
		QueueDepth:    len(m.queue), QueueCapacity: cap(m.queue), QueueDropped: m.queueDropped.Load(), Evaluated: m.evaluated.Load(),
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
	ID      int64         `json:"id"`
	Matches []Match       `json:"matches"`
	Rewrite *rewriteWire  `json:"rewrite"`
	Error   string        `json:"error"`
	Console []ConsoleLine `json:"console,omitempty"`
}

// rewriteWire carries a script's inline content rewrite (base64 of the new
// exact bytes) so binary/TCP payloads survive JSON transport.
type rewriteWire struct {
	ContentB64 string `json:"content_b64"`
}

// decodeRewrite turns a harness rewrite reply into new content bytes (nil when
// there was no rewrite or the payload is malformed).
func decodeRewrite(rw *rewriteWire) []byte {
	if rw == nil {
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
	if !m.RuntimeEnabled() {
		return nil
	}
	canonical, tracked := m.tracker.prepare(flow)
	m.tracker.commit(tracked, admittedByCaller(flow))
	m.tracker.forget(tracked)
	if !m.available || !m.hasEnabled(false) {
		return nil
	}
	matches, _ := m.evalLane(&m.async, canonical, false) // async can't mutate — drop any rewrite
	return matches
}

// EvaluateBlocking runs the enabled blocking scripts against flow synchronously
// on the request hot path. It is bounded by a short timeout and fails open
// (nil, nil = no block, no rewrite) if the worker stalls or dies, so a bad
// script never stalls traffic. Returns the matches (each Block flag says whether
// to drop now) and, when a script rewrote the content inline, the new bytes to
// forward.
func (m *Manager) EvaluateBlocking(flow Flow) ([]Match, []byte) {
	if !m.RuntimeEnabled() {
		return nil, nil
	}
	canonical, tracked := m.tracker.prepare(flow)
	admitted := admittedByCaller(flow)
	service := stringValue(canonical["service"])
	direction := stringValue(canonical["direction"])
	protocol := stringValue(canonical["protocol"])
	if !m.ShouldEvaluateBlocking(service, direction, protocol) {
		m.tracker.commit(tracked, admitted)
		return nil, nil
	}
	if service == "" {
		service = "*"
	}
	needsDedicatedLane := service != "*" && m.hasServiceSpecificBlocking(service)
	m.blockMu.Lock()
	if m.closed.Load() {
		m.blockMu.Unlock()
		return nil, nil
	}
	l := m.blockByService[service]
	if l == nil && !needsDedicatedLane {
		l = m.blockByService["*"]
	}
	if l == nil {
		l = &lane{blocking: true, service: service, timeout: m.cfg.BlockTimeout, loadedGen: -1}
		m.blockByService[service] = l
	}
	m.blockMu.Unlock()
	matches, rewritten := m.evalLane(l, canonical, false)
	if enforceableByCaller(flow) {
		for _, match := range matches {
			if match.Block {
				admitted = false
				break
			}
		}
	}
	m.tracker.commit(tracked, admitted)
	return matches, rewritten
}

// ReconcileBlocking updates the shared connection counters with the final
// admitted/drop/rewrite shape for an event already evaluated inline. It never
// invokes Python; the later persisted Submit reuses the event snapshot and
// performs the normal deduplication/forget lifecycle.
func (m *Manager) ReconcileBlocking(flow Flow) {
	if !m.RuntimeEnabled() {
		return
	}
	_, tracked := m.tracker.prepare(flow)
	m.tracker.commit(tracked, admittedByCaller(flow))
}

func admittedByCaller(flow Flow) bool {
	value, supplied := flow["admitted"]
	return !supplied || boolValue(value)
}

func enforceableByCaller(flow Flow) bool {
	value, supplied := flow["enforceable"]
	return !supplied || boolValue(value)
}

// evalLane ensures the lane's worker is up with the right scripts loaded, then
// runs one evaluation. On any transport error the worker is discarded (respawned
// next call) and (nil, nil) is returned.
func (m *Manager) evalLane(l *lane, flow Flow, drain bool) ([]Match, []byte) {
	if !m.RuntimeEnabled() {
		return nil, nil
	}
	started := time.Now()
	if l.blocking {
		// Inline traffic must never wait behind another request. Busy lanes fail
		// open immediately; the active request remains bounded by BlockTimeout.
		if !l.mu.TryLock() {
			return nil, nil
		}
	} else {
		l.mu.Lock()
	}
	defer l.mu.Unlock()
	if !m.RuntimeEnabled() {
		return nil, nil
	}
	var remaining time.Duration
	if l.blocking {
		// Worker creation and script compilation never happen on the proxy hot
		// path. A missing/dead/stale lane fails open and one bounded recovery
		// worker reloads it outside the request.
		if l.worker == nil || l.worker.isDead() || l.loadedGen != m.currentGeneration() {
			m.schedulePrewarm(l.service)
			return nil, nil
		}
		remaining = l.timeout
	} else {
		remaining = l.timeout - time.Since(started)
		if remaining <= 0 {
			return nil, nil
		}
		if err := m.ensureLaneLocked(l, remaining); err != nil {
			m.setLastErr(err.Error())
			return nil, nil
		}
		remaining = l.timeout - time.Since(started)
	}
	if remaining <= 0 {
		return nil, nil
	}
	var resp evalResp
	if err := l.worker.roundtrip(evalReq{Cmd: "eval", Packet: flow}, remaining, &resp); err != nil {
		m.setLastErr(err.Error())
		discardLaneWorkerLocked(l) // force a clean respawn next time
		if l.blocking {
			m.schedulePrewarm(l.service)
		}
		return nil, nil
	}
	if !m.RuntimeEnabled() {
		return nil, nil
	}
	m.evaluated.Add(1)
	return resp.Matches, decodeRewrite(resp.Rewrite)
}

// ensureLaneLocked spawns the lane's worker if needed and (re)loads its script
// subset when the generation changed. Caller holds l.mu. Inline callers use it
// only from PrewarmServices, never while forwarding traffic.
func (m *Manager) ensureLaneLocked(l *lane, loadTimeout time.Duration) error {
	if !m.RuntimeEnabled() {
		return nil
	}
	if l.worker == nil || l.worker.isDead() {
		w, err := spawnWorker(m.pythonPath, harness)
		if err != nil {
			return err
		}
		l.worker = w
		l.loadedGen = -1
	}
	specs, gen := m.enabledSpecsAndGen(l.blocking, l.service)
	if gen != l.loadedGen {
		var resp loadResp
		if err := l.worker.roundtrip(loadReq{Cmd: "load", Scripts: specs}, loadTimeout, &resp); err != nil {
			discardLaneWorkerLocked(l)
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

func discardLaneWorkerLocked(l *lane) {
	if l.worker != nil {
		l.worker.stop()
		l.worker = nil
	}
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
	if !m.RuntimeEnabled() {
		return
	}
	canonical, tracked := m.tracker.prepare(flow)
	m.tracker.commit(tracked, admittedByCaller(flow))
	m.tracker.forget(tracked)
	if !m.available || !m.hasEnabled(false) {
		return
	}
	m.queueMu.Lock()
	defer m.queueMu.Unlock()
	if !m.RuntimeEnabled() {
		return
	}
	select {
	case m.queue <- canonical:
	default:
		m.queueDropped.Add(1)
	}
}

func (m *Manager) runPipeline() {
	defer close(m.pipelineDone)
	for flow := range m.queue {
		var matches []Match
		if m.RuntimeEnabled() && m.available && m.hasEnabled(false) {
			matches, _ = m.evalLane(&m.async, flow, true)
		}
		if m.RuntimeEnabled() {
			m.runCallbacksBounded(flow, matches)
		}
	}
}

// runCallbacksBounded preserves synchronous callback ordering during normal
// operation. Once shutdown starts, an arbitrary callback gets at most
// EvalTimeout: running it off the pipeline goroutine then also makes callback ->
// Close re-entrant instead of waiting on itself forever.
func (m *Manager) runCallbacksBounded(flow Flow, matches []Match) {
	if !m.RuntimeEnabled() || m.cfg.OnMatch == nil || len(matches) == 0 {
		return
	}
	valid := make([]Match, 0, len(matches))
	for _, mt := range matches {
		if mt.Error {
			m.setLastErr(mt.Script + ": " + mt.Reason)
			continue
		}
		valid = append(valid, mt)
	}
	if len(valid) == 0 {
		return
	}

	type callbackResult struct{ panicValue any }
	done := make(chan callbackResult, 1)
	expired := make(chan struct{})
	go func() {
		defer func() { done <- callbackResult{panicValue: recover()} }()
		for _, mt := range valid {
			if !m.RuntimeEnabled() {
				return
			}
			select {
			case <-expired:
				return
			default:
			}
			m.cfg.OnMatch(flow, mt)
		}
	}()

	recordPanic := func(result callbackResult) {
		if result.panicValue != nil {
			m.setLastErr(fmt.Sprintf("pyfilter callback panic: %v", result.panicValue))
		}
	}
	select {
	case result := <-done:
		recordPanic(result)
	case <-m.closing:
		timer := time.NewTimer(m.cfg.EvalTimeout)
		defer timer.Stop()
		select {
		case result := <-done:
			recordPanic(result)
		case <-timer.C:
			close(expired)
			m.setLastErr("pyfilter callback timed out during shutdown")
		}
	}
}

// ValidateScript compiles/loads code without executing match().
func (m *Manager) ValidateScript(name, code string) (string, error) {
	if !m.available {
		return "", errors.New("python interpreter not available")
	}
	w, err := spawnWorker(m.pythonPath, harness)
	if err != nil {
		return "", err
	}
	defer w.stop()
	var resp loadResp
	if err := w.roundtrip(loadReq{Cmd: "load", Scripts: []scriptSpec{{ID: "validate", Name: name, Code: code}}}, m.cfg.EvalTimeout, &resp); err != nil {
		return "", err
	}
	return resp.Errors["validate"], nil
}

// TestStep is one packet's result in a sequence test: its matches plus, when a
// script rewrote the content inline, the new bytes (so the tester can preview
// the rewrite).
type TestStep struct {
	Matches []Match
	Rewrite []byte
	Console []ConsoleLine
}

// TestSequence evaluates a (possibly unsaved) script against an ordered sequence
// of flows — a whole reconstructed flow, or a single packet — in an isolated
// worker, without touching the live worker or its state. match() is called on
// each flow in turn so stateful/correlating scripts see the sequence; repeat
// re-runs the whole sequence N times (>=1). Returns one match list per flow (in
// order, from the last pass), a compile/definition error message, and a
// transport error.
func (m *Manager) TestSequence(name, code string, flows []Flow, repeat int) ([]TestStep, string, error) {
	// Legacy direct callers expect drop/rewrite directives to be previewed.
	return m.TestSequenceScoped(name, code, flows, repeat, ScriptOptions{Mode: "rewrite", ServiceIDs: []string{"*"}})
}

// TestSequenceScoped mirrors a saved filter's mode and scopes while keeping an
// isolated worker/tracker, so dry-runs neither read nor mutate live state.
func (m *Manager) TestSequenceScoped(name, code string, flows []Flow, repeat int, options ScriptOptions) ([]TestStep, string, error) {
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
	if options.Mode == "" {
		options.Mode = "observe"
	}
	spec := scriptSpec{ID: "test", Name: name, Code: code, ServiceIDs: options.ServiceIDs, Directions: options.Directions, Protocols: options.Protocols}
	var loaded loadResp
	if err := w.roundtrip(loadReq{Cmd: "load", Scripts: []scriptSpec{spec}}, m.cfg.EvalTimeout, &loaded); err != nil {
		return nil, "", err
	}
	if message := loaded.Errors["test"]; message != "" {
		return nil, message, nil
	}

	tracker := flowTracker{}
	deadline := time.Now().Add(m.cfg.EvalTimeout + time.Duration(repeat*len(flows))*10*time.Millisecond)
	var steps []TestStep
	for pass := 0; pass < repeat; pass++ {
		steps = make([]TestStep, 0, len(flows))
		for index, raw := range flows {
			input := cloneFlow(raw)
			input["event_id"] = fmt.Sprintf("test/%d/%d/%s", pass, index, stringValue(raw["event_id"]))
			canonical, tracked := tracker.prepare(input)
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return nil, "", errTimeout
			}
			var resp evalResp
			if err := w.roundtrip(evalReq{Cmd: "eval", Packet: canonical}, remaining, &resp); err != nil {
				return nil, "", err
			}
			admitted := admittedByCaller(input)
			if options.Mode != "observe" {
				for _, match := range resp.Matches {
					if match.Block {
						admitted = false
						break
					}
				}
			}
			tracker.commit(tracked, admitted)
			rewrite := decodeRewrite(resp.Rewrite)
			steps = append(steps, TestStep{Matches: resp.Matches, Rewrite: rewrite, Console: resp.Console})
		}
	}
	return steps, "", nil
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
	m.closeOnce.Do(func() {
		m.runtimeMu.Lock()
		m.runtimeEnabled.Store(false)
		// queueMu is the admission barrier: every Submit that won it first has
		// either enqueued or failed before the queue is closed. Later calls see
		// closed and cannot race a send against close(queue).
		m.queueMu.Lock()
		m.closed.Store(true)
		close(m.closing)
		close(m.queue)
		m.queueMu.Unlock()
		m.runtimeMu.Unlock()

		// The queue is finite and every evaluation/callback has a timeout, so this
		// drains all accepted work without an unbounded worker wait.
		<-m.pipelineDone
		<-m.recoveryDone
		// Wait out an explicit admin/startup prewarm that began before closed was
		// published. Later calls observe closed and return immediately.
		m.prewarmMu.Lock()
		m.prewarmMu.Unlock()

		m.blockMu.Lock()
		lanes := []*lane{&m.async}
		for _, l := range m.blockByService {
			lanes = append(lanes, l)
		}
		m.blockMu.Unlock()
		for _, l := range lanes {
			l.mu.Lock()
			if l.worker != nil {
				l.worker.stop()
				l.worker = nil
			}
			l.mu.Unlock()
		}
		close(m.closedDone)
	})
	<-m.closedDone
}
