// Package scoring classifies captured flows with deterministic, explainable
// heuristics. It intentionally contains no AI, model training, or external
// inference: every point is tied to a reason shown to the operator.
package scoring

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	flowmodel "github.com/SimoneErrigo/Janus/backend/internal/flow"
	"github.com/SimoneErrigo/Janus/backend/internal/rounddiff"
	"github.com/SimoneErrigo/Janus/backend/internal/sniffer"
)

const (
	DefaultBaselineStartRound       = 1
	DefaultBaselineEndRound         = 5
	flowIdleTimeout                 = 1500 * time.Millisecond
	maxPendingFlows                 = 4096
	maxBaselineSignaturesPerService = 4096
	maxBaselineOverflowPerService   = 4096
	maxBaselineReplayPackets        = 200000
)

// BaselineConfig fully identifies the deterministic learning window. The
// range is inclusive and a signature becomes trusted only after it appears in
// every configured round.
type BaselineConfig struct {
	CompetitionStart time.Time
	RoundDurationSec int
	StartRound       int
	EndRound         int
	ServiceRanges    map[string]BaselineRange
}

type BaselineRange struct {
	StartRound int `json:"start_round"`
	EndRound   int `json:"end_round"`
}

func NewBaselineConfig(start time.Time, roundDurationSec, startRound, endRound int, serviceRanges map[string]BaselineRange) BaselineConfig {
	cfg := BaselineConfig{
		CompetitionStart: start, RoundDurationSec: roundDurationSec,
		StartRound: startRound, EndRound: endRound, ServiceRanges: serviceRanges,
	}
	return cfg.normalized()
}

func (c BaselineConfig) normalized() BaselineConfig {
	if c.RoundDurationSec <= 0 {
		c.RoundDurationSec = 120
	}
	if c.StartRound <= 0 {
		c.StartRound = DefaultBaselineStartRound
	}
	if c.EndRound < c.StartRound+1 {
		c.EndRound = c.StartRound + (DefaultBaselineEndRound - DefaultBaselineStartRound)
	}
	ranges := make(map[string]BaselineRange, len(c.ServiceRanges))
	for serviceID, rounds := range c.ServiceRanges {
		if serviceID != "" && rounds.StartRound > 0 && rounds.EndRound >= rounds.StartRound+1 {
			ranges[serviceID] = rounds
		}
	}
	c.ServiceRanges = ranges
	c.CompetitionStart = c.CompetitionStart.UTC()
	return c
}

func (c BaselineConfig) RequiredRounds() int {
	c = c.normalized()
	return c.EndRound - c.StartRound + 1
}

func (c BaselineConfig) RangeFor(serviceID string) BaselineRange {
	if rounds, ok := c.ServiceRanges[serviceID]; ok && rounds.StartRound > 0 && rounds.EndRound >= rounds.StartRound+1 {
		return rounds
	}
	start, end := c.StartRound, c.EndRound
	if start <= 0 {
		start = DefaultBaselineStartRound
	}
	if end < start+1 {
		end = start + (DefaultBaselineEndRound - DefaultBaselineStartRound)
	}
	return BaselineRange{StartRound: start, EndRound: end}
}

func (c BaselineConfig) contains(serviceID string, round int) bool {
	rounds := c.RangeFor(serviceID)
	return round >= rounds.StartRound && round <= rounds.EndRound
}

func (c BaselineConfig) roundForTime(at time.Time) int {
	c = c.normalized()
	if c.CompetitionStart.IsZero() || at.Before(c.CompetitionStart) {
		return 0
	}
	return int(at.Sub(c.CompetitionStart)/(time.Duration(c.RoundDurationSec)*time.Second)) + 1
}

func (c BaselineConfig) windows() (sniffer.BaselineWindow, map[string]sniffer.BaselineWindow, bool) {
	c = c.normalized()
	if c.CompetitionStart.IsZero() {
		return sniffer.BaselineWindow{}, nil, false
	}
	duration := time.Duration(c.RoundDurationSec) * time.Second
	window := func(rounds BaselineRange) sniffer.BaselineWindow {
		return sniffer.BaselineWindow{
			From: c.CompetitionStart.Add(time.Duration(rounds.StartRound-1) * duration),
			To:   c.CompetitionStart.Add(time.Duration(rounds.EndRound) * duration),
		}
	}
	serviceWindows := make(map[string]sniffer.BaselineWindow, len(c.ServiceRanges))
	for serviceID, rounds := range c.ServiceRanges {
		serviceWindows[serviceID] = window(rounds)
	}
	return window(BaselineRange{StartRound: c.StartRound, EndRound: c.EndRound}), serviceWindows, true
}

// BaselineEpoch includes both timing and the selected round range, preventing
// persisted signatures from a different learning policy from being reused.
func BaselineEpoch(c BaselineConfig) string {
	c = c.normalized()
	start := "unconfigured"
	if !c.CompetitionStart.IsZero() {
		start = c.CompetitionStart.Format(time.RFC3339Nano)
	}
	epoch := fmt.Sprintf("%s/%ds/r%d-%d", start, c.RoundDurationSec, c.StartRound, c.EndRound)
	if len(c.ServiceRanges) == 0 {
		return epoch
	}
	serviceIDs := make([]string, 0, len(c.ServiceRanges))
	for serviceID := range c.ServiceRanges {
		serviceIDs = append(serviceIDs, serviceID)
	}
	sort.Strings(serviceIDs)
	var overrides strings.Builder
	for _, serviceID := range serviceIDs {
		rounds := c.ServiceRanges[serviceID]
		fmt.Fprintf(&overrides, "/%q:r%d-%d", serviceID, rounds.StartRound, rounds.EndRound)
	}
	return epoch + overrides.String()
}

type baselineDefinition struct {
	CompetitionStart time.Time                `json:"competition_start"`
	RoundDurationSec int                      `json:"round_duration_seconds"`
	StartRound       int                      `json:"baseline_start_round"`
	EndRound         int                      `json:"baseline_end_round"`
	ServiceRanges    map[string]BaselineRange `json:"baseline_service_rounds"`
}

func encodeBaselineDefinition(config BaselineConfig) (string, error) {
	config = config.normalized()
	encoded, err := json.Marshal(baselineDefinition{
		CompetitionStart: config.CompetitionStart, RoundDurationSec: config.RoundDurationSec,
		StartRound: config.StartRound, EndRound: config.EndRound, ServiceRanges: config.ServiceRanges,
	})
	if err != nil {
		return "", fmt.Errorf("encoding baseline definition: %w", err)
	}
	return string(encoded), nil
}

func decodeBaselineDefinition(encoded string) (BaselineConfig, error) {
	var definition baselineDefinition
	if err := json.Unmarshal([]byte(encoded), &definition); err != nil {
		return BaselineConfig{}, err
	}
	return NewBaselineConfig(
		definition.CompetitionStart, definition.RoundDurationSec,
		definition.StartRound, definition.EndRound, definition.ServiceRanges,
	), nil
}

type Store interface {
	UpdateFlowScore([]int64, sniffer.FlowScore) error
	PrepareBaseline(epoch, definition string) error
	LoadBaselineSignatures() ([]sniffer.BaselineSignature, error)
	UpsertBaselineSignature(serviceID, signature string, rounds []int) error
	DeleteBaselineSignature(serviceID, signature string) error
	ReplaceBaselineSignatures([]sniffer.BaselineSignature) error
	ListBaselineSnapshots() ([]sniffer.BaselineSnapshot, error)
	CountBaselinePackets(defaultWindow sniffer.BaselineWindow, serviceWindows map[string]sniffer.BaselineWindow) (int, error)
	ReplayBaselinePackets(defaultWindow sniffer.BaselineWindow, serviceWindows map[string]sniffer.BaselineWindow, limit int, visit func(*sniffer.Packet) error) (int, error)
}

type flowRun struct {
	packets     []*sniffer.Packet
	lastSeen    time.Time // local arrival time; safe for imported captures
	lastPacket  time.Time // capture time; used only to split exchanges
	hasRequest  bool
	hasResponse bool
}

// Engine serializes scoring off the proxy hot path. Submit is non-blocking;
// failure or overload can only omit metadata and can never affect forwarding.
type Engine struct {
	store  Store
	epoch  string
	config BaselineConfig
	in     chan *sniffer.Packet
	reset  chan resetRequest
	stop   chan struct{}
	done   chan struct{}
	once   sync.Once
	admit  sync.RWMutex
	closed bool

	flows        map[string]*flowRun
	stateMu      sync.RWMutex
	baseline     map[string]map[string]map[int]struct{}
	overflow     map[string]map[string]map[int]struct{}
	excluded     map[string]uint64
	scored       map[string]uint64
	queueDropped uint64
	storeErrors  uint64
	lastError    string
	rebuilding   bool
	replayed     int
}

type resetRequest struct {
	config BaselineConfig
	force  bool
	done   chan error
}

type Status struct {
	Epoch           string           `json:"epoch,omitempty"`
	OpeningRounds   int              `json:"opening_rounds"`
	StartRound      int              `json:"baseline_start_round"`
	EndRound        int              `json:"baseline_end_round"`
	RequiredRounds  int              `json:"baseline_required_rounds"`
	Rebuilding      bool             `json:"rebuilding"`
	ReplayedPackets int              `json:"replayed_packets"`
	QueueDropped    uint64           `json:"queue_dropped"`
	StoreErrors     uint64           `json:"store_errors"`
	LastError       string           `json:"last_error,omitempty"`
	Services        []ServiceStatus  `json:"services"`
	Snapshots       []SnapshotStatus `json:"snapshots"`
}

type SnapshotStatus struct {
	Epoch            string                   `json:"epoch"`
	Active           bool                     `json:"active"`
	Compatible       bool                     `json:"compatible"`
	CompetitionStart time.Time                `json:"competition_start"`
	RoundDurationSec int                      `json:"round_duration_seconds"`
	StartRound       int                      `json:"baseline_start_round"`
	EndRound         int                      `json:"baseline_end_round"`
	ServiceRanges    map[string]BaselineRange `json:"baseline_service_rounds"`
	SignatureCount   int                      `json:"signature_count"`
	CreatedAt        time.Time                `json:"created_at"`
	UpdatedAt        time.Time                `json:"updated_at"`
}

type ServiceStatus struct {
	ServiceID            string `json:"service_id"`
	BaselineStartRound   int    `json:"baseline_start_round"`
	BaselineEndRound     int    `json:"baseline_end_round"`
	BaselineRequired     int    `json:"baseline_required_rounds"`
	UsesDefaultBaseline  bool   `json:"uses_default_baseline"`
	RoundsObserved       []int  `json:"rounds_observed"`
	CandidateSignatures  int    `json:"candidate_signatures"`
	TrustedSignatures    int    `json:"trusted_signatures"`
	Complete             bool   `json:"complete"`
	ExcludedOpeningFlows uint64 `json:"excluded_opening_flows"`
	ScoredFlows          uint64 `json:"scored_flows"`
}

func New(store Store, config BaselineConfig) *Engine {
	config = config.normalized()
	e := &Engine{
		store: store, epoch: BaselineEpoch(config), config: config, in: make(chan *sniffer.Packet, maxPendingFlows),
		reset: make(chan resetRequest),
		stop:  make(chan struct{}), done: make(chan struct{}),
		flows: make(map[string]*flowRun), baseline: make(map[string]map[string]map[int]struct{}),
		overflow: make(map[string]map[string]map[int]struct{}),
		excluded: make(map[string]uint64), scored: make(map[string]uint64),
	}
	if err := e.configureBaseline(config, false); err != nil {
		e.recordStoreError(err)
	}
	go e.run()
	return e
}

func (e *Engine) Submit(packet *sniffer.Packet) {
	if packet == nil || packet.ID == 0 {
		return
	}
	e.admit.RLock()
	defer e.admit.RUnlock()
	if e.closed {
		return
	}
	copyPacket := *packet
	copyPacket.Body = append([]byte(nil), packet.Body...)
	copyPacket.MatchedRules = append([]sniffer.MatchedRuleInfo(nil), packet.MatchedRules...)
	copyPacket.MatchedFlagIDs = append([]string(nil), packet.MatchedFlagIDs...)
	select {
	case e.in <- &copyPacket:
	default:
		e.stateMu.Lock()
		e.queueDropped++
		e.stateMu.Unlock()
	}
}

func (e *Engine) Close() {
	e.once.Do(func() {
		// Serialize admission with shutdown: every Submit that acquired the read
		// lock is queued (or rejected as full) before the scorer drains and exits.
		e.admit.Lock()
		e.closed = true
		close(e.stop)
		e.admit.Unlock()
		<-e.done
	})
}

// ConfigureBaseline switches timing/range on the engine goroutine after
// finishing pending flows. A preserved snapshot is restored when available;
// otherwise retained packets seed a new version without deleting old ones.
func (e *Engine) ConfigureBaseline(config BaselineConfig) error {
	return e.requestBaseline(resetRequest{config: config.normalized(), done: make(chan error, 1)})
}

// RebuildBaseline relearns the current range in isolation and publishes it
// only after retained traffic passes coverage checks.
func (e *Engine) RebuildBaseline() error {
	e.stateMu.RLock()
	config := e.config
	e.stateMu.RUnlock()
	return e.requestBaseline(resetRequest{config: config, force: true, done: make(chan error, 1)})
}

func (e *Engine) requestBaseline(req resetRequest) error {
	select {
	case e.reset <- req:
		select {
		case err := <-req.done:
			return err
		case <-e.done:
			return fmt.Errorf("scoring engine is closed")
		}
	case <-e.stop:
		return fmt.Errorf("scoring engine is closed")
	case <-e.done:
		return fmt.Errorf("scoring engine is closed")
	}
}

// Status returns a stable, read-only snapshot for the operator UI.
func (e *Engine) Status() Status {
	var storedSnapshots []sniffer.BaselineSnapshot
	var snapshotErr error
	if e.store != nil {
		storedSnapshots, snapshotErr = e.store.ListBaselineSnapshots()
	}
	e.stateMu.RLock()
	defer e.stateMu.RUnlock()
	config := e.config.normalized()
	ids := make(map[string]struct{}, len(e.baseline)+len(e.scored)+len(e.excluded))
	for id := range e.baseline {
		ids[id] = struct{}{}
	}
	for id := range e.scored {
		ids[id] = struct{}{}
	}
	for id := range e.excluded {
		ids[id] = struct{}{}
	}
	for id := range config.ServiceRanges {
		ids[id] = struct{}{}
	}
	services := make([]ServiceStatus, 0, len(ids))
	for serviceID := range ids {
		rounds := config.RangeFor(serviceID)
		required := rounds.EndRound - rounds.StartRound + 1
		seen := make(map[int]struct{}, required)
		trusted := 0
		for _, observedRounds := range e.baseline[serviceID] {
			complete := true
			for round := rounds.StartRound; round <= rounds.EndRound; round++ {
				if _, ok := observedRounds[round]; !ok {
					complete = false
				}
			}
			if complete {
				trusted++
			}
			for round := range observedRounds {
				seen[round] = struct{}{}
			}
		}
		services = append(services, ServiceStatus{
			ServiceID: serviceID, BaselineStartRound: rounds.StartRound, BaselineEndRound: rounds.EndRound,
			BaselineRequired: required, UsesDefaultBaseline: serviceUsesDefault(config, serviceID),
			RoundsObserved:      sortedRounds(seen),
			CandidateSignatures: len(e.baseline[serviceID]), TrustedSignatures: trusted, Complete: trusted > 0,
			ExcludedOpeningFlows: e.excluded[serviceID], ScoredFlows: e.scored[serviceID],
		})
	}
	sort.Slice(services, func(i, j int) bool { return services[i].ServiceID < services[j].ServiceID })
	snapshots := make([]SnapshotStatus, 0, len(storedSnapshots))
	activeSignatures := 0
	for _, signatures := range e.baseline {
		activeSignatures += len(signatures)
	}
	for _, stored := range storedSnapshots {
		definition, err := decodeBaselineDefinition(stored.Definition)
		if err != nil {
			continue
		}
		count := stored.SignatureCount
		if stored.Active && stored.Epoch == e.epoch {
			count = activeSignatures
		}
		snapshots = append(snapshots, SnapshotStatus{
			Epoch: stored.Epoch, Active: stored.Active, Compatible: sameCompetition(definition, config),
			CompetitionStart: definition.CompetitionStart, RoundDurationSec: definition.RoundDurationSec,
			StartRound: definition.StartRound, EndRound: definition.EndRound, ServiceRanges: definition.ServiceRanges,
			SignatureCount: count, CreatedAt: stored.CreatedAt, UpdatedAt: stored.UpdatedAt,
		})
	}
	lastError := e.lastError
	if snapshotErr != nil {
		lastError = snapshotErr.Error()
	}
	return Status{
		Epoch: e.epoch, OpeningRounds: config.RequiredRounds(),
		StartRound: config.StartRound, EndRound: config.EndRound,
		RequiredRounds: config.RequiredRounds(), Rebuilding: e.rebuilding, ReplayedPackets: e.replayed,
		QueueDropped: e.queueDropped, StoreErrors: e.storeErrors, LastError: lastError,
		Services: services, Snapshots: snapshots,
	}
}

func sameCompetition(left, right BaselineConfig) bool {
	return left.CompetitionStart.Equal(right.CompetitionStart) && left.RoundDurationSec == right.RoundDurationSec
}

func (e *Engine) run() {
	defer close(e.done)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case packet := <-e.in:
			e.accept(packet)
		case req := <-e.reset:
			e.flushAll()
			req.done <- e.configureBaseline(req.config, req.force)
		case now := <-ticker.C:
			e.flushIdle(now)
		case <-e.stop:
			for {
				select {
				case packet := <-e.in:
					e.accept(packet)
				default:
					e.flushAll()
					return
				}
			}
		}
	}
}

func (e *Engine) configureBaseline(config BaselineConfig, force bool) error {
	config = config.normalized()
	definition, err := encodeBaselineDefinition(config)
	if err != nil {
		return err
	}
	e.stateMu.Lock()
	e.rebuilding = true
	previous := e.captureBaselineStateLocked()
	e.stateMu.Unlock()
	defer func() {
		e.stateMu.Lock()
		e.rebuilding = false
		e.stateMu.Unlock()
	}()

	defaultWindow, serviceWindows, hasWindow := config.windows()
	if force {
		return e.rebuildBaselineAtomically(config, defaultWindow, serviceWindows, hasWindow, previous)
	}

	epoch := BaselineEpoch(config)
	snapshots, err := e.store.ListBaselineSnapshots()
	if err != nil {
		return err
	}
	restored := false
	for _, snapshot := range snapshots {
		if snapshot.Epoch == epoch && snapshot.SignatureCount > 0 {
			restored = true
			break
		}
	}
	if !restored && hasWindow {
		count, err := e.store.CountBaselinePackets(defaultWindow, serviceWindows)
		if err != nil {
			return err
		}
		if count > maxBaselineReplayPackets {
			return fmt.Errorf("baseline window contains %d packets and exceeds the %d-packet safety limit; choose a narrower round range", count, maxBaselineReplayPackets)
		}
	}
	if err := e.store.PrepareBaseline(epoch, definition); err != nil {
		return err
	}
	stored, err := e.store.LoadBaselineSignatures()
	if err != nil {
		e.restorePreviousBaseline(previous)
		return err
	}
	e.installBaseline(config, epoch, baselineFromSignatures(config, stored))
	if restored || !hasWindow {
		return nil
	}

	replayed, err := e.replayBaselineWindow(config, defaultWindow, serviceWindows)
	if err == nil {
		err = e.store.ReplaceBaselineSignatures(e.baselineSnapshot())
	}
	if err != nil {
		e.restorePreviousBaseline(previous)
		return err
	}
	e.stateMu.Lock()
	e.replayed = replayed
	e.stateMu.Unlock()
	return nil
}

type baselineState struct {
	epoch    string
	config   BaselineConfig
	baseline map[string]map[string]map[int]struct{}
	overflow map[string]map[string]map[int]struct{}
	excluded map[string]uint64
	scored   map[string]uint64
	replayed int
}

func (e *Engine) captureBaselineStateLocked() baselineState {
	return baselineState{
		epoch: e.epoch, config: e.config, baseline: cloneBaselineMap(e.baseline), overflow: cloneBaselineMap(e.overflow),
		excluded: cloneCounters(e.excluded), scored: cloneCounters(e.scored), replayed: e.replayed,
	}
}

func (e *Engine) restorePreviousBaseline(previous baselineState) {
	if previous.epoch != "" {
		if definition, err := encodeBaselineDefinition(previous.config); err == nil {
			if err := e.store.PrepareBaseline(previous.epoch, definition); err != nil {
				e.recordStoreError(fmt.Errorf("restoring previous baseline snapshot: %w", err))
			}
		}
	}
	e.stateMu.Lock()
	e.epoch, e.config = previous.epoch, previous.config
	e.baseline, e.overflow = previous.baseline, previous.overflow
	e.excluded, e.scored, e.replayed = previous.excluded, previous.scored, previous.replayed
	e.stateMu.Unlock()
}

func (e *Engine) installBaseline(config BaselineConfig, epoch string, baseline map[string]map[string]map[int]struct{}) {
	e.stateMu.Lock()
	e.epoch, e.config, e.baseline = epoch, config, baseline
	e.overflow = make(map[string]map[string]map[int]struct{})
	e.excluded = make(map[string]uint64)
	e.scored = make(map[string]uint64)
	e.replayed = 0
	e.stateMu.Unlock()
}

func (e *Engine) rebuildBaselineAtomically(config BaselineConfig, defaultWindow sniffer.BaselineWindow, serviceWindows map[string]sniffer.BaselineWindow, hasWindow bool, previous baselineState) error {
	if !hasWindow {
		return fmt.Errorf("cannot rebuild baseline without a competition start; persisted snapshot was kept")
	}
	count, err := e.store.CountBaselinePackets(defaultWindow, serviceWindows)
	if err != nil {
		return err
	}
	if count == 0 {
		return fmt.Errorf("cannot rebuild baseline: no retained packets cover the selected rounds; persisted snapshot was kept")
	}
	if count > maxBaselineReplayPackets {
		return fmt.Errorf("cannot rebuild baseline: %d retained packets exceed the %d-packet safety limit; persisted snapshot was kept", count, maxBaselineReplayPackets)
	}
	e.installBaseline(config, BaselineEpoch(config), make(map[string]map[string]map[int]struct{}))
	replayed, err := e.replayBaselineWindow(config, defaultWindow, serviceWindows)
	if err == nil {
		err = validateRebuildCoverage(config, e.baselineSnapshot(), previous.baseline)
	}
	if err == nil {
		err = e.store.ReplaceBaselineSignatures(e.baselineSnapshot())
	}
	if err != nil {
		e.restorePreviousBaseline(previous)
		return err
	}
	e.stateMu.Lock()
	e.replayed = replayed
	e.stateMu.Unlock()
	return nil
}

func validateRebuildCoverage(config BaselineConfig, items []sniffer.BaselineSignature, previous map[string]map[string]map[int]struct{}) error {
	seen := make(map[string]map[int]struct{})
	for _, item := range items {
		if seen[item.ServiceID] == nil {
			seen[item.ServiceID] = make(map[int]struct{})
		}
		for _, round := range item.Rounds {
			seen[item.ServiceID][round] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return fmt.Errorf("cannot rebuild baseline: retained traffic contains no safe fingerprints; persisted snapshot was kept")
	}
	expected := make(map[string]struct{}, len(previous)+len(config.ServiceRanges))
	for serviceID := range previous {
		expected[serviceID] = struct{}{}
	}
	for serviceID := range config.ServiceRanges {
		expected[serviceID] = struct{}{}
	}
	if len(expected) == 0 {
		for serviceID := range seen {
			expected[serviceID] = struct{}{}
		}
	}
	var incomplete []string
	for serviceID := range expected {
		rounds := config.RangeFor(serviceID)
		var missing []string
		for round := rounds.StartRound; round <= rounds.EndRound; round++ {
			if _, ok := seen[serviceID][round]; !ok {
				missing = append(missing, fmt.Sprint(round))
			}
		}
		if len(missing) > 0 {
			incomplete = append(incomplete, fmt.Sprintf("%s (missing %s)", serviceID, strings.Join(missing, ",")))
		}
	}
	if len(incomplete) > 0 {
		sort.Strings(incomplete)
		return fmt.Errorf("cannot rebuild baseline: retained safe traffic is incomplete for %s; persisted snapshot was kept", strings.Join(incomplete, "; "))
	}
	return nil
}

func baselineFromSignatures(config BaselineConfig, stored []sniffer.BaselineSignature) map[string]map[string]map[int]struct{} {
	baseline := make(map[string]map[string]map[int]struct{})
	for _, item := range stored {
		if baseline[item.ServiceID] == nil {
			baseline[item.ServiceID] = make(map[string]map[int]struct{})
		}
		rounds := make(map[int]struct{}, len(item.Rounds))
		for _, round := range item.Rounds {
			if config.contains(item.ServiceID, round) {
				rounds[round] = struct{}{}
			}
		}
		baseline[item.ServiceID][item.Signature] = rounds
	}
	return baseline
}

func cloneBaselineMap(source map[string]map[string]map[int]struct{}) map[string]map[string]map[int]struct{} {
	copy := make(map[string]map[string]map[int]struct{}, len(source))
	for serviceID, signatures := range source {
		copy[serviceID] = make(map[string]map[int]struct{}, len(signatures))
		for signature, rounds := range signatures {
			copy[serviceID][signature] = make(map[int]struct{}, len(rounds))
			for round := range rounds {
				copy[serviceID][signature][round] = struct{}{}
			}
		}
	}
	return copy
}

func cloneCounters(source map[string]uint64) map[string]uint64 {
	copy := make(map[string]uint64, len(source))
	for key, value := range source {
		copy[key] = value
	}
	return copy
}

func (e *Engine) accept(packet *sniffer.Packet) {
	e.acceptInto(e.flows, packet, e.finish)
}

func (e *Engine) acceptInto(flows map[string]*flowRun, packet *sniffer.Packet, finish func(*flowRun)) {
	key := flowKey(packet)
	run := flows[key]
	if run != nil {
		gap := packet.Timestamp.Sub(run.lastPacket)
		newExchange := packet.Direction == sniffer.DirectionRequest && run.hasRequest && run.hasResponse
		if gap > flowIdleTimeout || newExchange {
			finish(run)
			delete(flows, key)
			run = nil
		}
	}
	if run == nil {
		if len(flows) >= maxPendingFlows {
			flushOldestRun(flows, finish)
		}
		run = &flowRun{}
		flows[key] = run
	}
	run.packets = append(run.packets, packet)
	run.lastSeen = time.Now()
	run.lastPacket = packet.Timestamp
	run.hasRequest = run.hasRequest || packet.Direction == sniffer.DirectionRequest
	run.hasResponse = run.hasResponse || packet.Direction == sniffer.DirectionResponse
}

func (e *Engine) flushIdle(now time.Time) {
	for key, run := range e.flows {
		if now.Sub(run.lastSeen) >= flowIdleTimeout {
			e.finish(run)
			delete(e.flows, key)
		}
	}
}

func (e *Engine) flushOldest() {
	flushOldestRun(e.flows, e.finish)
}

func flushOldestRun(flows map[string]*flowRun, finish func(*flowRun)) {
	var oldestKey string
	var oldest time.Time
	for key, run := range flows {
		if oldestKey == "" || run.lastSeen.Before(oldest) {
			oldestKey, oldest = key, run.lastSeen
		}
	}
	if oldestKey != "" {
		finish(flows[oldestKey])
		delete(flows, oldestKey)
	}
}

func (e *Engine) flushAll() {
	for key, run := range e.flows {
		e.finish(run)
		delete(e.flows, key)
	}
}

func (e *Engine) finish(run *flowRun) {
	if run == nil || len(run.packets) == 0 {
		return
	}
	signature := flowSignature(run.packets)
	serviceID := run.packets[0].ServiceID
	if err := e.learnBaseline(run.packets, signature, true); err != nil {
		e.recordStoreError(err)
	}
	score := e.score(run.packets, signature)
	ids := make([]int64, 0, len(run.packets))
	for _, packet := range run.packets {
		ids = append(ids, packet.ID)
	}
	if err := e.store.UpdateFlowScore(ids, score); err != nil {
		e.recordStoreError(err)
		return
	}
	e.stateMu.Lock()
	e.scored[serviceID]++
	e.stateMu.Unlock()
}

func (e *Engine) learnBaseline(packets []*sniffer.Packet, signature string, persist bool) error {
	if len(packets) == 0 {
		return nil
	}
	round, sameRound := flowRound(packets)
	e.stateMu.RLock()
	config := e.config
	e.stateMu.RUnlock()
	serviceID := packets[0].ServiceID
	if !config.contains(serviceID, round) {
		return nil
	}
	if !sameRound || !baselineSafe(packets) {
		e.stateMu.Lock()
		e.excluded[serviceID]++
		e.stateMu.Unlock()
		return nil
	}
	rounds, evicted, ok := e.addBaselineRound(serviceID, signature, round)
	if !ok {
		return nil
	}
	if !persist {
		return nil
	}
	if evicted != "" {
		if err := e.store.DeleteBaselineSignature(serviceID, evicted); err != nil {
			return err
		}
	}
	return e.store.UpsertBaselineSignature(serviceID, signature, rounds)
}

// replayBaselineWindow rebuilds only learning state and consumes storage in
// bounded batches. Historical scores stay untouched; new flows immediately
// use the reconstructed baseline.
func (e *Engine) replayBaselineWindow(config BaselineConfig, defaultWindow sniffer.BaselineWindow, serviceWindows map[string]sniffer.BaselineWindow) (int, error) {
	runs := make(map[string]*flowRun)
	var replayErr error
	finish := func(run *flowRun) {
		if replayErr != nil || run == nil || len(run.packets) == 0 {
			return
		}
		replayErr = e.learnBaseline(run.packets, flowSignature(run.packets), false)
	}
	replayed, err := e.store.ReplayBaselinePackets(defaultWindow, serviceWindows, maxBaselineReplayPackets, func(packet *sniffer.Packet) error {
		if packet == nil {
			return nil
		}
		packet.Round = config.roundForTime(packet.Timestamp)
		e.acceptInto(runs, packet, finish)
		return replayErr
	})
	if err != nil {
		return replayed, err
	}
	keys := make([]string, 0, len(runs))
	for key := range runs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		finish(runs[key])
		if replayErr != nil {
			return replayed, replayErr
		}
	}
	return replayed, nil
}

func (e *Engine) baselineSnapshot() []sniffer.BaselineSignature {
	e.stateMu.RLock()
	defer e.stateMu.RUnlock()
	items := make([]sniffer.BaselineSignature, 0)
	for serviceID, signatures := range e.baseline {
		for signature, rounds := range signatures {
			items = append(items, sniffer.BaselineSignature{
				ServiceID: serviceID, Signature: signature, Rounds: sortedRounds(rounds),
			})
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].ServiceID != items[j].ServiceID {
			return items[i].ServiceID < items[j].ServiceID
		}
		return items[i].Signature < items[j].Signature
	})
	return items
}

func (e *Engine) recordStoreError(err error) {
	if err == nil {
		return
	}
	e.stateMu.Lock()
	e.storeErrors++
	e.lastError = err.Error()
	e.stateMu.Unlock()
}

func (e *Engine) score(packets []*sniffer.Packet, signature string) sniffer.FlowScore {
	serviceID := packets[0].ServiceID
	round, _ := flowRound(packets)
	e.stateMu.RLock()
	config := e.config
	e.stateMu.RUnlock()
	baselineRounds := config.RangeFor(serviceID)
	attack, normal := 0, 0
	reasons := make([]sniffer.ScoreReason, 0, 8)
	addAttack := func(code, label string, points int) {
		attack += points
		reasons = append(reasons, sniffer.ScoreReason{Code: code, Label: label, Weight: points})
	}
	addNormal := func(code, label string, points int) {
		normal += points
		reasons = append(reasons, sniffer.ScoreReason{Code: code, Label: label, Weight: -points})
	}

	actualDrop, wouldDrop, alertRule := false, false, false
	requestHasFlag, responseHasFlag, response5xx := false, false, false
	tagSet := map[rounddiff.SuspicionTag]struct{}{}
	decoded, truncated := false, false
	for _, packet := range packets {
		actualDrop = actualDrop || packet.Verdict.Outcome == flowmodel.OutcomeDropped
		wouldDrop = wouldDrop || packet.Verdict.Outcome == flowmodel.OutcomeWouldDrop
		truncated = truncated || packet.CaptureTruncated
		decoded = decoded || len(packet.Decoded) > 0
		response5xx = response5xx || (packet.Direction == sniffer.DirectionResponse && packet.Status >= 500)
		if packet.ContainsFlagID || packet.Flagged {
			if packet.Direction == sniffer.DirectionRequest {
				requestHasFlag = true
			} else {
				responseHasFlag = true
			}
		}
		for _, rule := range packet.MatchedRules {
			switch rule.Action {
			case "drop", "both":
				if packet.Verdict.Outcome == flowmodel.OutcomeDropped {
					actualDrop = true
				} else {
					wouldDrop = true
				}
			case "alert":
				alertRule = true
			}
		}
		text := packetSuspicionText(packet)
		for _, tag := range rounddiff.SuspicionTags(text) {
			tagSet[tag] = struct{}{}
		}
	}

	switch {
	case actualDrop:
		addAttack("rule_drop", "Blocked by an explicit rule", 35)
	case wouldDrop:
		addAttack("rule_would_drop", "Block rule matched in observation only", 18)
	case alertRule:
		addAttack("rule_alert", "Flagged by an explicit rule", 8)
	}
	if n := len(tagSet); n > 0 {
		points := 12
		if n == 2 {
			points = 20
		} else if n >= 3 {
			points = 25
		}
		labels := make([]string, 0, n)
		for tag := range tagSet {
			labels = append(labels, string(tag))
		}
		sort.Strings(labels)
		addAttack("payload_patterns", "Suspicious patterns: "+strings.Join(labels, ", "), points)
	}
	if requestHasFlag {
		addAttack("flag_in_request", "Known flag present in the request", 25)
	} else if responseHasFlag && len(tagSet) > 0 {
		addAttack("suspicious_flag_response", "Flag response after a suspicious request", 25)
	} else if responseHasFlag {
		addAttack("flag_in_response", "Response contains a flag", 8)
	}
	if response5xx && len(tagSet) > 0 {
		addAttack("suspicious_5xx", "5xx response after a suspicious payload", 8)
	}

	baselineComplete := e.baselineComplete(serviceID)
	trusted := e.signatureTrusted(serviceID, signature)
	currentSafe := baselineSafe(packets)
	if round > baselineRounds.EndRound && baselineComplete {
		switch {
		case trusted && currentSafe:
			addNormal("opening_baseline", fmt.Sprintf("Flow repeated in every baseline round (%d-%d)", baselineRounds.StartRound, baselineRounds.EndRound), 70)
		case trusted:
			addAttack("unsafe_baseline_match", "Known shape carries current attack indicators", 15)
		default:
			addAttack("baseline_novelty", "Sequence absent from the trusted baseline", 15)
		}
	}

	attack, normal = clamp(attack), clamp(normal)
	coverage := 25
	if round > baselineRounds.EndRound {
		if baselineComplete {
			coverage = 70
		} else {
			coverage = 40
		}
	}
	if decoded {
		coverage += 15
	}
	if !truncated {
		coverage += 15
	} else {
		coverage -= 25
	}
	coverage = clamp(coverage)
	confidence := abs(attack-normal) * coverage / 100

	classification := "review"
	margin := attack - normal
	switch {
	case attack >= 60 && margin >= 25:
		classification = "likely_exploit"
	case currentSafe && coverage >= 60 && normal >= 65 && attack < 35 && margin <= -25:
		classification = "likely_checker"
	case coverage < 50 || round <= baselineRounds.EndRound:
		classification = "insufficient_data"
	}
	return sniffer.FlowScore{
		Attack: attack, Normal: normal, Coverage: coverage, Confidence: confidence,
		Classification: classification, Reasons: reasons,
	}
}

func (e *Engine) addBaselineRound(serviceID, signature string, round int) ([]int, string, bool) {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()
	config := e.config
	baselineRounds := config.RangeFor(serviceID)
	bySignature := e.baseline[serviceID]
	if bySignature == nil {
		bySignature = make(map[string]map[int]struct{})
		e.baseline[serviceID] = bySignature
	}
	rounds := bySignature[signature]
	evicted := ""
	if rounds == nil {
		if len(bySignature) >= maxBaselineSignaturesPerService {
			// Do not churn SQLite for a one-round flood. Keep a second bounded
			// exact set and admit an overflow signature only after it recurs in
			// another selected round; recurring primary candidates stay protected.
			if e.overflow == nil {
				e.overflow = make(map[string]map[string]map[int]struct{})
			}
			byOverflow := e.overflow[serviceID]
			if byOverflow == nil {
				byOverflow = make(map[string]map[int]struct{})
				e.overflow[serviceID] = byOverflow
			}
			seen := byOverflow[signature]
			if seen == nil {
				if len(byOverflow) >= maxBaselineOverflowPerService {
					victim := ""
					victimRounds := 0
					for candidate, candidateSeen := range byOverflow {
						strength := len(candidateSeen)
						if victim == "" || strength < victimRounds || (strength == victimRounds && candidate > victim) {
							victim, victimRounds = candidate, strength
						}
					}
					// A fresh one-round signature must never displace an overflow
					// candidate that already recurred in another selected round.
					if victim == "" || victimRounds > 1 {
						return nil, "", false
					}
					delete(byOverflow, victim)
				}
				seen = make(map[int]struct{})
				byOverflow[signature] = seen
			}
			seen[round] = struct{}{}
			if len(seen) < 2 {
				return nil, "", false
			}

			victim := ""
			victimRounds := 0
			for candidate, seen := range bySignature {
				strength := len(seen)
				if victim == "" || strength < victimRounds || (strength == victimRounds && candidate > victim) {
					victim, victimRounds = candidate, strength
				}
			}
			if victim == "" || victimRounds > 1 {
				return nil, "", false
			}
			victimSeen := bySignature[victim]
			delete(bySignature, victim)
			delete(byOverflow, signature)
			byOverflow[victim] = victimSeen
			evicted = victim
			rounds = seen
		}
		if rounds == nil {
			rounds = make(map[int]struct{})
		}
		bySignature[signature] = rounds
	}
	if round >= baselineRounds.StartRound && round <= baselineRounds.EndRound {
		rounds[round] = struct{}{}
	}
	return sortedRounds(rounds), evicted, true
}

func (e *Engine) signatureTrusted(serviceID, signature string) bool {
	e.stateMu.RLock()
	defer e.stateMu.RUnlock()
	rounds := e.baseline[serviceID][signature]
	baselineRounds := e.config.RangeFor(serviceID)
	for round := baselineRounds.StartRound; round <= baselineRounds.EndRound; round++ {
		if _, ok := rounds[round]; !ok {
			return false
		}
	}
	return true
}

func (e *Engine) baselineComplete(serviceID string) bool {
	e.stateMu.RLock()
	defer e.stateMu.RUnlock()
	baselineRounds := e.config.RangeFor(serviceID)
	for _, rounds := range e.baseline[serviceID] {
		complete := true
		for round := baselineRounds.StartRound; round <= baselineRounds.EndRound; round++ {
			if _, ok := rounds[round]; !ok {
				complete = false
				break
			}
		}
		if complete {
			return true
		}
	}
	return false
}

func serviceUsesDefault(config BaselineConfig, serviceID string) bool {
	_, overridden := config.ServiceRanges[serviceID]
	return !overridden
}

func sortedRounds(set map[int]struct{}) []int {
	out := make([]int, 0, len(set))
	for round := range set {
		out = append(out, round)
	}
	sort.Ints(out)
	return out
}

func baselineSafe(packets []*sniffer.Packet) bool {
	for _, packet := range packets {
		// A truncated payload cannot be proven free of indicators outside the
		// retained prefix. An explicit analyst exploit label is also honored on
		// historical rebuilds, giving operators a deterministic recovery path.
		if packet.CaptureTruncated || strings.EqualFold(packet.AnalystLabel, "exploit") {
			return false
		}
		if packet.Verdict.Outcome == flowmodel.OutcomeDropped || packet.Verdict.Outcome == flowmodel.OutcomeWouldDrop {
			return false
		}
		if len(packet.MatchedRules) > 0 {
			return false
		}
		if packet.Direction == sniffer.DirectionRequest && (packet.ContainsFlagID || packet.Flagged) {
			return false
		}
		if len(rounddiff.SuspicionTags(packetSuspicionText(packet))) > 0 {
			return false
		}
	}
	return true
}

func packetSuspicionText(packet *sniffer.Packet) string {
	var out strings.Builder
	out.WriteString(packet.URL)
	headerNames := make([]string, 0, len(packet.Headers))
	for name := range packet.Headers {
		headerNames = append(headerNames, name)
	}
	sort.Strings(headerNames)
	for _, name := range headerNames {
		out.WriteByte('\n')
		out.WriteString(name)
		out.WriteString(": ")
		out.WriteString(packet.Headers[name])
	}
	out.WriteByte('\n')
	if packet.BodyString != "" {
		out.WriteString(packet.BodyString)
	} else {
		out.Write(packet.Body)
	}
	return out.String()
}

var (
	uuidRE = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	hexRE  = regexp.MustCompile(`(?i)\b[0-9a-f]{16,}\b`)
	numRE  = regexp.MustCompile(`\b\d+\b`)
)

func flowSignature(packets []*sniffer.Packet) string {
	parts := make([]string, 0, len(packets))
	for _, packet := range packets {
		route := packet.URL
		if i := strings.IndexByte(route, '?'); i >= 0 {
			route = route[:i]
		}
		route = normalizeDynamic(route)
		statusClass := 0
		if packet.Status > 0 {
			statusClass = packet.Status / 100
		}
		hint := applicationHint(packet.Decoded)
		length := ""
		if hint == "" && packet.Method == "" && route == "" {
			hint = rawHint(packet.BodyString)
			length = lengthBucket(len(packet.Body))
		}
		parts = append(parts, fmt.Sprintf("%s|%s|%s|%s|%dxx|%s|%s|%s",
			packet.Protocol, packet.Direction, strings.ToUpper(packet.Method), route, statusClass,
			decodedShape(packet.Decoded), hint, length))
	}
	digest := sha256.Sum256([]byte(strings.Join(parts, ">")))
	return hex.EncodeToString(digest[:16])
}

func flowKey(packet *sniffer.Packet) string {
	if packet.SessionID != "" {
		return packet.ServiceID + "\x00" + packet.SessionID
	}
	return fmt.Sprintf("%s\x00%s:%d>%s:%d", packet.ServiceID, packet.SrcIP, packet.SrcPort, packet.DstIP, packet.DstPort)
}

func normalizeDynamic(value string) string {
	value = strings.ToLower(value)
	value = uuidRE.ReplaceAllString(value, ":uuid")
	value = hexRE.ReplaceAllString(value, ":hex")
	return numRE.ReplaceAllString(value, ":id")
}

func decodedShape(decoded map[string]any) string {
	keys := make([]string, 0, 12)
	var walk func(string, any)
	walk = func(prefix string, value any) {
		object, ok := value.(map[string]any)
		if !ok {
			if prefix != "" {
				keys = append(keys, prefix)
			}
			return
		}
		names := make([]string, 0, len(object))
		for name := range object {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if len(keys) >= 24 {
				return
			}
			path := name
			if prefix != "" {
				path = prefix + "." + name
			}
			walk(path, object[name])
		}
	}
	walk("", decoded)
	return strings.Join(keys, ",")
}

func applicationHint(decoded map[string]any) string {
	for _, item := range [][2]string{{"resp", "command"}, {"mqtt", "packet"}, {"dns", "qtype"}} {
		namespace, field := item[0], item[1]
		object, ok := decoded[namespace].(map[string]any)
		if !ok {
			continue
		}
		if value, ok := object[field]; ok {
			return namespace + ":" + normalizeDynamic(fmt.Sprint(value))
		}
	}
	return ""
}

func flowRound(packets []*sniffer.Packet) (int, bool) {
	round, same := 0, true
	for _, packet := range packets {
		if packet.Round > round {
			round = packet.Round
		}
	}
	for _, packet := range packets {
		if packet.Round != round {
			same = false
			break
		}
	}
	return round, same
}

func rawHint(body string) string {
	tokens := rounddiff.Tokenize(body)
	if len(tokens) > 1 {
		tokens = tokens[:1]
	}
	return strings.Join(tokens, " ")
}

func lengthBucket(length int) string {
	switch {
	case length == 0:
		return "0"
	case length <= 32:
		return "1-32"
	case length <= 128:
		return "33-128"
	case length <= 512:
		return "129-512"
	case length <= 2048:
		return "513-2048"
	default:
		return "2049+"
	}
}

func clamp(value int) int {
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}

func abs(value int) int {
	if value < 0 {
		return -value
	}
	return value
}
