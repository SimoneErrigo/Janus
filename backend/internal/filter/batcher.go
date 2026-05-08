package filter

import (
	"strings"

	ahocorasick "github.com/petar-dambovaliev/aho-corasick"
)

// MatchSet is the result of a single batched scan: matchSet[patternID] is true
// when that literal needle was found in its target field.
type MatchSet []bool

// MatchSetAware is the optional interface a PacketView can implement so the
// batched evaluator can answer `contains` predicates with a precomputed bit
// instead of running its own scan. Wrap a normal view with batchedView (below)
// before invoking compiled closures.
type MatchSetAware interface {
	Matched(patternID int) bool
}

// PredicateHook intercepts predicate compilation. When it returns ok=true the
// compiler uses the supplied closure instead of building the default matcher.
// The Batcher is the only PredicateHook today.
type PredicateHook interface {
	Predicate(p *Predicate) (EvalFunc, bool)
}

// Batcher collects literal contains/icontains predicates across many
// expressions of one service and compiles them into a single Aho-Corasick
// automaton per (field, case-insensitivity) group. The hot path then scans
// each target field once per packet.
type Batcher struct {
	groups   map[batchKey]*batchGroup
	patterns int // total registered patterns
}

type batchKey struct {
	field string // body, url, header, raw, method, src, dst, peer, service, direction, proto
	ci    bool   // case-insensitive (icontains)
}

type batchGroup struct {
	needles []string // already lower-cased when ci is true
	pids    []int    // global pattern ID per needle
}

// NewBatcher creates an empty Batcher. Register predicates by invoking the
// CompileEvalWith path that supplies the Batcher as a PredicateHook, then
// call Build to finalize the automatons.
func NewBatcher() *Batcher {
	return &Batcher{groups: map[batchKey]*batchGroup{}}
}

// Predicate implements PredicateHook. It only handles literal contains /
// icontains on string-shaped fields without a header sub-name. Anything else
// returns ok=false so the compiler falls back to the standard closure.
func (b *Batcher) Predicate(p *Predicate) (EvalFunc, bool) {
	if p.Op != OpContains && p.Op != OpIContains {
		return nil, false
	}
	field, ok := LookupField(p.Field)
	if !ok {
		return nil, false
	}
	if !isBatchableField(field, p) {
		return nil, false
	}
	needle, err := stringValue(p.Value)
	if err != nil || needle == "" {
		return nil, false
	}
	ci := p.Op == OpIContains
	pid := b.register(p.Field, ci, needle)
	pred := *p // capture for fallback
	return func(v PacketView) bool {
		if msa, ok := v.(MatchSetAware); ok {
			return msa.Matched(pid)
		}
		// Fallback when the view isn't batched (e.g. residual eval on a raw
		// *Packet). Walk the same code path as the standard compiler.
		text := readString(v, pred.Field, pred.HeaderName)
		if ci {
			return strings.Contains(strings.ToLower(text), strings.ToLower(needle))
		}
		return strings.Contains(text, needle)
	}, true
}

func (b *Batcher) register(field string, ci bool, needle string) int {
	if ci {
		needle = strings.ToLower(needle)
	}
	k := batchKey{field: field, ci: ci}
	g := b.groups[k]
	if g == nil {
		g = &batchGroup{}
		b.groups[k] = g
	}
	pid := b.patterns
	b.patterns++
	g.needles = append(g.needles, needle)
	g.pids = append(g.pids, pid)
	return pid
}

// Build finalizes registered patterns into a BatchScanner. Safe to call with
// no registered patterns — the scanner returns an empty MatchSet.
func (b *Batcher) Build() *BatchScanner {
	s := &BatchScanner{total: b.patterns, groups: make([]builtGroup, 0, len(b.groups))}
	for k, g := range b.groups {
		if len(g.needles) == 0 {
			continue
		}
		builder := ahocorasick.NewAhoCorasickBuilder(ahocorasick.Opts{
			AsciiCaseInsensitive: false, // we lowercase ourselves for ci
			MatchOnlyWholeWords:  false,
			MatchKind:            ahocorasick.StandardMatch,
			DFA:                  true,
		})
		ac := builder.Build(g.needles)
		s.groups = append(s.groups, builtGroup{
			ac:    ac,
			key:   k,
			pids:  g.pids,
			count: len(g.needles),
		})
	}
	return s
}

// BatchScanner runs the per-field Aho-Corasick automatons over a PacketView
// and produces a MatchSet keyed by the global pattern IDs returned during
// registration.
type BatchScanner struct {
	groups []builtGroup
	total  int
}

type builtGroup struct {
	ac    ahocorasick.AhoCorasick
	key   batchKey
	pids  []int
	count int
}

// PatternCount returns the total number of registered literal patterns.
func (s *BatchScanner) PatternCount() int { return s.total }

// Scan walks each field's automaton once and returns the resulting bitset.
// A nil PacketView returns an all-false set.
func (s *BatchScanner) Scan(v PacketView) MatchSet {
	set := make(MatchSet, s.total)
	if v == nil {
		return set
	}
	for _, g := range s.groups {
		text := readString(v, g.key.field, "")
		if text == "" {
			continue
		}
		if g.key.ci {
			text = strings.ToLower(text)
		}
		// Iterate matches; mark the first hit per pattern ID. Stopping early
		// would be possible per pattern but FindAll is already O(text).
		for _, hit := range g.ac.FindAll(text) {
			pid := g.pids[hit.Pattern()]
			set[pid] = true
		}
	}
	return set
}

// Wrap returns a MatchSetAware-enabled view binding the supplied MatchSet.
func Wrap(v PacketView, set MatchSet) PacketView {
	return batchedView{PacketView: v, set: set}
}

type batchedView struct {
	PacketView
	set MatchSet
}

func (bv batchedView) Matched(pid int) bool {
	if pid < 0 || pid >= len(bv.set) {
		return false
	}
	return bv.set[pid]
}

func isBatchableField(f Field, p *Predicate) bool {
	// Header sub-name is its own target — different per name. Don't batch.
	if f.IsHeaderField && p.HeaderName != "" {
		return false
	}
	// Bool fields can't sensibly contain text; skip.
	if f.Type == TypeBool || f.Type == TypeInt {
		return false
	}
	return true
}
