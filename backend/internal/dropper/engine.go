package dropper

import (
	"log"
	"sync"

	"github.com/SimoneErrigo/Janus/backend/internal/filter"
)

// RulesCache is the interface the engine uses to read cached rules.
type RulesCache interface {
	GetServiceRules(serviceID string) ([]*Rule, bool)
}

// Engine evaluates drop/alert rules against request data.
//
// The engine is expression-driven:
//   - every rule is parsed once from rule.Expression to a closure;
//   - all literal contains/icontains predicates of one service's enabled
//     rules are batched into a single Aho-Corasick automaton via
//     filter.Batcher, so the body/url/header/raw text is scanned once
//     per packet regardless of how many rules a service has.
//
// The compiled bundle is cached and refreshed whenever the rule-store
// version changes (notifyChange already runs on every CRUD).
type Engine struct {
	ruleStore *RuleStore
	cache     RulesCache

	mu     sync.RWMutex
	bundle *compiledBundle
}

// NewEngine creates a new drop engine.
func NewEngine(ruleStore *RuleStore) *Engine {
	return &Engine{ruleStore: ruleStore}
}

// SetCache sets the Redis cache for rule lookups.
func (e *Engine) SetCache(c RulesCache) { e.cache = c }

// MatchResult holds info about which rule matched.
type MatchResult struct {
	Matched bool
	Rule    *Rule
}

// HTTPRequest holds the data extracted from an HTTP request for matching.
type HTTPRequest struct {
	ServiceID string
	Headers   string // flattened headers as a single string
	Body      []byte
	URL       string
	RawBytes  []byte // full raw bytes if available
}

// compiledBundle is the per-service hot-path artifact: one Aho-Corasick
// scanner shared by every literal contains predicate, plus one closure
// per rule.
type compiledBundle struct {
	version  int64
	rules    []compiledRule
	scanner  *filter.BatchScanner
	hasBatch bool
}

type compiledRule struct {
	rule      *Rule
	predicate filter.EvalFunc
}

// listRules returns rules for a service, checking the cache first.
func (e *Engine) listRules(serviceID string) []*Rule {
	if e.cache != nil {
		if rules, ok := e.cache.GetServiceRules(serviceID); ok {
			return rules
		}
	}
	return e.ruleStore.ListRules(serviceID)
}

// getBundle returns the compiled bundle for a service, recompiling when the
// rule-store version has advanced.
func (e *Engine) getBundle(serviceID string) *compiledBundle {
	currentVersion := int64(0)
	if e.ruleStore != nil {
		currentVersion = e.ruleStore.Version()
	}

	e.mu.RLock()
	b := e.bundle
	e.mu.RUnlock()
	if b != nil && b.version == currentVersion {
		return b
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.bundle != nil && e.bundle.version == currentVersion {
		return e.bundle
	}

	e.bundle = e.compile(serviceID, currentVersion)
	return e.bundle
}

func (e *Engine) compile(serviceID string, version int64) *compiledBundle {
	rules := e.listRules(serviceID)
	bundle := &compiledBundle{version: version, rules: make([]compiledRule, 0, len(rules))}

	batcher := filter.NewBatcher()
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		if r.Expression == "" {
			log.Printf("rules engine: skipping rule %q (%s) — empty expression", r.ID, r.Name)
			continue
		}
		ast, err := filter.Parse(r.Expression)
		if err != nil {
			log.Printf("rules engine: skipping rule %q (%s) — invalid expression %q (%v)", r.ID, r.Name, r.Expression, err)
			continue
		}
		fn, err := filter.CompileEvalWith(ast, batcher)
		if err != nil {
			log.Printf("rules engine: skipping rule %q (%s) — compile failed (%v)", r.ID, r.Name, err)
			continue
		}
		bundle.rules = append(bundle.rules, compiledRule{rule: r, predicate: fn})
	}
	bundle.scanner = batcher.Build()
	bundle.hasBatch = bundle.scanner.PatternCount() > 0
	return bundle
}

// EvaluateActions checks all enabled rules and returns categorized matches.
func (e *Engine) EvaluateActions(req *HTTPRequest) EvalResult {
	bundle := e.getBundle(req.ServiceID)
	view := newView(req)
	var setView filter.PacketView = view
	if bundle.hasBatch {
		set := bundle.scanner.Scan(view)
		setView = filter.Wrap(view, set)
	}

	var result EvalResult
	for _, cr := range bundle.rules {
		if !cr.predicate(setView) {
			continue
		}
		rule := *cr.rule
		result.AllMatched = append(result.AllMatched, rule)
		switch rule.Action {
		case ActionDrop:
			result.ShouldDrop = true
			result.DropRules = append(result.DropRules, rule)
		case ActionAlert:
			result.AlertRules = append(result.AlertRules, rule)
		case ActionBoth:
			result.ShouldDrop = true
			result.DropRules = append(result.DropRules, rule)
			result.AlertRules = append(result.AlertRules, rule)
		default:
			result.ShouldDrop = true
			result.DropRules = append(result.DropRules, rule)
		}
	}
	return result
}

// Evaluate returns the first matching rule (by priority). Kept for callers
// that only need a single result.
func (e *Engine) Evaluate(req *HTTPRequest) MatchResult {
	res := e.EvaluateActions(req)
	if len(res.AllMatched) == 0 {
		return MatchResult{}
	}
	return MatchResult{Matched: true, Rule: &res.AllMatched[0]}
}

// EvaluateAll returns every matching rule, copies of *Rule.
func (e *Engine) EvaluateAll(req *HTTPRequest) []Rule {
	return e.EvaluateActions(req).AllMatched
}

// EvalResult holds categorized rule matches.
type EvalResult struct {
	ShouldDrop bool   // true if any drop or both rule matched
	DropRules  []Rule // rules with action=drop or both
	AlertRules []Rule // rules with action=alert or both
	AllMatched []Rule // all matched rules (all actions)
}
