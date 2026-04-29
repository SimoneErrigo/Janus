package dropper

import (
	"encoding/hex"
	"regexp"
	"strings"
	"sync"
)

// RulesCache is the interface the engine uses to read cached rules.
type RulesCache interface {
	GetServiceRules(serviceID string) ([]*Rule, bool)
}

// Engine evaluates drop rules against request data.
type Engine struct {
	ruleStore *RuleStore
	cache     RulesCache
	// Cache compiled regexes
	mu       sync.RWMutex
	regexMap map[string]*regexp.Regexp
}

// NewEngine creates a new drop engine.
func NewEngine(ruleStore *RuleStore) *Engine {
	return &Engine{
		ruleStore: ruleStore,
		regexMap:  make(map[string]*regexp.Regexp),
	}
}

// SetCache sets the Redis cache for rule lookups.
func (e *Engine) SetCache(c RulesCache) {
	e.cache = c
}

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

// listRules returns rules for a service, checking the cache first.
func (e *Engine) listRules(serviceID string) []*Rule {
	if e.cache != nil {
		if rules, ok := e.cache.GetServiceRules(serviceID); ok {
			return rules
		}
	}
	return e.ruleStore.ListRules(serviceID)
}

// Evaluate checks all enabled rules for the service and returns the first match (by priority).
func (e *Engine) Evaluate(req *HTTPRequest) MatchResult {
	rules := e.listRules(req.ServiceID)
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if e.matches(rule, req) {
			return MatchResult{Matched: true, Rule: rule}
		}
	}
	return MatchResult{Matched: false}
}

// EvaluateAll checks all enabled rules for the service and returns every match.
func (e *Engine) EvaluateAll(req *HTTPRequest) []Rule {
	rules := e.listRules(req.ServiceID)
	var matched []Rule
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if e.matches(rule, req) {
			matched = append(matched, *rule)
		}
	}
	return matched
}

// EvalResult holds categorized rule matches.
type EvalResult struct {
	ShouldDrop bool   // true if any drop or both rule matched
	DropRules  []Rule // rules with action=drop or both
	AlertRules []Rule // rules with action=alert or both
	AllMatched []Rule // all matched rules (all actions)
}

// EvaluateActions checks all enabled rules and categorizes matches by action.
func (e *Engine) EvaluateActions(req *HTTPRequest) EvalResult {
	matched := e.EvaluateAll(req)
	var result EvalResult
	result.AllMatched = matched

	for _, rule := range matched {
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
			// Legacy rules without action default to drop
			result.ShouldDrop = true
			result.DropRules = append(result.DropRules, rule)
		}
	}
	return result
}

func (e *Engine) matches(rule *Rule, req *HTTPRequest) bool {
	// Support comma-separated scopes (e.g. "body,header")
	scopes := strings.Split(string(rule.Scope), ",")
	for _, s := range scopes {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if e.matchesScope(Scope(s), rule, req) {
			return true
		}
	}
	return false
}

func (e *Engine) matchesScope(scope Scope, rule *Rule, req *HTTPRequest) bool {
	var target string
	var targetBytes []byte

	switch scope {
	case ScopeHeader:
		target = req.Headers
	case ScopeBody:
		target = string(req.Body)
		targetBytes = req.Body
	case ScopeURL:
		target = req.URL
	case ScopeRaw:
		target = string(req.RawBytes)
		targetBytes = req.RawBytes
	default:
		return false
	}

	switch rule.Type {
	case MatchString:
		return strings.Contains(target, rule.Pattern)
	case MatchRegex:
		return e.matchRegex(rule.Pattern, target)
	case MatchBytes:
		return e.matchBytes(rule.Pattern, targetBytes)
	default:
		return false
	}
}

func (e *Engine) matchRegex(pattern, target string) bool {
	re := e.getCompiledRegex(pattern)
	if re == nil {
		return false
	}
	return re.MatchString(target)
}

func (e *Engine) getCompiledRegex(pattern string) *regexp.Regexp {
	e.mu.RLock()
	re, ok := e.regexMap[pattern]
	e.mu.RUnlock()
	if ok {
		return re
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Double-check after acquiring write lock
	if re, ok := e.regexMap[pattern]; ok {
		return re
	}

	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	e.regexMap[pattern] = compiled
	return compiled
}

func (e *Engine) matchBytes(hexPattern string, target []byte) bool {
	if len(target) == 0 {
		return false
	}
	patternBytes, err := hex.DecodeString(hexPattern)
	if err != nil {
		return false
	}
	return strings.Contains(string(target), string(patternBytes))
}
