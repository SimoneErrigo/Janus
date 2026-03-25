package dropper

import (
	"encoding/hex"
	"regexp"
	"strings"
	"sync"
)

// Engine evaluates drop rules against request data.
type Engine struct {
	ruleStore *RuleStore
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

// Evaluate checks all enabled rules for the service and returns the first match (by priority).
func (e *Engine) Evaluate(req *HTTPRequest) MatchResult {
	rules := e.ruleStore.ListRules(req.ServiceID)
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
	rules := e.ruleStore.ListRules(req.ServiceID)
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

func (e *Engine) matches(rule *Rule, req *HTTPRequest) bool {
	var target string
	var targetBytes []byte

	switch rule.Scope {
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
