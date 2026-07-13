package dropper

// MatchType defines how the pattern is interpreted.
type MatchType string

const (
	MatchString MatchType = "string"
	MatchRegex  MatchType = "regex"
	MatchBytes  MatchType = "bytes"
)

// Scope defines which part of the request to match against.
type Scope string

const (
	ScopeHeader Scope = "header"
	ScopeBody   Scope = "body"
	ScopeURL    Scope = "url"
	ScopeRaw    Scope = "raw"
)

// Action defines what happens when a rule matches.
type Action string

const (
	ActionDrop  Action = "drop"
	ActionAlert Action = "alert"
	ActionBoth  Action = "both"
)

// Rule represents a drop/alert rule for a service.
//
// During the Step 4 → Step 5 migration the rule carries both the legacy
// (Type/Scope/Pattern) fields and the new unified Expression. The hot-path
// engine still reads the legacy fields; Expression is the source of truth
// for the frontend and will become the only matcher input in Step 5.
type Rule struct {
	ID        string    `json:"id"`
	ServiceID string    `json:"service_id"`
	Name      string    `json:"name"`
	Type      MatchType `json:"type"`
	Scope     Scope     `json:"scope"`
	Pattern   string    `json:"pattern"`
	// Expression is the unified DSL form of the rule. Populated automatically
	// from legacy fields on load when missing.
	Expression string `json:"expression,omitempty"`
	Priority   int    `json:"priority"`
	Enabled    bool   `json:"enabled"`
	Action     Action `json:"action"`
	CreatedBy  string `json:"created_by,omitempty"` // display name of the user who created this rule
	Revision   int    `json:"revision"`
	UpdatedAt  int64  `json:"updated_at,omitempty"`
}

// RuleRevision is an immutable snapshot written before a revision becomes
// active. The separate history allows rollback without changing the compact
// rules.json format consumed by existing installations.
type RuleRevision struct {
	Rule       Rule  `json:"rule"`
	RecordedAt int64 `json:"recorded_at"`
}

// IsFlagRule returns true if this rule is an auto-generated flag rule.
func (r *Rule) IsFlagRule() bool {
	return len(r.ID) > len(flagRulePrefix) && r.ID[:len(flagRulePrefix)] == flagRulePrefix
}

const flagRulePrefix = "flag-auto-"
