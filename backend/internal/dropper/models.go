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

// Rule represents a drop rule for a service.
type Rule struct {
	ID        string    `json:"id"`
	ServiceID string    `json:"service_id"`
	Name      string    `json:"name"`
	Type      MatchType `json:"type"`
	Scope     Scope     `json:"scope"`
	Pattern   string    `json:"pattern"`
	Priority  int       `json:"priority"`
	Enabled   bool      `json:"enabled"`
}
