package filter

import (
	"sort"
	"strings"
)

// Node is the AST root interface for parsed expressions.
type Node interface {
	isNode()
}

// OrNode is a logical OR over its children. Empty Children means false.
type OrNode struct{ Children []Node }

// AndNode is a logical AND over its children. Empty Children means true.
type AndNode struct{ Children []Node }

// NotNode negates its single child.
type NotNode struct{ Child Node }

// BoolLit is a literal `true` or `false` used standalone.
type BoolLit struct{ Value bool }

// Predicate is a leaf comparison: <field> <op> <value>.
// HeaderName is populated only for the special "header.<name>" form.
// Length is set for the "<field>.length" form (aliases .len/.size), which
// compares the byte length of a string/bytes/header field as an integer.
type Predicate struct {
	Field      string
	HeaderName string
	Length     bool
	Op         Op
	Value      Value
}

func (OrNode) isNode()    {}
func (AndNode) isNode()   {}
func (NotNode) isNode()   {}
func (BoolLit) isNode()   {}
func (Predicate) isNode() {}

// FieldsUsed returns the sorted, de-duplicated set of canonical field names
// referenced by the predicates in an expression. Useful for policy checks such
// as "this expression must not touch network/identity fields".
func FieldsUsed(node Node) []string {
	seen := map[string]struct{}{}
	var walk func(Node)
	walk = func(n Node) {
		switch v := n.(type) {
		case *OrNode:
			for _, c := range v.Children {
				walk(c)
			}
		case *AndNode:
			for _, c := range v.Children {
				walk(c)
			}
		case *NotNode:
			walk(v.Child)
		case *Predicate:
			seen[canonicalField(v.Field)] = struct{}{}
		}
	}
	if node != nil {
		walk(node)
	}
	out := make([]string, 0, len(seen))
	for f := range seen {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// NeedsServerEvaluation reports expressions whose browser-side evaluation
// cannot be guaranteed identical to Go/SQLite (payload fields absent from SSE,
// RE2 regexes, CIDRs, header JSON and byte-length semantics).
func NeedsServerEvaluation(node Node) bool {
	needs := false
	var walk func(Node)
	walk = func(n Node) {
		if needs || n == nil {
			return
		}
		switch v := n.(type) {
		case *OrNode:
			for _, child := range v.Children {
				walk(child)
			}
		case *AndNode:
			for _, child := range v.Children {
				walk(child)
			}
		case *NotNode:
			walk(v.Child)
		case *Predicate:
			field := canonicalField(v.Field)
			if field == "body" || field == "raw" || field == "header" || v.Length || v.Op == OpMatches {
				needs = true
				return
			}
			if field == "src" || field == "dst" || field == "peer" {
				if strings.Contains(v.Value.Str, "/") {
					needs = true
					return
				}
				for _, item := range v.Value.List {
					if strings.Contains(item.Str, "/") {
						needs = true
						return
					}
				}
			}
		}
	}
	walk(node)
	return needs
}

// Op is a predicate operator.
type Op string

const (
	OpContains   Op = "contains"
	OpIContains  Op = "icontains"
	OpEq         Op = "=="
	OpNeq        Op = "!="
	OpMatches    Op = "matches"
	OpStartsWith Op = "startswith"
	OpEndsWith   Op = "endswith"
	OpIn         Op = "in"
	OpGT         Op = ">"
	OpLT         Op = "<"
	OpGTE        Op = ">="
	OpLTE        Op = "<="
)

// ValueKind tags the concrete payload of a Value.
type ValueKind int

const (
	ValString ValueKind = iota
	ValNumber
	ValBool
	ValList
)

// Value is a literal in an expression.
type Value struct {
	Kind ValueKind
	Str  string
	Num  int64
	Bool bool
	List []Value
}
