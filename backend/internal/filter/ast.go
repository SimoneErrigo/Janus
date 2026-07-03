package filter

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
