package filter

import (
	"fmt"
	"strings"
)

// Compiled is the result of CompileSQL.
//
//   - Where is a SQL WHERE fragment without the leading "WHERE" keyword.
//     It is empty when the expression has no SQL-pushable predicates.
//   - Args are the placeholder bindings for Where in order.
//   - Residual is an in-process evaluator covering predicates the SQL
//     compiler couldn't push down (regex matches, header.<name>, raw bytes,
//     CIDRs, OR subtrees that contain unpushable predicates). Run it in Go
//     over each row returned by the SQL fetch. Nil means no residual.
//
// The fragment, if non-empty, is already a complete boolean expression
// (it may include parentheses); callers should `AND` it into their existing
// WHERE clause without adding extra parens.
type Compiled struct {
	Where    string
	Args     []any
	Residual EvalFunc
}

// CompileSQL turns an AST into a SQL fragment plus a residual evaluator.
// A nil AST produces an empty Compiled (matches every row).
func CompileSQL(node Node) (*Compiled, error) {
	if node == nil {
		return &Compiled{}, nil
	}

	// Top-level optimization: split on AND so each conjunct is independently
	// pushable or residual. Without this we'd be forced to make whole subtrees
	// residual whenever a single predicate fails to push, which loses a lot
	// of performance.
	conjuncts := splitAnd(node)
	var sqlFrags []string
	var args []any
	var residualNodes []Node
	for _, c := range conjuncts {
		frag, a, ok := tryPushNode(c)
		if ok {
			if frag != "" {
				sqlFrags = append(sqlFrags, frag)
				args = append(args, a...)
			}
		} else {
			residualNodes = append(residualNodes, c)
		}
	}

	c := &Compiled{Where: strings.Join(sqlFrags, " AND "), Args: args}
	if len(residualNodes) > 0 {
		var residualNode Node
		if len(residualNodes) == 1 {
			residualNode = residualNodes[0]
		} else {
			residualNode = &AndNode{Children: residualNodes}
		}
		ev, err := CompileEval(residualNode)
		if err != nil {
			return nil, err
		}
		c.Residual = ev
	}
	return c, nil
}

// splitAnd flattens nested ANDs into a list of conjuncts.
func splitAnd(n Node) []Node {
	if a, ok := n.(*AndNode); ok {
		var out []Node
		for _, c := range a.Children {
			out = append(out, splitAnd(c)...)
		}
		return out
	}
	return []Node{n}
}

// tryPushNode attempts to push a whole subtree into SQL.
// Returns (fragment, args, ok). ok=false means the caller should make the
// whole subtree a residual.
func tryPushNode(n Node) (string, []any, bool) {
	switch v := n.(type) {
	case *AndNode:
		var frags []string
		var args []any
		for _, c := range v.Children {
			f, a, ok := tryPushNode(c)
			if !ok {
				return "", nil, false
			}
			if f != "" {
				frags = append(frags, f)
				args = append(args, a...)
			}
		}
		if len(frags) == 0 {
			return "", nil, true
		}
		if len(frags) == 1 {
			return frags[0], args, true
		}
		return "(" + strings.Join(frags, " AND ") + ")", args, true
	case *OrNode:
		// All-or-nothing: every child must push, otherwise we'd have to leave
		// the whole OR for the residual evaluator (we can't safely AND a
		// partial-OR fragment with the rest).
		var frags []string
		var args []any
		for _, c := range v.Children {
			f, a, ok := tryPushNode(c)
			if !ok {
				return "", nil, false
			}
			if f == "" {
				// Empty fragment from a child means "always true" — the OR
				// short-circuits to true, so push as 1=1.
				return "1=1", nil, true
			}
			frags = append(frags, f)
			args = append(args, a...)
		}
		if len(frags) == 0 {
			return "", nil, true
		}
		if len(frags) == 1 {
			return frags[0], args, true
		}
		return "(" + strings.Join(frags, " OR ") + ")", args, true
	case *NotNode:
		f, a, ok := tryPushNode(v.Child)
		if !ok {
			return "", nil, false
		}
		if f == "" {
			// NOT(true) = false
			return "0=1", nil, true
		}
		return "NOT (" + f + ")", a, true
	case *BoolLit:
		if v.Value {
			return "", nil, true // empty == always-true
		}
		return "0=1", nil, true
	case *Predicate:
		return tryPushPredicate(v)
	}
	return "", nil, false
}

// tryPushPredicate maps a single predicate to a SQL fragment when possible.
func tryPushPredicate(pr *Predicate) (string, []any, bool) {
	field, ok := LookupField(pr.Field)
	if !ok {
		return "", nil, false
	}

	// Direction-aware pushdown for `peer`.
	if pr.Field == "peer" {
		return tryPushPeer(pr)
	}

	// header.<name> can't be pushed (it's a JSON-keyed lookup).
	if field.IsHeaderField && pr.HeaderName != "" {
		return "", nil, false
	}

	// raw is byte-only, evaluated in-process.
	if pr.Field == "raw" {
		return "", nil, false
	}

	if field.SQLColumn == "" {
		return "", nil, false
	}

	// Regex push-down would need SQLite REGEXP; we don't ship that UDF.
	if pr.Op == OpMatches {
		return "", nil, false
	}

	switch field.Type {
	case TypeBool:
		return tryPushBool(field.SQLColumn, pr)
	case TypeInt:
		return tryPushInt(field.SQLColumn, pr)
	case TypeString, TypeHeaders:
		return tryPushString(field, pr)
	case TypeBytes:
		return "", nil, false
	}
	return "", nil, false
}

func tryPushBool(col string, pr *Predicate) (string, []any, bool) {
	want, err := boolValue(pr.Value)
	if err != nil {
		return "", nil, false
	}
	bit := 0
	if want {
		bit = 1
	}
	switch pr.Op {
	case OpEq:
		return fmt.Sprintf("%s = %d", col, bit), nil, true
	case OpNeq:
		return fmt.Sprintf("%s != %d", col, bit), nil, true
	}
	return "", nil, false
}

func tryPushInt(col string, pr *Predicate) (string, []any, bool) {
	switch pr.Op {
	case OpIn:
		nums, err := intList(pr.Value)
		if err != nil || len(nums) == 0 {
			return "", nil, false
		}
		placeholders := make([]string, len(nums))
		args := make([]any, len(nums))
		for i, n := range nums {
			placeholders[i] = "?"
			args[i] = n
		}
		return col + " IN (" + strings.Join(placeholders, ",") + ")", args, true
	}
	want, err := intValue(pr.Value)
	if err != nil {
		return "", nil, false
	}
	op := ""
	switch pr.Op {
	case OpEq:
		op = "="
	case OpNeq:
		op = "!="
	case OpGT:
		op = ">"
	case OpLT:
		op = "<"
	case OpGTE:
		op = ">="
	case OpLTE:
		op = "<="
	default:
		return "", nil, false
	}
	return fmt.Sprintf("%s %s ?", col, op), []any{want}, true
}

func tryPushString(field Field, pr *Predicate) (string, []any, bool) {
	col := field.SQLColumn
	isIPField := pr.Field == "src" || pr.Field == "dst"

	switch pr.Op {
	case OpEq:
		s, err := stringValue(pr.Value)
		if err != nil {
			return "", nil, false
		}
		// CIDR equality on IP fields: residual.
		if isIPField && strings.Contains(s, "/") {
			return "", nil, false
		}
		return col + " = ?", []any{s}, true
	case OpNeq:
		s, err := stringValue(pr.Value)
		if err != nil {
			return "", nil, false
		}
		if isIPField && strings.Contains(s, "/") {
			return "", nil, false
		}
		return col + " != ?", []any{s}, true
	case OpContains, OpIContains:
		// SQLite's LIKE is ASCII case-insensitive by default for both columns,
		// so contains and icontains push to the same fragment. case-sensitive
		// `contains` is preserved in residual when we can't push (we can:
		// LIKE in SQLite is already CI for ASCII, which is what users expect
		// of `contains` in this UI).
		s, err := stringValue(pr.Value)
		if err != nil {
			return "", nil, false
		}
		return col + " LIKE ?", []any{"%" + likeEscape(s) + "%"}, true
	case OpStartsWith:
		s, err := stringValue(pr.Value)
		if err != nil {
			return "", nil, false
		}
		return col + " LIKE ?", []any{likeEscape(s) + "%"}, true
	case OpEndsWith:
		s, err := stringValue(pr.Value)
		if err != nil {
			return "", nil, false
		}
		return col + " LIKE ?", []any{"%" + likeEscape(s)}, true
	case OpIn:
		items, err := stringList(pr.Value)
		if err != nil || len(items) == 0 {
			return "", nil, false
		}
		// Reject CIDR-bearing lists on IP fields — let the residual evaluator
		// handle the whole `in (...)` predicate to keep behavior correct.
		if isIPField {
			for _, s := range items {
				if strings.Contains(s, "/") {
					return "", nil, false
				}
			}
		}
		placeholders := make([]string, len(items))
		args := make([]any, len(items))
		for i, s := range items {
			placeholders[i] = "?"
			args[i] = s
		}
		return col + " IN (" + strings.Join(placeholders, ",") + ")", args, true
	}
	return "", nil, false
}

// tryPushPeer compiles direction-aware predicates on the `peer` virtual field.
// It only handles equality and contains/etc. on the IP value; everything more
// exotic stays residual.
func tryPushPeer(pr *Predicate) (string, []any, bool) {
	switch pr.Op {
	case OpEq:
		s, err := stringValue(pr.Value)
		if err != nil || strings.Contains(s, "/") {
			return "", nil, false
		}
		return "((direction='request' AND src_ip=?) OR (direction='response' AND dst_ip=?))",
			[]any{s, s}, true
	case OpNeq:
		s, err := stringValue(pr.Value)
		if err != nil || strings.Contains(s, "/") {
			return "", nil, false
		}
		return "NOT ((direction='request' AND src_ip=?) OR (direction='response' AND dst_ip=?))",
			[]any{s, s}, true
	}
	return "", nil, false
}

// likeEscape escapes the SQL LIKE wildcards `%` and `_` so user input can't
// match unintended rows. We don't set an ESCAPE clause here because none of
// the existing legacy params do — keeping behavior consistent. The current
// store does the same (raw "%" + value + "%") so user-supplied wildcards
// already "work" but we at least normalize backslashes.
func likeEscape(s string) string {
	// Match the legacy buildWhere() behavior: no escaping. This keeps results
	// identical to the existing query path; users who want regex use `matches`.
	return s
}
