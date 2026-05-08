package filter

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// EvalFunc evaluates an expression against a packet view.
// A nil expression compiles to an EvalFunc that returns true (match all).
type EvalFunc func(PacketView) bool

// CompileEval turns an AST into a closure tree.
// The compiler validates field/op/value compatibility and pre-compiles
// regexes, CIDRs and lower-cased contains needles. All heavy lifting
// happens once here, never on the hot path.
func CompileEval(node Node) (EvalFunc, error) {
	return CompileEvalWith(node, nil)
}

// CompileEvalWith is CompileEval with an optional PredicateHook that can
// intercept individual predicate compilations (used by the rules engine to
// route literal contains predicates through a per-service Aho-Corasick
// batcher). hook may be nil.
func CompileEvalWith(node Node, hook PredicateHook) (EvalFunc, error) {
	if node == nil {
		return func(PacketView) bool { return true }, nil
	}
	return compileNodeHook(node, hook)
}

func compileNodeHook(n Node, hook PredicateHook) (EvalFunc, error) {
	switch v := n.(type) {
	case *OrNode:
		children, err := compileChildrenHook(v.Children, hook)
		if err != nil {
			return nil, err
		}
		if len(children) == 1 {
			return children[0], nil
		}
		return func(p PacketView) bool {
			for _, c := range children {
				if c(p) {
					return true
				}
			}
			return false
		}, nil
	case *AndNode:
		children, err := compileChildrenHook(v.Children, hook)
		if err != nil {
			return nil, err
		}
		if len(children) == 1 {
			return children[0], nil
		}
		return func(p PacketView) bool {
			for _, c := range children {
				if !c(p) {
					return false
				}
			}
			return true
		}, nil
	case *NotNode:
		inner, err := compileNodeHook(v.Child, hook)
		if err != nil {
			return nil, err
		}
		return func(p PacketView) bool { return !inner(p) }, nil
	case *BoolLit:
		val := v.Value
		return func(PacketView) bool { return val }, nil
	case *Predicate:
		if hook != nil {
			if fn, ok := hook.Predicate(v); ok {
				return fn, nil
			}
		}
		return compilePredicate(v)
	}
	return nil, fmt.Errorf("internal: unknown AST node type %T", n)
}

func compileChildrenHook(in []Node, hook PredicateHook) ([]EvalFunc, error) {
	out := make([]EvalFunc, len(in))
	for i, c := range in {
		ev, err := compileNodeHook(c, hook)
		if err != nil {
			return nil, err
		}
		out[i] = ev
	}
	return out, nil
}

func compilePredicate(pr *Predicate) (EvalFunc, error) {
	field, ok := LookupField(pr.Field)
	if !ok {
		return nil, fmt.Errorf("unknown field %q", pr.Field)
	}
	if !opCompatible(field.Type, pr.Op) {
		return nil, fmt.Errorf("operator %q not supported on field %q", pr.Op, pr.Field)
	}

	// Bool predicate: equality only.
	if field.Type == TypeBool {
		want, err := boolValue(pr.Value)
		if err != nil {
			return nil, err
		}
		fname := pr.Field
		switch pr.Op {
		case OpEq:
			return func(p PacketView) bool { return readBool(p, fname) == want }, nil
		case OpNeq:
			return func(p PacketView) bool { return readBool(p, fname) != want }, nil
		}
		return nil, fmt.Errorf("internal: bool op %q not handled", pr.Op)
	}

	// Int predicate.
	if field.Type == TypeInt {
		fname := pr.Field
		switch pr.Op {
		case OpIn:
			nums, err := intList(pr.Value)
			if err != nil {
				return nil, err
			}
			set := make(map[int64]struct{}, len(nums))
			for _, n := range nums {
				set[n] = struct{}{}
			}
			return func(p PacketView) bool {
				_, ok := set[readInt(p, fname)]
				return ok
			}, nil
		}
		want, err := intValue(pr.Value)
		if err != nil {
			return nil, err
		}
		switch pr.Op {
		case OpEq:
			return func(p PacketView) bool { return readInt(p, fname) == want }, nil
		case OpNeq:
			return func(p PacketView) bool { return readInt(p, fname) != want }, nil
		case OpGT:
			return func(p PacketView) bool { return readInt(p, fname) > want }, nil
		case OpLT:
			return func(p PacketView) bool { return readInt(p, fname) < want }, nil
		case OpGTE:
			return func(p PacketView) bool { return readInt(p, fname) >= want }, nil
		case OpLTE:
			return func(p PacketView) bool { return readInt(p, fname) <= want }, nil
		}
	}

	// String / bytes / headers predicate.
	fname := pr.Field
	headerName := pr.HeaderName

	getter := func(p PacketView) string {
		return readString(p, fname, headerName)
	}

	// IP fields get extra CIDR support on `==`, `!=`, `in`.
	isIPField := fname == "src" || fname == "dst" || fname == "peer"

	switch pr.Op {
	case OpContains:
		needle, err := stringValue(pr.Value)
		if err != nil {
			return nil, err
		}
		return func(p PacketView) bool { return strings.Contains(getter(p), needle) }, nil
	case OpIContains:
		needle, err := stringValue(pr.Value)
		if err != nil {
			return nil, err
		}
		needleLower := strings.ToLower(needle)
		return func(p PacketView) bool {
			return strings.Contains(strings.ToLower(getter(p)), needleLower)
		}, nil
	case OpStartsWith:
		needle, err := stringValue(pr.Value)
		if err != nil {
			return nil, err
		}
		return func(p PacketView) bool { return strings.HasPrefix(getter(p), needle) }, nil
	case OpEndsWith:
		needle, err := stringValue(pr.Value)
		if err != nil {
			return nil, err
		}
		return func(p PacketView) bool { return strings.HasSuffix(getter(p), needle) }, nil
	case OpMatches:
		pat, err := stringValue(pr.Value)
		if err != nil {
			return nil, err
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("invalid regex %q: %v", pat, err)
		}
		return func(p PacketView) bool { return re.MatchString(getter(p)) }, nil
	case OpEq, OpNeq:
		want, err := stringValue(pr.Value)
		if err != nil {
			return nil, err
		}
		neg := pr.Op == OpNeq
		if isIPField {
			if matcher, isCIDR := compileCIDR(want); isCIDR {
				return func(p PacketView) bool {
					m := matcher(getter(p))
					if neg {
						return !m
					}
					return m
				}, nil
			}
		}
		return func(p PacketView) bool {
			eq := getter(p) == want
			if neg {
				return !eq
			}
			return eq
		}, nil
	case OpIn:
		items, err := stringList(pr.Value)
		if err != nil {
			return nil, err
		}
		// Compile each item: literal exact match OR CIDR matcher (IP fields only).
		exact := make(map[string]struct{}, len(items))
		var cidrMatchers []func(string) bool
		for _, it := range items {
			if isIPField {
				if m, ok := compileCIDR(it); ok {
					cidrMatchers = append(cidrMatchers, m)
					continue
				}
			}
			exact[it] = struct{}{}
		}
		return func(p PacketView) bool {
			v := getter(p)
			if _, ok := exact[v]; ok {
				return true
			}
			for _, m := range cidrMatchers {
				if m(v) {
					return true
				}
			}
			return false
		}, nil
	}
	return nil, fmt.Errorf("internal: unhandled op %q on string field %q", pr.Op, pr.Field)
}

func stringValue(v Value) (string, error) {
	switch v.Kind {
	case ValString:
		return v.Str, nil
	case ValNumber:
		return strconv.FormatInt(v.Num, 10), nil
	case ValBool:
		if v.Bool {
			return "true", nil
		}
		return "false", nil
	}
	return "", fmt.Errorf("expected string-like value, got list")
}

func intValue(v Value) (int64, error) {
	switch v.Kind {
	case ValNumber:
		return v.Num, nil
	case ValString:
		n, err := strconv.ParseInt(v.Str, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("expected number, got %q", v.Str)
		}
		return n, nil
	}
	return 0, fmt.Errorf("expected number value")
}

func boolValue(v Value) (bool, error) {
	switch v.Kind {
	case ValBool:
		return v.Bool, nil
	case ValString:
		switch strings.ToLower(v.Str) {
		case "true", "1", "yes":
			return true, nil
		case "false", "0", "no":
			return false, nil
		}
	case ValNumber:
		return v.Num != 0, nil
	}
	return false, fmt.Errorf("expected bool value")
}

func stringList(v Value) ([]string, error) {
	if v.Kind != ValList {
		return nil, fmt.Errorf("expected list, got scalar")
	}
	out := make([]string, 0, len(v.List))
	for _, item := range v.List {
		s, err := stringValue(item)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func intList(v Value) ([]int64, error) {
	if v.Kind != ValList {
		return nil, fmt.Errorf("expected list, got scalar")
	}
	out := make([]int64, 0, len(v.List))
	for _, item := range v.List {
		n, err := intValue(item)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

// compileCIDR returns a matcher and true if s is a valid CIDR.
// Matcher reports whether a candidate IP string falls inside the CIDR.
func compileCIDR(s string) (func(string) bool, bool) {
	if !strings.Contains(s, "/") {
		return nil, false
	}
	_, network, err := net.ParseCIDR(s)
	if err != nil {
		return nil, false
	}
	return func(candidate string) bool {
		ip := net.ParseIP(candidate)
		if ip == nil {
			return false
		}
		return network.Contains(ip)
	}, true
}
