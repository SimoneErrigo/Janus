// Package filter implements the unified expression language used by both
// the packet query API and the drop/alert rules engine.
//
// Grammar (informal):
//
//	expr      := orExpr
//	orExpr    := andExpr (("OR"|"||") andExpr)*
//	andExpr   := notExpr (("AND"|"&&") notExpr)*
//	notExpr   := ("NOT"|"!"|"~") notExpr | atom
//	atom      := "(" orExpr ")" | predicate | bool
//	predicate := field op value
//	             | field                             (bool-field shortcut: == true)
//	field     := body | url | method | status | proto | service
//	           | src | dst | peer | sport | dport
//	           | header | header.<name> | raw | direction
//	           | flagged | contains_flagid | dropped
//	op        := contains | icontains | == | != | matches
//	           | startswith | endswith | in | > | < | >= | <=
//
// The package exposes:
//   - Parse:       source string -> AST
//   - CompileEval: AST -> in-process evaluator (closure tree)
//
// Future steps add CompileSQL (SQL pushdown) and a per-service Aho-Corasick
// batcher used by the rules engine on the hot path.
package filter

// Compile is a one-shot helper: parse + compile to an EvalFunc.
// Returns a function that always reports true when src is empty.
func Compile(src string) (EvalFunc, error) {
	ast, err := Parse(src)
	if err != nil {
		return nil, err
	}
	return CompileEval(ast)
}

// Validate is a parse-only check used by the /api/filter/validate endpoint
// (Step 2). It returns nil on success and a *SyntaxError (or wrapping
// error) on failure.
func Validate(src string) error {
	_, err := Parse(src)
	return err
}
