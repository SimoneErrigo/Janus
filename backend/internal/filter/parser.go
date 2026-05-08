package filter

import (
	"fmt"
	"strconv"
	"strings"
)

// Parse turns an expression source string into an AST.
// An empty (or whitespace-only) source parses to nil — callers treat nil as "match all".
func Parse(src string) (Node, error) {
	if strings.TrimSpace(src) == "" {
		return nil, nil
	}
	toks, err := tokenize(src)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	node, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.peek().kind != tkEOF {
		t := p.peek()
		return nil, &SyntaxError{Pos: t.pos, Message: fmt.Sprintf("unexpected token %q", t.val)}
	}
	return node, nil
}

type parser struct {
	toks []token
	i    int
}

func (p *parser) peek() token {
	return p.toks[p.i]
}
func (p *parser) advance() token {
	t := p.toks[p.i]
	p.i++
	return t
}
func (p *parser) match(k tokKind) bool {
	if p.peek().kind == k {
		p.advance()
		return true
	}
	return false
}

func (p *parser) parseOr() (Node, error) {
	first, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	if p.peek().kind != tkOr {
		return first, nil
	}
	children := []Node{first}
	for p.peek().kind == tkOr {
		p.advance()
		next, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		children = append(children, next)
	}
	return &OrNode{Children: children}, nil
}

func (p *parser) parseAnd() (Node, error) {
	first, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	if p.peek().kind != tkAnd {
		return first, nil
	}
	children := []Node{first}
	for p.peek().kind == tkAnd {
		p.advance()
		next, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		children = append(children, next)
	}
	return &AndNode{Children: children}, nil
}

func (p *parser) parseNot() (Node, error) {
	if p.peek().kind == tkNot {
		p.advance()
		child, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return &NotNode{Child: child}, nil
	}
	return p.parseAtom()
}

func (p *parser) parseAtom() (Node, error) {
	t := p.peek()
	switch t.kind {
	case tkLParen:
		p.advance()
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if !p.match(tkRParen) {
			pp := p.peek()
			return nil, &SyntaxError{Pos: pp.pos, Message: "expected `)`"}
		}
		return inner, nil
	case tkBool:
		p.advance()
		return &BoolLit{Value: t.val == "true"}, nil
	case tkIdent:
		return p.parsePredicate()
	case tkEOF:
		return nil, &SyntaxError{Pos: t.pos, Message: "unexpected end of expression"}
	}
	return nil, &SyntaxError{Pos: t.pos, Message: fmt.Sprintf("unexpected token %q", t.val)}
}

// parsePredicate handles:
//   <field> <op> <value>
//   <field>                                  (bool field shortcut: equivalent to <field> == true)
//   header.<name> <op> <value>
func (p *parser) parsePredicate() (Node, error) {
	field := p.advance()
	pred := Predicate{Field: strings.ToLower(field.val)}

	// header.<name>
	if p.peek().kind == tkDot {
		if pred.Field != "header" && pred.Field != "headers" {
			t := p.peek()
			return nil, &SyntaxError{Pos: t.pos, Message: "only `header.` accepts a sub-name"}
		}
		p.advance() // consume dot
		nm := p.peek()
		if nm.kind != tkIdent {
			return nil, &SyntaxError{Pos: nm.pos, Message: "expected header name after `.`"}
		}
		p.advance()
		pred.Field = "header"
		pred.HeaderName = nm.val
	}

	// canonicalize aliases
	pred.Field = canonicalField(pred.Field)

	// bare-field bool shortcut (e.g. `flagged`)
	switch p.peek().kind {
	case tkAnd, tkOr, tkRParen, tkEOF:
		pred.Op = OpEq
		pred.Value = Value{Kind: ValBool, Bool: true}
		return &pred, nil
	}

	// op
	opTok := p.peek()
	switch opTok.kind {
	case tkOp:
		p.advance()
		switch opTok.val {
		case "==":
			pred.Op = OpEq
		case "!=":
			pred.Op = OpNeq
		case "<":
			pred.Op = OpLT
		case "<=":
			pred.Op = OpLTE
		case ">":
			pred.Op = OpGT
		case ">=":
			pred.Op = OpGTE
		}
	case tkKwOp:
		p.advance()
		pred.Op = Op(opTok.val)
	default:
		return nil, &SyntaxError{Pos: opTok.pos, Message: fmt.Sprintf("expected operator after field `%s`", field.val)}
	}

	// value
	v, err := p.parseValue(pred.Op == OpIn)
	if err != nil {
		return nil, err
	}
	pred.Value = v
	return &pred, nil
}

// parseValue reads a literal: string, number, bool, identifier (for IPs/CIDRs/enums),
// or a parenthesized comma-separated list (for `in`).
// When inList is true the function expects a list literal.
func (p *parser) parseValue(inList bool) (Value, error) {
	if inList {
		t := p.peek()
		if t.kind != tkLParen {
			return Value{}, &SyntaxError{Pos: t.pos, Message: "expected `(` after `in`"}
		}
		p.advance()
		var items []Value
		for {
			if p.peek().kind == tkRParen {
				p.advance()
				break
			}
			item, err := p.parseScalarValue()
			if err != nil {
				return Value{}, err
			}
			items = append(items, item)
			if p.peek().kind == tkComma {
				p.advance()
				continue
			}
			if p.peek().kind == tkRParen {
				p.advance()
				break
			}
			t := p.peek()
			return Value{}, &SyntaxError{Pos: t.pos, Message: "expected `,` or `)` in list"}
		}
		return Value{Kind: ValList, List: items}, nil
	}
	return p.parseScalarValue()
}

func (p *parser) parseScalarValue() (Value, error) {
	t := p.peek()
	switch t.kind {
	case tkString:
		p.advance()
		return Value{Kind: ValString, Str: t.val}, nil
	case tkNumber:
		p.advance()
		// Numbers may continue as dotted IPs (e.g. 10.0.0.1 or 10.0.0.0/8).
		// readIdent already absorbs `/` and digits when starting from a
		// letter, but a leading number stops at the first `.`. Reassemble
		// here using subsequent tkDot / tkNumber / tkIdent tokens.
		full, ok := p.tryReadDottedFromNumber(t.val)
		if ok {
			return Value{Kind: ValString, Str: full}, nil
		}
		// Plain number.
		n, err := strconv.ParseInt(t.val, 10, 64)
		if err != nil {
			return Value{}, &SyntaxError{Pos: t.pos, Message: fmt.Sprintf("invalid number %q", t.val)}
		}
		return Value{Kind: ValNumber, Num: n}, nil
	case tkBool:
		p.advance()
		return Value{Kind: ValBool, Bool: t.val == "true"}, nil
	case tkIdent:
		// Bareword value (e.g. enum, identifier). Reassemble dotted forms too.
		p.advance()
		full := t.val
		if dotted, ok := p.tryReadDottedFromIdent(full); ok {
			return Value{Kind: ValString, Str: dotted}, nil
		}
		return Value{Kind: ValString, Str: full}, nil
	case tkLParen:
		// Allow parenthesized scalar — tolerated, mostly for symmetry.
		p.advance()
		v, err := p.parseScalarValue()
		if err != nil {
			return Value{}, err
		}
		if !p.match(tkRParen) {
			return Value{}, &SyntaxError{Pos: p.peek().pos, Message: "expected `)`"}
		}
		return v, nil
	}
	return Value{}, &SyntaxError{Pos: t.pos, Message: fmt.Sprintf("expected literal value, got %q", t.val)}
}

// tryReadDottedFromNumber rebuilds dotted IPs / CIDRs whose first part the
// lexer consumed as a number. `head` is the already-consumed numeric part.
// Returns the full token text and true if a dot follows.
func (p *parser) tryReadDottedFromNumber(head string) (string, bool) {
	if p.peek().kind != tkDot {
		return "", false
	}
	var b strings.Builder
	b.WriteString(head)
	for p.peek().kind == tkDot {
		p.advance()
		b.WriteByte('.')
		nx := p.peek()
		if nx.kind != tkNumber && nx.kind != tkIdent {
			// rollback would be nice but our tokens are immutable; emit what
			// we have. Caller will treat as identifier-string.
			break
		}
		p.advance()
		b.WriteString(nx.val)
	}
	return b.String(), true
}

// tryReadDottedFromIdent supports cases where lex started with letters and
// continued through a dot — only relevant if the lexer ever returns a `.`
// token after an ident. Conservative: just returns false today.
func (p *parser) tryReadDottedFromIdent(head string) (string, bool) {
	_ = head
	return "", false
}
