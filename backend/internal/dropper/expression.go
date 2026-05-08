package dropper

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// DeriveExpression produces the unified-DSL form of a legacy rule
// (Type/Scope/Pattern). Returns "" when the rule isn't expressible — that
// case shouldn't happen in practice but lets the caller skip the migration.
//
// Mappings:
//
//	{string,  scope, "x"}  →  scope contains "x"
//	{regex,   scope, "x"}  →  scope matches  "x"
//	{bytes,   scope, "DE"} →  scope contains "\xDE"
//
// Comma-separated scopes (e.g. "body,header") become an OR group:
//
//	(body contains "x" OR header contains "x")
func DeriveExpression(r *Rule) string {
	if r == nil || r.Pattern == "" {
		return ""
	}
	scopes := splitScopes(string(r.Scope))
	if len(scopes) == 0 {
		return ""
	}
	pieces := make([]string, 0, len(scopes))
	for _, s := range scopes {
		piece := derivePiece(s, r.Type, r.Pattern)
		if piece == "" {
			continue
		}
		pieces = append(pieces, piece)
	}
	if len(pieces) == 0 {
		return ""
	}
	if len(pieces) == 1 {
		return pieces[0]
	}
	return "(" + strings.Join(pieces, " OR ") + ")"
}

func derivePiece(scope string, typ MatchType, pattern string) string {
	field := scopeToField(Scope(scope))
	if field == "" {
		return ""
	}
	switch typ {
	case MatchString:
		return fmt.Sprintf(`%s contains %s`, field, quoteString(pattern))
	case MatchRegex:
		return fmt.Sprintf(`%s matches %s`, field, quoteString(pattern))
	case MatchBytes:
		decoded, err := hex.DecodeString(strings.TrimSpace(pattern))
		if err != nil {
			return ""
		}
		return fmt.Sprintf(`%s contains %s`, field, quoteBytes(decoded))
	}
	return ""
}

func scopeToField(s Scope) string {
	switch s {
	case ScopeBody:
		return "body"
	case ScopeHeader:
		return "header"
	case ScopeURL:
		return "url"
	case ScopeRaw:
		return "raw"
	}
	return ""
}

func splitScopes(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// quoteString renders a string literal for the DSL: wraps in double quotes
// and escapes \, ", \n, \r, \t. Other control bytes get rendered as \xHH.
func quoteString(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if c < 0x20 || c == 0x7F {
				fmt.Fprintf(&b, `\x%02X`, c)
			} else {
				b.WriteByte(c)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// quoteBytes renders a byte slice as a DSL string literal using \xHH for
// every non-printable byte. Printable ASCII passes through.
func quoteBytes(buf []byte) string {
	var b strings.Builder
	b.Grow(len(buf)*4 + 2)
	b.WriteByte('"')
	for _, c := range buf {
		switch {
		case c == '\\':
			b.WriteString(`\\`)
		case c == '"':
			b.WriteString(`\"`)
		case c >= 0x20 && c < 0x7F:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, `\x%02X`, c)
		}
	}
	b.WriteByte('"')
	return b.String()
}
