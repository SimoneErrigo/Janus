package filter

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

type tokKind int

const (
	tkEOF tokKind = iota
	tkIdent
	tkString
	tkNumber
	tkLParen
	tkRParen
	tkComma
	tkDot
	tkAnd
	tkOr
	tkNot
	tkOp   // ==, !=, <, <=, >, >=
	tkKwOp // contains, icontains, matches, startswith, endswith, in
	tkBool // true / false
)

type token struct {
	kind tokKind
	val  string
	pos  int // 0-based byte offset in source
}

func (t token) String() string {
	return fmt.Sprintf("{%d %q@%d}", t.kind, t.val, t.pos)
}

// SyntaxError carries a 0-based byte position so the frontend can underline
// the offending token.
type SyntaxError struct {
	Pos     int
	Message string
}

func (e *SyntaxError) Error() string {
	return fmt.Sprintf("syntax error at %d: %s", e.Pos, e.Message)
}

// keyword operators recognized as a token kind tkKwOp.
var keywordOps = map[string]bool{
	"contains":   true,
	"icontains":  true,
	"matches":    true,
	"startswith": true,
	"endswith":   true,
	"in":         true,
	"exists":     true,
	"missing":    true,
}

// reserved logical keywords (case-insensitive).
var logicalKeywords = map[string]tokKind{
	"and": tkAnd,
	"or":  tkOr,
	"not": tkNot,
}

func tokenize(src string) ([]token, error) {
	var out []token
	i := 0
	n := len(src)

	for i < n {
		c := src[i]
		// whitespace
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			i++
			continue
		}
		// punctuation
		switch c {
		case '(':
			out = append(out, token{tkLParen, "(", i})
			i++
			continue
		case ')':
			out = append(out, token{tkRParen, ")", i})
			i++
			continue
		case ',':
			out = append(out, token{tkComma, ",", i})
			i++
			continue
		case '.':
			out = append(out, token{tkDot, ".", i})
			i++
			continue
		}
		// && / ||
		if c == '&' && i+1 < n && src[i+1] == '&' {
			out = append(out, token{tkAnd, "&&", i})
			i += 2
			continue
		}
		if c == '|' && i+1 < n && src[i+1] == '|' {
			out = append(out, token{tkOr, "||", i})
			i += 2
			continue
		}
		// ! and ~ as NOT (single char). Note: != is a comparison.
		if c == '!' && (i+1 >= n || src[i+1] != '=') {
			out = append(out, token{tkNot, "!", i})
			i++
			continue
		}
		if c == '~' {
			out = append(out, token{tkNot, "~", i})
			i++
			continue
		}
		// comparison operators: ==, !=, <=, >=, <, >
		if op, w := readOp(src, i); op != "" {
			out = append(out, token{tkOp, op, i})
			i += w
			continue
		}
		// string literal
		if c == '"' || c == '\'' {
			s, w, err := readStringLiteral(src, i, c)
			if err != nil {
				return nil, err
			}
			out = append(out, token{tkString, s, i})
			i += w
			continue
		}
		// number — also catches dotted-decimal IPs and CIDRs so they tokenize
		// as a single identifier-shaped value rather than fragmenting.
		if c >= '0' && c <= '9' {
			s, w, k := readNumber(src, i)
			out = append(out, token{k, s, i})
			i += w
			continue
		}
		// identifier (also catches CIDR / dotted IPs in the in-list context;
		// those are kept as raw identifiers and reparsed by the value-resolver)
		if isIdentStart(rune(c)) {
			s, w := readIdent(src, i)
			low := strings.ToLower(s)
			if kk, ok := logicalKeywords[low]; ok {
				out = append(out, token{kk, low, i})
			} else if low == "true" || low == "false" {
				out = append(out, token{tkBool, low, i})
			} else if keywordOps[low] {
				out = append(out, token{tkKwOp, low, i})
			} else {
				out = append(out, token{tkIdent, s, i})
			}
			i += w
			continue
		}
		return nil, &SyntaxError{Pos: i, Message: fmt.Sprintf("unexpected character %q", c)}
	}

	out = append(out, token{tkEOF, "", n})
	return out, nil
}

func readOp(src string, i int) (string, int) {
	n := len(src)
	if i+1 < n {
		two := src[i : i+2]
		switch two {
		case "==", "!=", "<=", ">=":
			return two, 2
		}
	}
	switch src[i] {
	case '<', '>':
		return string(src[i]), 1
	}
	return "", 0
}

func readStringLiteral(src string, i int, quote byte) (string, int, error) {
	n := len(src)
	var b strings.Builder
	j := i + 1
	for j < n {
		c := src[j]
		if c == '\\' && j+1 < n {
			next := src[j+1]
			switch next {
			case 'n':
				b.WriteByte('\n')
				j += 2
				continue
			case 't':
				b.WriteByte('\t')
				j += 2
				continue
			case 'r':
				b.WriteByte('\r')
				j += 2
				continue
			case '\\':
				b.WriteByte('\\')
				j += 2
				continue
			case '"':
				b.WriteByte('"')
				j += 2
				continue
			case '\'':
				b.WriteByte('\'')
				j += 2
				continue
			case 'x':
				// \xHH — two hex digits → one raw byte. Used by byte-pattern rules.
				if j+3 >= n || !isHex(src[j+2]) || !isHex(src[j+3]) {
					return "", 0, &SyntaxError{Pos: j, Message: "invalid \\x escape, expected two hex digits"}
				}
				b.WriteByte(hexByte(src[j+2], src[j+3]))
				j += 4
				continue
			default:
				b.WriteByte(next)
				j += 2
				continue
			}
		}
		if c == quote {
			return b.String(), j - i + 1, nil
		}
		b.WriteByte(c)
		j++
	}
	return "", 0, &SyntaxError{Pos: i, Message: "unterminated string literal"}
}

func readNumber(src string, i int) (string, int, tokKind) {
	n := len(src)
	j := i
	for j < n && src[j] >= '0' && src[j] <= '9' {
		j++
	}
	// Absorb subsequent `.<digits>` and `/<digits>` runs so dotted-decimal
	// IPs (10.0.5.7) and CIDRs (10.0.0.0/8) become one token.
	isIPish := false
	for j < n && (src[j] == '.' || src[j] == '/') {
		if j+1 >= n || src[j+1] < '0' || src[j+1] > '9' {
			break
		}
		isIPish = true
		j++
		for j < n && src[j] >= '0' && src[j] <= '9' {
			j++
		}
	}
	kind := tkNumber
	if isIPish {
		kind = tkIdent
	}
	return src[i:j], j - i, kind
}

func isIdentStart(r rune) bool {
	return r == '_' || unicode.IsLetter(r)
}
func isIdentPart(r rune) bool {
	return r == '_' || r == '-' || r == '/' || unicode.IsLetter(r) || unicode.IsDigit(r)
}

// readIdent consumes a bare identifier. We allow `-`, `_`, and `/` so that
// header names like `Content-Type` and CIDR-ish text such as `10.0.0.0/8`
// (when used after `in`) tokenize cleanly. Dots are emitted as tkDot so
// `header.User-Agent` becomes `header` `.` `User-Agent` and dotted IPs in
// list context are reassembled by the parser.
func readIdent(src string, i int) (string, int) {
	n := len(src)
	j := i
	for j < n {
		r := rune(src[j])
		if !isIdentPart(r) {
			break
		}
		j++
	}
	return src[i:j], j - i
}

// helper used by parser when reassembling dotted IPs / CIDRs from list items.
func looksLikeNumber(s string) bool {
	_, err := strconv.ParseInt(s, 10, 64)
	return err == nil
}

func isHex(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

func hexByte(hi, lo byte) byte {
	return hexNibble(hi)<<4 | hexNibble(lo)
}

func hexNibble(b byte) byte {
	switch {
	case b >= '0' && b <= '9':
		return b - '0'
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10
	}
	return 0
}
