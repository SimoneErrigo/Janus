package rounddiff

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// VisualTokenize keeps the original text intact while splitting it into
// reasonably stable diff units: word runs, whitespace runs, and punctuation.
// Unlike Tokenize, it does not lowercase or normalize IDs; this is for display.
func VisualTokenize(s string) []string {
	if s == "" {
		return nil
	}
	tokens := make([]string, 0, len(s)/4)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		kind := visualKind(r)
		j := i + size
		if kind == visualSymbol {
			tokens = append(tokens, s[i:j])
			i = j
			continue
		}
		for j < len(s) {
			next, nextSize := utf8.DecodeRuneInString(s[j:])
			if visualKind(next) != kind || kind == visualSymbol {
				break
			}
			j += nextSize
		}
		tokens = append(tokens, s[i:j])
		i = j
	}
	return tokens
}

type visualTokenKind int

const (
	visualWord visualTokenKind = iota
	visualSpace
	visualSymbol
)

func visualKind(r rune) visualTokenKind {
	if unicode.IsSpace(r) {
		return visualSpace
	}
	if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
		return visualWord
	}
	return visualSymbol
}

// TextDiff returns an exact visual diff. It preserves case, numbers, and
// whitespace so the UI can highlight the actual captured packet contents.
func TextDiff(a, b string, maxLen int) []DiffOp {
	if maxLen <= 0 {
		maxLen = 1500
	}
	at, bt := VisualTokenize(a), VisualTokenize(b)
	if len(at) > maxLen || len(bt) > maxLen {
		ops := []DiffOp{}
		if len(at) > 0 {
			ops = append(ops, DiffOp{Op: "del", Text: strings.Join(at, "")})
		}
		if len(bt) > 0 {
			ops = append(ops, DiffOp{Op: "ins", Text: strings.Join(bt, "")})
		}
		return ops
	}
	if len(at) == 0 && len(bt) == 0 {
		return nil
	}
	if len(at) == 0 {
		return []DiffOp{{Op: "ins", Text: strings.Join(bt, "")}}
	}
	if len(bt) == 0 {
		return []DiffOp{{Op: "del", Text: strings.Join(at, "")}}
	}

	rows, cols := len(at)+1, len(bt)+1
	lcs := make([]int, rows*cols)
	cell := func(i, j int) int { return lcs[i*cols+j] }
	set := func(i, j, v int) { lcs[i*cols+j] = v }

	for i := 1; i < rows; i++ {
		ai := at[i-1]
		for j := 1; j < cols; j++ {
			if ai == bt[j-1] {
				set(i, j, cell(i-1, j-1)+1)
			} else if cell(i-1, j) >= cell(i, j-1) {
				set(i, j, cell(i-1, j))
			} else {
				set(i, j, cell(i, j-1))
			}
		}
	}

	ops := make([]DiffOp, 0, 8)
	i, j := len(at), len(bt)
	for i > 0 || j > 0 {
		switch {
		case i > 0 && j > 0 && at[i-1] == bt[j-1]:
			ops = appendRawOp(ops, "eq", at[i-1])
			i--
			j--
		case j > 0 && (i == 0 || cell(i, j-1) >= cell(i-1, j)):
			ops = appendRawOp(ops, "ins", bt[j-1])
			j--
		default:
			ops = appendRawOp(ops, "del", at[i-1])
			i--
		}
	}
	reverseDiffOps(ops)
	return ops
}

func appendRawOp(ops []DiffOp, kind, tok string) []DiffOp {
	if n := len(ops); n > 0 && ops[n-1].Op == kind {
		ops[n-1].Text = tok + ops[n-1].Text
		return ops
	}
	return append(ops, DiffOp{Op: kind, Text: tok})
}
