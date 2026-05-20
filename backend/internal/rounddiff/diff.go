package rounddiff

import "strings"

// DiffOp is one operation in the rendered diff sequence.
type DiffOp struct {
	Op   string `json:"op"`   // "eq", "ins", "del"
	Text string `json:"text"` // already joined with separators
}

// TokenDiff returns the minimal sequence of equal / insert / delete spans
// that turns tokens a into tokens b, using a straightforward LCS table.
// We cap the input size at maxLen tokens per side so a pathological 10k×10k
// pair can't lock up the request. When the cap is hit we degrade gracefully
// to a single delete + insert (still useful, but no inline highlight).
func TokenDiff(a, b []string, maxLen int) []DiffOp {
	if maxLen <= 0 {
		maxLen = 1500
	}
	if len(a) > maxLen || len(b) > maxLen {
		ops := []DiffOp{}
		if len(a) > 0 {
			ops = append(ops, DiffOp{Op: "del", Text: joinTokens(a)})
		}
		if len(b) > 0 {
			ops = append(ops, DiffOp{Op: "ins", Text: joinTokens(b)})
		}
		return ops
	}
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	if len(a) == 0 {
		return []DiffOp{{Op: "ins", Text: joinTokens(b)}}
	}
	if len(b) == 0 {
		return []DiffOp{{Op: "del", Text: joinTokens(a)}}
	}

	// LCS table — sized (len(a)+1) × (len(b)+1).
	rows, cols := len(a)+1, len(b)+1
	lcs := make([]int, rows*cols)
	at := func(i, j int) int { return lcs[i*cols+j] }
	set := func(i, j, v int) { lcs[i*cols+j] = v }

	for i := 1; i < rows; i++ {
		ai := a[i-1]
		for j := 1; j < cols; j++ {
			if ai == b[j-1] {
				set(i, j, at(i-1, j-1)+1)
			} else if at(i-1, j) >= at(i, j-1) {
				set(i, j, at(i-1, j))
			} else {
				set(i, j, at(i, j-1))
			}
		}
	}

	// Backtrack to collect operations in reverse.
	ops := make([]DiffOp, 0, 8)
	i, j := len(a), len(b)
	for i > 0 || j > 0 {
		switch {
		case i > 0 && j > 0 && a[i-1] == b[j-1]:
			ops = appendOp(ops, "eq", a[i-1])
			i--
			j--
		case j > 0 && (i == 0 || at(i, j-1) >= at(i-1, j)):
			ops = appendOp(ops, "ins", b[j-1])
			j--
		default:
			ops = appendOp(ops, "del", a[i-1])
			i--
		}
	}

	// ops is reversed; flip and merge adjacent same-op spans.
	reverseDiffOps(ops)
	return ops
}

// appendOp pushes one more token onto either a new op or the trailing op of
// the same kind. Joining is delayed so we can choose the separator at the
// end without quadratic copying.
func appendOp(ops []DiffOp, kind, tok string) []DiffOp {
	if n := len(ops); n > 0 && ops[n-1].Op == kind {
		if ops[n-1].Text == "" {
			ops[n-1].Text = tok
		} else {
			// Insert a space between word-shaped tokens; symbols hug.
			ops[n-1].Text = ops[n-1].Text + tokenSeparator(ops[n-1].Text, tok) + tok
		}
		return ops
	}
	return append(ops, DiffOp{Op: kind, Text: tok})
}

func reverseDiffOps(ops []DiffOp) {
	for i, j := 0, len(ops)-1; i < j; i, j = i+1, j-1 {
		ops[i], ops[j] = ops[j], ops[i]
	}
}

func joinTokens(toks []string) string {
	var b strings.Builder
	for i, t := range toks {
		if i > 0 {
			b.WriteString(tokenSeparator(toks[i-1], t))
		}
		b.WriteString(t)
	}
	return b.String()
}

// tokenSeparator returns " " when both tokens are word-shaped, "" otherwise
// (so e.g. `"id" "=" "1"` renders as `id=1`, not `id = 1`).
func tokenSeparator(prev, next string) string {
	if isWordToken(prev) && isWordToken(next) {
		return " "
	}
	return ""
}

func isWordToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isWordByte(s[i]) {
			return false
		}
	}
	return true
}
