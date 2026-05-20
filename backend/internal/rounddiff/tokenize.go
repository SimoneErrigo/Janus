package rounddiff

import (
	"regexp"
	"strings"
	"unicode"
)

// uuidLikeRE matches canonical UUIDs and similar dash-separated hex blocks
// so we can collapse them to a single `:uuid` token before tokenisation
// splits the dashes apart.
var uuidLikeRE = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

// preTokenize collapses identifier-shaped patterns that the byte-level
// tokenizer would otherwise shred into novel-looking fragments.
func preTokenize(s string) string {
	if s == "" {
		return s
	}
	return uuidLikeRE.ReplaceAllString(s, ":uuid")
}

// Tokenize splits a payload into normalized tokens used both for the
// "novelty" comparison between two rounds and as the unit for the
// representative diff. The rules:
//
//   - Alphanumeric runs are one token, lower-cased (so different casings of
//     "SELECT" collapse to the same novelty signature).
//   - Each ASCII punctuation/symbol character is its own token, except for
//     a handful of multi-char operators that mean something specific in
//     attack payloads: `--`, `||`, `&&`, `==`, `!=`, `>=`, `<=`, `<%`, `%>`,
//     `{{`, `}}`, `${`, `%2e`, `%00`. Keeping these as one token makes the
//     SQLi / SSTI / encoding categories more visible.
//   - Whitespace is a separator and never a token.
//   - UUID-shaped tokens collapse to ":uuid"; long hex collapses to ":hex";
//     pure digits to ":id"; this is the same noise-suppression we apply on
//     the frontend so randomized identifiers don't dominate the multiset.
func Tokenize(s string) []string {
	if s == "" {
		return nil
	}
	s = preTokenize(s)
	tokens := make([]string, 0, len(s)/4)
	i := 0
	n := len(s)
	for i < n {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			i++
			continue
		}
		// Multi-char operator detection — match longest first.
		if i+2 < n {
			tri := s[i : i+3]
			if tri == "%2e" || tri == "%2E" || tri == "%00" {
				tokens = append(tokens, strings.ToLower(tri))
				i += 3
				continue
			}
		}
		if i+1 < n {
			pair := s[i : i+2]
			switch pair {
			case "--", "||", "&&", "==", "!=", ">=", "<=", "<%", "%>", "{{", "}}", "${", "/*", "*/":
				tokens = append(tokens, pair)
				i += 2
				continue
			}
		}
		// Alphanumeric (and underscore) run.
		if isWordByte(c) {
			j := i
			for j < n && isWordByte(s[j]) {
				j++
			}
			tok := strings.ToLower(s[i:j])
			tokens = append(tokens, normalizeWordToken(tok))
			i = j
			continue
		}
		// Any other non-space character is a single-byte symbol token.
		tokens = append(tokens, string(c))
		i++
	}
	return tokens
}

func isWordByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '_'
}

// normalizeWordToken collapses identifier-shaped runs (UUID, long hex, pure
// digits) so that randomized request IDs don't pollute the novelty multiset.
func normalizeWordToken(s string) string {
	if len(s) == 0 {
		return s
	}
	// pure digits
	allDigit := true
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			allDigit = false
			break
		}
	}
	if allDigit {
		return ":id"
	}
	// UUID without hyphens isn't possible (we split on '-'), but pure hex
	// of length 16+ collapses to :hex.
	if len(s) >= 16 {
		allHex := true
		for i := 0; i < len(s); i++ {
			c := s[i]
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				allHex = false
				break
			}
		}
		if allHex {
			return ":hex"
		}
	}
	return s
}

// TokenMultiset counts token occurrences across a set of strings.
type TokenMultiset map[string]int

// Add increments the count for every token in s.
func (m TokenMultiset) Add(s string) {
	for _, t := range Tokenize(s) {
		m[t]++
	}
}

// NoveltyScore counts how many tokens in b were never seen in a, and how many
// total tokens b has. The score is novel/total in [0,1].
// novelTokens contains the distinct novel tokens (capped at maxNovel).
func NoveltyScore(a TokenMultiset, b string, maxNovel int) (score float64, novelTokens []string, total int) {
	toks := Tokenize(b)
	total = len(toks)
	if total == 0 {
		return 0, nil, 0
	}
	seen := make(map[string]struct{}, 16)
	novel := 0
	for _, t := range toks {
		if a[t] == 0 {
			novel++
			if _, dup := seen[t]; !dup {
				seen[t] = struct{}{}
				if len(novelTokens) < maxNovel {
					novelTokens = append(novelTokens, t)
				}
			}
		}
	}
	return float64(novel) / float64(total), novelTokens, total
}

// stripNonPrintable returns a printable preview of s, truncated to maxLen.
func stripNonPrintable(s string, maxLen int) string {
	if maxLen <= 0 {
		maxLen = 300
	}
	var b strings.Builder
	for _, r := range s {
		if r == '\n' || r == '\t' {
			b.WriteByte(' ')
			continue
		}
		if !unicode.IsPrint(r) {
			b.WriteByte('.')
			continue
		}
		b.WriteRune(r)
		if b.Len() >= maxLen {
			b.WriteString("…")
			break
		}
	}
	return b.String()
}
