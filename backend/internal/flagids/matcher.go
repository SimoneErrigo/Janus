package flagids

import (
	"bytes"
	"regexp"
	"strings"

	ahocorasick "github.com/petar-dambovaliev/aho-corasick"
)

// FlagMatch represents a matched flag ID with its round metadata.
type FlagMatch struct {
	FlagID string `json:"flag_id"`
	Round  int    `json:"round"`
}

// Matcher wraps an Aho-Corasick automaton for O(text_length) multi-pattern matching.
type Matcher struct {
	patterns []FlagMatch          // ordered list matching automaton pattern indices
	ac       ahocorasick.AhoCorasick
	empty    bool
	byValue  map[string]int       // flagID value -> index in patterns (for dedup)
}

// BuildMatcher constructs an Aho-Corasick automaton from round-aware flagId data.
// roundFlags: roundNum -> serviceName -> []flagIdValue
func BuildMatcher(roundFlags map[int]map[string][]string) *Matcher {
	m := &Matcher{byValue: make(map[string]int)}

	var values []string
	for round, services := range roundFlags {
		for _, flagIDs := range services {
			for _, v := range flagIDs {
				if len(v) < 6 {
					continue // skip short values to avoid false positives
				}
				if _, exists := m.byValue[v]; exists {
					continue // deduplicate
				}
				m.byValue[v] = len(m.patterns)
				m.patterns = append(m.patterns, FlagMatch{FlagID: v, Round: round})
				values = append(values, v)
			}
		}
	}

	if len(values) == 0 {
		m.empty = true
		return m
	}

	builder := ahocorasick.NewAhoCorasickBuilder(ahocorasick.Opts{
		AsciiCaseInsensitive: false,
		MatchOnlyWholeWords:  false,
		MatchKind:            ahocorasick.StandardMatch,
		DFA:                  true, // DFA is faster for repeated searches
	})
	m.ac = builder.Build(values)
	return m
}

// FindMatches returns all flag IDs found in the text, deduplicated.
func (m *Matcher) FindMatches(text string) []FlagMatch {
	if m == nil || m.empty {
		return nil
	}
	hits := m.ac.FindAll(text)
	if len(hits) == 0 {
		return nil
	}

	seen := make(map[int]struct{}, len(hits))
	var result []FlagMatch
	for _, hit := range hits {
		idx := hit.Pattern()
		if _, ok := seen[idx]; ok {
			continue
		}
		seen[idx] = struct{}{}
		result = append(result, m.patterns[idx])
	}
	return result
}

// ContainsAny returns true if the text contains any flagId pattern.
func (m *Matcher) ContainsAny(text string) bool {
	if m == nil || m.empty {
		return false
	}
	iter := m.ac.Iter(text)
	return iter.Next() != nil
}

// PatternCount returns the number of patterns in the automaton.
func (m *Matcher) PatternCount() int {
	if m == nil {
		return 0
	}
	return len(m.patterns)
}

// --- Extensible Fast Flag Scanner ---

// FlagScanner provides fast flag detection without regexp overhead.
// Different competition formats get specialized scanners.
type FlagScanner struct {
	// strategy chosen at build time
	scanBytes  func(data []byte) bool
	scanString func(s string) bool
	// fallback regex for unsupported patterns
	regex *regexp.Regexp
}

// NewFlagScanner creates an optimized scanner based on the flag regex pattern.
// Known patterns get hardware-accelerated byte scanning. Unknown patterns
// fall back to Go's regexp engine.
func NewFlagScanner(flagRegex string) *FlagScanner {
	if flagRegex == "" {
		return nil
	}

	fs := &FlagScanner{}

	// Try to parse known CTF flag patterns and build optimized scanners
	if spec := parseSuffixPattern(flagRegex); spec != nil {
		// Pattern like [A-Z0-9]{31}= or [a-f0-9]{32}: or [A-Za-z0-9]{24}$
		// Strategy: scan for suffix byte, validate preceding N chars against charset
		fs.scanBytes = func(data []byte) bool {
			return suffixScanBytes(data, spec)
		}
		fs.scanString = func(s string) bool {
			return suffixScanString(s, spec)
		}
		return fs
	}

	if prefix, inner := parsePrefixPattern(flagRegex); prefix != "" {
		// Pattern like FLAG{...} or CTF{[a-f0-9]+} or CCIT{.*}
		// Strategy: scan for prefix string, then validate content if inner regex exists
		fs.scanBytes = func(data []byte) bool {
			return prefixScanBytes(data, prefix, inner)
		}
		fs.scanString = func(s string) bool {
			return prefixScanString(s, prefix, inner)
		}
		return fs
	}

	// Unknown pattern: fall back to compiled regexp
	re, err := regexp.Compile(flagRegex)
	if err != nil {
		return nil
	}
	fs.regex = re
	fs.scanBytes = func(data []byte) bool { return re.Match(data) }
	fs.scanString = func(s string) bool { return re.MatchString(s) }
	return fs
}

// MatchBytes returns true if data contains a flag.
func (fs *FlagScanner) MatchBytes(data []byte) bool {
	if fs == nil {
		return false
	}
	return fs.scanBytes(data)
}

// MatchString returns true if s contains a flag.
func (fs *FlagScanner) MatchString(s string) bool {
	if fs == nil {
		return false
	}
	return fs.scanString(s)
}

// --- Suffix-anchored pattern: [CHARSET]{N}SUFFIX ---

type suffixSpec struct {
	suffix  byte   // the suffix byte to scan for (e.g. '=')
	length  int    // number of chars before suffix (e.g. 31)
	charSet [256]bool // allowed characters in the prefix
}

// parseSuffixPattern tries to parse patterns like [A-Z0-9]{31}= into a suffixSpec.
// Supports common CTF formats: [A-Z0-9]{31}=, [a-f0-9]{32}:, etc.
func parseSuffixPattern(pattern string) *suffixSpec {
	// Must match: [<charset>]{<N>}<single-char-suffix>
	if len(pattern) < 6 || pattern[0] != '[' {
		return nil
	}

	// Find closing bracket
	closeBracket := strings.IndexByte(pattern, ']')
	if closeBracket < 2 {
		return nil
	}

	// Parse character ranges inside brackets
	charsetStr := pattern[1:closeBracket]
	var charSet [256]bool
	i := 0
	for i < len(charsetStr) {
		if i+2 < len(charsetStr) && charsetStr[i+1] == '-' {
			// Range like A-Z
			lo, hi := charsetStr[i], charsetStr[i+2]
			if lo > hi {
				lo, hi = hi, lo
			}
			for c := lo; c <= hi; c++ {
				charSet[c] = true
			}
			i += 3
		} else {
			charSet[charsetStr[i]] = true
			i++
		}
	}

	rest := pattern[closeBracket+1:]

	// Must have {N} quantifier
	if len(rest) < 3 || rest[0] != '{' {
		return nil
	}
	closeBrace := strings.IndexByte(rest, '}')
	if closeBrace < 2 {
		return nil
	}

	// Parse length
	length := 0
	for _, c := range rest[1:closeBrace] {
		if c < '0' || c > '9' {
			return nil
		}
		length = length*10 + int(c-'0')
	}
	if length == 0 {
		return nil
	}

	// Must have exactly 1 char suffix after }
	suffix := rest[closeBrace+1:]
	if len(suffix) != 1 {
		return nil
	}

	return &suffixSpec{
		suffix:  suffix[0],
		length:  length,
		charSet: charSet,
	}
}

func suffixScanBytes(data []byte, spec *suffixSpec) bool {
	start := 0
	for {
		idx := bytes.IndexByte(data[start:], spec.suffix)
		if idx < 0 {
			return false
		}
		pos := start + idx
		if pos >= spec.length {
			valid := true
			for j := pos - spec.length; j < pos; j++ {
				if !spec.charSet[data[j]] {
					valid = false
					break
				}
			}
			if valid {
				return true
			}
		}
		start = pos + 1
	}
}

func suffixScanString(s string, spec *suffixSpec) bool {
	start := 0
	for {
		idx := strings.IndexByte(s[start:], spec.suffix)
		if idx < 0 {
			return false
		}
		pos := start + idx
		if pos >= spec.length {
			valid := true
			for j := pos - spec.length; j < pos; j++ {
				if !spec.charSet[s[j]] {
					valid = false
					break
				}
			}
			if valid {
				return true
			}
		}
		start = pos + 1
	}
}

// --- Prefix-anchored pattern: PREFIX{...} ---

// parsePrefixPattern tries to parse patterns like FLAG{.*} or CCIT{[a-f0-9]+}
// Returns the literal prefix (e.g. "FLAG{") and an optional inner regex for content validation.
func parsePrefixPattern(pattern string) (prefix string, inner *regexp.Regexp) {
	// Look for literal chars followed by {
	braceIdx := -1
	for i, c := range pattern {
		// If we hit a regex metacharacter before {, this isn't a simple prefix pattern
		if strings.ContainsRune(`[]()+*?.\^$|`, c) {
			if c == '{' && i > 0 {
				braceIdx = i
			}
			break
		}
		if c == '{' {
			braceIdx = i
			break
		}
	}
	if braceIdx <= 0 {
		return "", nil
	}

	prefix = pattern[:braceIdx+1] // e.g. "FLAG{"

	// Check for closing }
	if pattern[len(pattern)-1] != '}' {
		return "", nil
	}

	// Inner content regex (between { and })
	innerStr := pattern[braceIdx+1 : len(pattern)-1]
	if innerStr == "" || innerStr == ".*" || innerStr == ".+" {
		// No meaningful validation needed beyond finding the prefix and closing }
		return prefix, nil
	}

	// Try to compile the inner part as a regex for validation
	re, err := regexp.Compile("^" + innerStr + "$")
	if err != nil {
		return "", nil
	}
	return prefix, re
}

func prefixScanBytes(data []byte, prefix string, inner *regexp.Regexp) bool {
	prefixBytes := []byte(prefix)
	start := 0
	for {
		idx := bytes.Index(data[start:], prefixBytes)
		if idx < 0 {
			return false
		}
		pos := start + idx + len(prefixBytes)
		// Find closing }
		closeIdx := bytes.IndexByte(data[pos:], '}')
		if closeIdx >= 0 {
			if inner == nil || inner.Match(data[pos:pos+closeIdx]) {
				return true
			}
		}
		start = pos
	}
}

func prefixScanString(s string, prefix string, inner *regexp.Regexp) bool {
	start := 0
	for {
		idx := strings.Index(s[start:], prefix)
		if idx < 0 {
			return false
		}
		pos := start + idx + len(prefix)
		// Find closing }
		closeIdx := strings.IndexByte(s[pos:], '}')
		if closeIdx >= 0 {
			if inner == nil || inner.MatchString(s[pos:pos+closeIdx]) {
				return true
			}
		}
		start = pos
	}
}
