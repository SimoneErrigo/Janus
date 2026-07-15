package flagids

import (
	"bytes"
	"regexp"
	"sort"
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
	patterns      []FlagMatch // ordered list matching automaton pattern indices
	ac            ahocorasick.AhoCorasick
	shortPatterns []FlagMatch // five-byte IDs, matched only on word boundaries
	shortAC       ahocorasick.AhoCorasick
	empty         bool
}

// BuildMatcher constructs an Aho-Corasick automaton from round-aware flagId data.
// roundFlags: roundNum -> serviceName -> []flagIdValue
func BuildMatcher(roundFlags map[int]map[string][]string) *Matcher {
	m := &Matcher{}
	seen := make(map[string]struct{})
	var values, shortValues []string
	rounds := make([]int, 0, len(roundFlags))
	for round := range roundFlags {
		rounds = append(rounds, round)
	}
	// A repeated value belongs to the newest retained round. Sorting rounds and
	// service names also makes matcher metadata stable across process restarts.
	sort.Sort(sort.Reverse(sort.IntSlice(rounds)))
	for _, round := range rounds {
		services := roundFlags[round]
		names := make([]string, 0, len(services))
		for name := range services {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			for _, value := range services[name] {
				if len(value) < 5 {
					continue
				}
				if _, exists := seen[value]; exists {
					continue
				}
				seen[value] = struct{}{}
				match := FlagMatch{FlagID: value, Round: round}
				if len(value) == 5 {
					m.shortPatterns = append(m.shortPatterns, match)
					shortValues = append(shortValues, value)
				} else {
					m.patterns = append(m.patterns, match)
					values = append(values, value)
				}
			}
		}
	}

	if len(values) == 0 && len(shortValues) == 0 {
		m.empty = true
		return m
	}
	if len(values) > 0 {
		m.ac = buildFlagIDAutomaton(values, false)
	}
	if len(shortValues) > 0 {
		m.shortAC = buildFlagIDAutomaton(shortValues, true)
	}
	return m
}

func buildFlagIDAutomaton(values []string, wholeWords bool) ahocorasick.AhoCorasick {
	builder := ahocorasick.NewAhoCorasickBuilder(ahocorasick.Opts{
		AsciiCaseInsensitive: false,
		MatchOnlyWholeWords:  wholeWords,
		MatchKind:            ahocorasick.StandardMatch,
		DFA:                  true,
	})
	return builder.Build(values)
}

// FindMatches returns all flag IDs found in the text, deduplicated.
func (m *Matcher) FindMatches(text string) []FlagMatch {
	if m == nil || m.empty {
		return nil
	}
	seen := make(map[string]struct{})
	var result []FlagMatch
	if len(m.patterns) > 0 {
		appendFlagIDMatches(&result, seen, m.ac.FindAll(text), m.patterns)
	}
	if len(m.shortPatterns) > 0 {
		appendFlagIDMatches(&result, seen, m.shortAC.FindAll(text), m.shortPatterns)
	}
	return result
}

func appendFlagIDMatches(result *[]FlagMatch, seen map[string]struct{}, hits []ahocorasick.Match, patterns []FlagMatch) {
	for _, hit := range hits {
		match := patterns[hit.Pattern()]
		if _, ok := seen[match.FlagID]; ok {
			continue
		}
		seen[match.FlagID] = struct{}{}
		*result = append(*result, match)
	}
}

// ContainsAny returns true if the text contains any flagId pattern.
func (m *Matcher) ContainsAny(text string) bool {
	if m == nil || m.empty {
		return false
	}
	return (len(m.patterns) > 0 && m.ac.Iter(text).Next() != nil) ||
		(len(m.shortPatterns) > 0 && m.shortAC.Iter(text).Next() != nil)
}

// PatternCount returns the number of patterns in the automaton.
func (m *Matcher) PatternCount() int {
	if m == nil {
		return 0
	}
	return len(m.patterns) + len(m.shortPatterns)
}

// --- Extensible Fast Flag Scanner ---

// FlagScanner provides fast flag detection without regexp overhead.
// Different competition formats get specialized scanners.
type FlagScanner struct {
	// strategy chosen at build time
	scanBytes  func(data []byte) bool
	scanString func(s string) bool
	// fallback regex for unsupported patterns
	regex      *regexp.Regexp
	countRegex *regexp.Regexp
	// decodeURL also scans a percent-decoded copy of the input, so
	// URL-encoded flags are caught even when the raw bytes don't match.
	decodeURL bool
}

// NewFlagScanner creates an optimized scanner based on the flag regex pattern.
// Known patterns get hardware-accelerated byte scanning. Unknown patterns
// fall back to Go's regexp engine.
//
// caseInsensitive matches flags regardless of ASCII case (a leading "(?i)" in
// the pattern implies the same). decodeURL additionally scans a percent-decoded
// copy of the traffic so URL-encoded flags are still detected.
func NewFlagScanner(flagRegex string, caseInsensitive, decodeURL bool) *FlagScanner {
	if flagRegex == "" {
		return nil
	}

	// Honor an inline "(?i)" flag as a case-insensitive request and strip it
	// from the pattern fed to the fast-path parsers (which don't understand
	// regexp flags).
	ci := caseInsensitive
	pat := flagRegex
	if strings.HasPrefix(pat, "(?i)") {
		ci = true
		pat = pat[len("(?i)"):]
	}

	compilePat := pat
	if ci && !strings.HasPrefix(compilePat, "(?i)") {
		compilePat = "(?i)" + compilePat
	}
	countRegex, err := regexp.Compile(compilePat)
	if err != nil {
		return nil
	}
	fs := &FlagScanner{decodeURL: decodeURL, countRegex: countRegex}

	// Try to parse known CTF flag patterns and build optimized scanners
	if spec := parseSuffixPattern(pat, ci); spec != nil {
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

	if prefix, inner := parsePrefixPattern(pat, ci); prefix != "" {
		// Pattern like FLAG{...} or CTF{[a-f0-9]+} or CCIT{.*}
		// Strategy: scan for prefix string, then validate content if inner regex exists
		prefixLower := strings.ToLower(prefix)
		fs.scanBytes = func(data []byte) bool {
			return prefixScanBytes(data, prefix, prefixLower, inner, ci)
		}
		fs.scanString = func(s string) bool {
			return prefixScanString(s, prefix, prefixLower, inner, ci)
		}
		return fs
	}

	// Unknown pattern: fall back to compiled regexp
	fs.regex = countRegex
	fs.scanBytes = func(data []byte) bool { return countRegex.Match(data) }
	fs.scanString = func(s string) bool { return countRegex.MatchString(s) }
	return fs
}

// MatchBytes returns true if data contains a flag.
func (fs *FlagScanner) MatchBytes(data []byte) bool {
	if fs == nil {
		return false
	}
	if fs.scanBytes(data) {
		return true
	}
	if fs.decodeURL {
		if dec, changed := lenientPercentDecode(data); changed {
			return fs.scanBytes(dec)
		}
	}
	return false
}

// MatchString returns true if s contains a flag.
func (fs *FlagScanner) MatchString(s string) bool {
	if fs == nil {
		return false
	}
	if fs.scanString(s) {
		return true
	}
	if fs.decodeURL {
		if dec, changed := lenientPercentDecode([]byte(s)); changed {
			return fs.scanString(string(dec))
		}
	}
	return false
}

// CountBytes returns the number of non-overlapping flag matches. When URL
// decoding is enabled it scans the decoded representation only, so the same raw
// match is never counted twice while encoded flags are still included.
func (fs *FlagScanner) CountBytes(data []byte) int {
	if fs == nil || fs.countRegex == nil || len(data) == 0 {
		return 0
	}
	if fs.decodeURL {
		if decoded, changed := lenientPercentDecode(data); changed {
			data = decoded
		}
	}
	return len(fs.countRegex.FindAll(data, -1))
}

// CountString is the string counterpart of CountBytes.
func (fs *FlagScanner) CountString(value string) int {
	return fs.CountBytes([]byte(value))
}

// lenientPercentDecode decodes "%HH" escapes in-place, leaving any invalid or
// non-escape byte untouched. It returns the decoded bytes and whether any
// escape was actually decoded (so callers can skip a redundant re-scan). Unlike
// net/url it never errors on malformed input, which matters for binary traffic.
func lenientPercentDecode(data []byte) ([]byte, bool) {
	idx := bytes.IndexByte(data, '%')
	if idx < 0 {
		return data, false
	}
	out := make([]byte, 0, len(data))
	out = append(out, data[:idx]...)
	changed := false
	for i := idx; i < len(data); i++ {
		if data[i] == '%' && i+2 < len(data) && isHexByte(data[i+1]) && isHexByte(data[i+2]) {
			out = append(out, hexNib(data[i+1])<<4|hexNib(data[i+2]))
			i += 2
			changed = true
			continue
		}
		out = append(out, data[i])
	}
	return out, changed
}

func isHexByte(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

func hexNib(b byte) byte {
	switch {
	case b >= '0' && b <= '9':
		return b - '0'
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10
	default:
		return b - 'A' + 10
	}
}

// --- Suffix-anchored pattern: [CHARSET]{N}SUFFIX ---

type suffixSpec struct {
	suffix   byte      // the suffix byte to scan for (e.g. '=')
	suffixCI bool      // when true, the suffix byte matches either ASCII case
	length   int       // number of chars before suffix (e.g. 31)
	charSet  [256]bool // allowed characters in the prefix
}

// parseSuffixPattern tries to parse patterns like [A-Z0-9]{31}= into a suffixSpec.
// Supports common CTF formats: [A-Z0-9]{31}=, [a-f0-9]{32}:, etc.
// When ci is set the prefix charset (and a letter suffix) match either ASCII case.
func parseSuffixPattern(pattern string, ci bool) *suffixSpec {
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

	// Case-insensitive: for every allowed letter also allow its counterpart,
	// so [A-Z0-9] matches lowercase hex/base32 flags too.
	suffixCI := false
	if ci {
		for c := byte('A'); c <= 'Z'; c++ {
			if charSet[c] {
				charSet[c+32] = true
			}
		}
		for c := byte('a'); c <= 'z'; c++ {
			if charSet[c] {
				charSet[c-32] = true
			}
		}
		b := suffix[0]
		suffixCI = (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
	}

	return &suffixSpec{
		suffix:   suffix[0],
		suffixCI: suffixCI,
		length:   length,
		charSet:  charSet,
	}
}

// indexSuffix returns the offset of the next suffix byte in data at/after start,
// honoring case-insensitive matching, or -1.
func indexSuffix(data []byte, start int, spec *suffixSpec) int {
	idx := bytes.IndexByte(data[start:], spec.suffix)
	if !spec.suffixCI {
		if idx < 0 {
			return -1
		}
		return start + idx
	}
	alt := caseSwap(spec.suffix)
	idxAlt := bytes.IndexByte(data[start:], alt)
	switch {
	case idx < 0 && idxAlt < 0:
		return -1
	case idx < 0:
		return start + idxAlt
	case idxAlt < 0:
		return start + idx
	default:
		if idx < idxAlt {
			return start + idx
		}
		return start + idxAlt
	}
}

func caseSwap(b byte) byte {
	switch {
	case b >= 'A' && b <= 'Z':
		return b + 32
	case b >= 'a' && b <= 'z':
		return b - 32
	}
	return b
}

func suffixScanBytes(data []byte, spec *suffixSpec) bool {
	start := 0
	for {
		pos := indexSuffix(data, start, spec)
		if pos < 0 {
			return false
		}
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
	return suffixScanBytes([]byte(s), spec)
}

// --- Prefix-anchored pattern: PREFIX{...} ---

// parsePrefixPattern tries to parse patterns like FLAG{.*} or CCIT{[a-f0-9]+}
// Returns the literal prefix (e.g. "FLAG{") and an optional inner regex for content validation.
// When ci is set the inner-content regex is compiled case-insensitively.
func parsePrefixPattern(pattern string, ci bool) (prefix string, inner *regexp.Regexp) {
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
	anchor := "^" + innerStr + "$"
	if ci {
		anchor = "(?i)" + anchor
	}
	re, err := regexp.Compile(anchor)
	if err != nil {
		return "", nil
	}
	return prefix, re
}

// indexPrefix finds the next occurrence of the prefix in data at/after start,
// matching case-insensitively when ci is set (prefixLower must be the
// lowercased prefix in that case). Returns -1 when not found.
func indexPrefix(data []byte, start int, prefix, prefixLower string, ci bool) int {
	if !ci {
		idx := bytes.Index(data[start:], []byte(prefix))
		if idx < 0 {
			return -1
		}
		return start + idx
	}
	pl := []byte(prefixLower)
	for i := start; i+len(pl) <= len(data); i++ {
		match := true
		for j := 0; j < len(pl); j++ {
			if toLowerByte(data[i+j]) != pl[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func toLowerByte(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + 32
	}
	return b
}

func prefixScanBytes(data []byte, prefix, prefixLower string, inner *regexp.Regexp, ci bool) bool {
	start := 0
	for {
		idx := indexPrefix(data, start, prefix, prefixLower, ci)
		if idx < 0 {
			return false
		}
		pos := idx + len(prefix)
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

func prefixScanString(s string, prefix, prefixLower string, inner *regexp.Regexp, ci bool) bool {
	return prefixScanBytes([]byte(s), prefix, prefixLower, inner, ci)
}
