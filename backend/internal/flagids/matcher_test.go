package flagids

import "testing"

func TestFlagIDMatcherShortBoundaryAndNewestRound(t *testing.T) {
	matcher := BuildMatcher(map[int]map[string][]string{
		7: {"service": {"user5"}},
		8: {"service": {"user5", "user314"}},
	})
	matches := matcher.FindMatches("account=user5&other=user314")
	if len(matches) != 2 {
		t.Fatalf("matches=%v, want two", matches)
	}
	for _, match := range matches {
		if match.Round != 8 {
			t.Fatalf("match %q attributed to round %d, want newest round 8", match.FlagID, match.Round)
		}
	}
	if matcher.ContainsAny("account=user50") {
		t.Fatal("five-byte attack-info must require a word boundary")
	}
}

// a valid CyberChallenge-style flag: 31 uppercase alnum chars + '='
const upperFlag = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345="

func lowerFlag() string {
	b := []byte(upperFlag)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 32
		}
	}
	return string(b)
}

func TestFlagScannerSuffixBaseline(t *testing.T) {
	fs := NewFlagScanner("[A-Z0-9]{31}=", false, false)
	if fs == nil {
		t.Fatal("scanner should not be nil")
	}
	if !fs.MatchString("leak here " + upperFlag + " end") {
		t.Error("uppercase flag should match")
	}
	if fs.MatchString(lowerFlag()) {
		t.Error("lowercase flag should NOT match without case-insensitivity")
	}
	if fs.MatchString("nothing to see") {
		t.Error("non-flag text should not match")
	}
}

func TestFlagScannerCaseInsensitive(t *testing.T) {
	for _, pat := range []string{"[A-Z0-9]{31}=", "(?i)[A-Z0-9]{31}="} {
		ci := pat == "[A-Z0-9]{31}=" // first uses the flag arg, second the inline (?i)
		fs := NewFlagScanner(pat, ci, false)
		if fs == nil {
			t.Fatalf("scanner nil for %q", pat)
		}
		if !fs.MatchString(lowerFlag()) {
			t.Errorf("pattern %q should match lowercase flag", pat)
		}
		if !fs.MatchBytes([]byte(upperFlag)) {
			t.Errorf("pattern %q should still match uppercase flag", pat)
		}
	}
}

func TestFlagScannerURLEncoded(t *testing.T) {
	fs := NewFlagScanner("[A-Z0-9]{31}=", false, true)
	// The '=' suffix is percent-encoded as %3D.
	encoded := upperFlag[:len(upperFlag)-1] + "%3D"
	if !fs.MatchString(encoded) {
		t.Error("URL-encoded '=' suffix should be caught with decode enabled")
	}
	// Whole flag with an encoded char in the middle-ish region still works.
	if !fs.MatchString("q=" + encoded + "&x=1") {
		t.Error("URL-encoded flag inside a query string should match")
	}
	// Without decode, the encoded suffix must NOT match.
	fsNo := NewFlagScanner("[A-Z0-9]{31}=", false, false)
	if fsNo.MatchString(encoded) {
		t.Error("encoded suffix should not match when decode disabled")
	}
}

func TestFlagScannerPrefixCaseInsensitive(t *testing.T) {
	fs := NewFlagScanner("FLAG{[a-f0-9]+}", true, false)
	if fs == nil {
		t.Fatal("prefix scanner nil")
	}
	if !fs.MatchString("xx flag{DEADBEEF} yy") {
		t.Error("case-insensitive prefix + hex content should match")
	}
	if !fs.MatchString("FLAG{deadbeef}") {
		t.Error("canonical prefix should match")
	}
}

func TestLenientPercentDecode(t *testing.T) {
	got, changed := lenientPercentDecode([]byte("a%3Db%ZZc%"))
	if !changed {
		t.Fatal("expected a change")
	}
	// %3D -> '=', %ZZ left as-is, trailing % left as-is.
	if string(got) != "a=b%ZZc%" {
		t.Errorf("got %q", string(got))
	}
	if _, changed := lenientPercentDecode([]byte("no escapes here")); changed {
		t.Error("should report no change")
	}
}
