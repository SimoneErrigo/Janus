package dropper

import (
	"fmt"
	"testing"
)

// BenchmarkEvaluateActions_ManyContains exercises the Aho-Corasick batching
// path: many literal contains rules over a non-trivial body.
func BenchmarkEvaluateActions_ManyContains(b *testing.B) {
	const ruleCount = 30
	store, err := NewRuleStore(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < ruleCount; i++ {
		err := store.CreateRule(&Rule{
			ID:        fmt.Sprintf("r%02d", i),
			ServiceID: "svc",
			Name:      fmt.Sprintf("rule%d", i),
			Type:      MatchString,
			Scope:     ScopeBody,
			Pattern:   fmt.Sprintf("needle-%02d-marker", i),
			Enabled:   true,
			Action:    ActionAlert,
		})
		if err != nil {
			b.Fatal(err)
		}
	}
	engine := NewEngine(store)

	body := make([]byte, 0, 8192)
	body = append(body, []byte("prefix junk noise blah blah ")...)
	for i := 0; i < 200; i++ {
		body = append(body, []byte("padding-XYZ ")...)
	}
	body = append(body, []byte("needle-15-marker")...) // exactly one rule fires
	for i := 0; i < 200; i++ {
		body = append(body, []byte("more-padding ")...)
	}

	req := &HTTPRequest{ServiceID: "svc", Body: body}

	// Warm the bundle compile.
	_ = engine.EvaluateActions(req)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.EvaluateActions(req)
	}
}
