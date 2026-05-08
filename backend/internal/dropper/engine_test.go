package dropper

import (
	"testing"
)

func newEngineWithRules(t *testing.T, rules ...*Rule) *Engine {
	t.Helper()
	store, err := NewRuleStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if err := store.CreateRule(r); err != nil {
			t.Fatalf("CreateRule %s: %v", r.ID, err)
		}
	}
	return NewEngine(store)
}

func TestEngine_ExpressionContains(t *testing.T) {
	e := newEngineWithRules(t, &Rule{
		ID: "r1", ServiceID: "svc-a", Name: "x",
		Type: MatchString, Scope: ScopeBody, Pattern: "pippo",
		Enabled: true, Action: ActionDrop,
	})
	res := e.EvaluateActions(&HTTPRequest{
		ServiceID: "svc-a",
		Body:      []byte(`{"hi":"pippo"}`),
	})
	if !res.ShouldDrop || len(res.DropRules) != 1 {
		t.Fatalf("expected drop, got %+v", res)
	}
	res = e.EvaluateActions(&HTTPRequest{ServiceID: "svc-a", Body: []byte("nope")})
	if res.ShouldDrop {
		t.Fatalf("should not drop, got %+v", res)
	}
}

func TestEngine_ExpressionRegexAndAction(t *testing.T) {
	e := newEngineWithRules(t, &Rule{
		ID: "r-regex", ServiceID: "svc-a", Name: "x",
		Type: MatchRegex, Scope: ScopeURL, Pattern: `^/admin/.*$`,
		Enabled: true, Action: ActionAlert,
	})
	res := e.EvaluateActions(&HTTPRequest{ServiceID: "svc-a", URL: "/admin/login"})
	if res.ShouldDrop {
		t.Fatal("alert rule must not drop")
	}
	if len(res.AlertRules) != 1 {
		t.Fatalf("expected 1 alert rule, got %d", len(res.AlertRules))
	}
}

func TestEngine_ExpressionAndOr(t *testing.T) {
	e := newEngineWithRules(t, &Rule{
		ID:        "r-and",
		ServiceID: "svc-a",
		Name:      "x",
		// Bypass the auto-derivation: the engine should now follow the
		// Expression field directly. The Type/Scope/Pattern below would never
		// match this body alone — only the AND-of-OR expression does.
		Type:       MatchString,
		Scope:      ScopeBody,
		Pattern:    "never",
		Expression: `body contains "pippo" AND (url contains "/api/" OR url contains "/login")`,
		Enabled:    true,
		Action:     ActionDrop,
	})
	// Match: both halves true.
	res := e.EvaluateActions(&HTTPRequest{
		ServiceID: "svc-a",
		Body:      []byte("hello pippo here"),
		URL:       "/api/v1/users",
	})
	if !res.ShouldDrop {
		t.Fatalf("expected drop, got %+v", res)
	}
	// No match: body contains pippo but url is unrelated.
	res = e.EvaluateActions(&HTTPRequest{
		ServiceID: "svc-a",
		Body:      []byte("pippo"),
		URL:       "/healthz",
	})
	if res.ShouldDrop {
		t.Fatalf("should not drop, got %+v", res)
	}
}

func TestEngine_AhoCorasickBatching(t *testing.T) {
	// Five rules each with a literal contains predicate on body. Confirm all
	// fire from a body that matches all five at once.
	rules := []*Rule{
		{ID: "r1", ServiceID: "svc-x", Name: "a", Type: MatchString, Scope: ScopeBody, Pattern: "alpha", Enabled: true, Action: ActionAlert},
		{ID: "r2", ServiceID: "svc-x", Name: "b", Type: MatchString, Scope: ScopeBody, Pattern: "beta", Enabled: true, Action: ActionAlert},
		{ID: "r3", ServiceID: "svc-x", Name: "c", Type: MatchString, Scope: ScopeBody, Pattern: "gamma", Enabled: true, Action: ActionAlert},
		{ID: "r4", ServiceID: "svc-x", Name: "d", Type: MatchString, Scope: ScopeBody, Pattern: "delta", Enabled: true, Action: ActionAlert},
		{ID: "r5", ServiceID: "svc-x", Name: "e", Type: MatchString, Scope: ScopeBody, Pattern: "epsilon", Enabled: true, Action: ActionAlert},
	}
	e := newEngineWithRules(t, rules...)
	res := e.EvaluateActions(&HTTPRequest{
		ServiceID: "svc-x",
		Body:      []byte("alpha beta gamma delta epsilon"),
	})
	if len(res.AlertRules) != 5 {
		t.Fatalf("expected 5 alert rules to fire, got %d (%+v)", len(res.AlertRules), res.AlertRules)
	}
	// Disjoint body: only one fires.
	res = e.EvaluateActions(&HTTPRequest{
		ServiceID: "svc-x",
		Body:      []byte("just gamma"),
	})
	if len(res.AlertRules) != 1 || res.AlertRules[0].ID != "r3" {
		t.Fatalf("expected r3 only, got %+v", res.AlertRules)
	}
}

func TestEngine_RecompilesOnRuleChange(t *testing.T) {
	store, err := NewRuleStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateRule(&Rule{
		ID: "r1", ServiceID: "svc-a", Name: "x",
		Type: MatchString, Scope: ScopeBody, Pattern: "first",
		Enabled: true, Action: ActionDrop,
	}); err != nil {
		t.Fatal(err)
	}
	e := NewEngine(store)

	// Initial: matches "first".
	if !e.EvaluateActions(&HTTPRequest{ServiceID: "svc-a", Body: []byte("xfirstx")}).ShouldDrop {
		t.Fatal("first rule should match")
	}
	if e.EvaluateActions(&HTTPRequest{ServiceID: "svc-a", Body: []byte("xsecondx")}).ShouldDrop {
		t.Fatal("second pattern should not match yet")
	}

	// Add a new rule. Engine must pick it up via the version-counter check.
	if err := store.CreateRule(&Rule{
		ID: "r2", ServiceID: "svc-a", Name: "y",
		Type: MatchString, Scope: ScopeBody, Pattern: "second",
		Enabled: true, Action: ActionDrop,
	}); err != nil {
		t.Fatal(err)
	}
	if !e.EvaluateActions(&HTTPRequest{ServiceID: "svc-a", Body: []byte("xsecondx")}).ShouldDrop {
		t.Fatal("recompile didn't pick up the new rule")
	}

	// Disable r1 — engine should stop matching "first".
	r1, _ := store.GetRule("r1")
	r1.Enabled = false
	if err := store.UpdateRule(r1); err != nil {
		t.Fatal(err)
	}
	if e.EvaluateActions(&HTTPRequest{ServiceID: "svc-a", Body: []byte("xfirstx")}).ShouldDrop {
		t.Fatal("disabled rule should not match anymore")
	}
}

func TestEngine_DisabledRulesIgnored(t *testing.T) {
	e := newEngineWithRules(t, &Rule{
		ID: "r1", ServiceID: "svc-a", Name: "x",
		Type: MatchString, Scope: ScopeBody, Pattern: "pippo",
		Enabled: false, Action: ActionDrop,
	})
	if e.EvaluateActions(&HTTPRequest{ServiceID: "svc-a", Body: []byte("pippo")}).ShouldDrop {
		t.Fatal("disabled rule must not match")
	}
}

func TestEngine_ICContainsBatched(t *testing.T) {
	e := newEngineWithRules(t, &Rule{
		ID: "r1", ServiceID: "svc-a", Name: "x",
		// auto-derive sets `body contains "PIPPO"`. Override with icontains.
		Expression: `body icontains "PIPPO"`,
		Enabled:    true, Action: ActionAlert,
	})
	res := e.EvaluateActions(&HTTPRequest{
		ServiceID: "svc-a",
		Body:      []byte("hello pippo world"),
	})
	if len(res.AlertRules) != 1 {
		t.Fatalf("icontains should match case-insensitively; got %+v", res.AlertRules)
	}
}
