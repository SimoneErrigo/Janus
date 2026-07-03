package pyfilter

import (
	"sync"
	"testing"
	"time"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	m := NewManager(Config{DataDir: t.TempDir(), EvalTimeout: 5 * time.Second})
	if !m.available {
		t.Skip("python3 not available on this host")
	}
	t.Cleanup(m.Close)
	return m
}

func TestTestScriptMatchAndReason(t *testing.T) {
	m := newTestManager(t)
	code := `
def match(flow):
    if flow["method"] == "POST" and flow["url"] == "/login":
        return "login attempt"
    return False
`
	flow := Flow{"method": "POST", "url": "/login"}
	matches, scriptErr, err := m.Test("login", code, flow, 1)
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if scriptErr != "" {
		t.Fatalf("unexpected script error: %s", scriptErr)
	}
	if len(matches) != 1 || matches[0].Reason != "login attempt" {
		t.Fatalf("expected one match with reason, got %+v", matches)
	}

	// Non-matching flow.
	matches, _, err = m.Test("login", code, Flow{"method": "GET", "url": "/"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected no match, got %+v", matches)
	}
}

func TestTestScriptCompileError(t *testing.T) {
	m := newTestManager(t)
	_, scriptErr, err := m.Test("broken", "def match(flow)\n  return True", Flow{}, 1)
	if err != nil {
		t.Fatalf("transport error: %v", err)
	}
	if scriptErr == "" {
		t.Fatal("expected a script error for invalid syntax")
	}
}

func TestTestScriptMissingMatch(t *testing.T) {
	m := newTestManager(t)
	_, scriptErr, err := m.Test("nofunc", "x = 1", Flow{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if scriptErr == "" {
		t.Fatal("expected an error when match() is missing")
	}
}

func TestLiveStatefulCounting(t *testing.T) {
	m := newTestManager(t)
	// Script keeps state across calls: alert on the 2nd+ login for a user.
	code := `
seen = {}
def match(flow):
    if flow.get("url") == "/login":
        u = flow.get("user")
        seen[u] = seen.get(u, 0) + 1
        if seen[u] > 1:
            return "repeat login for %s (#%d)" % (u, seen[u])
    return False
`
	if _, err := m.CreateScript("repeat-login", code, true); err != nil {
		t.Fatalf("CreateScript: %v", err)
	}

	eval := func(user string) []Match {
		return m.Evaluate(Flow{"url": "/login", "user": user})
	}

	if got := eval("alice"); len(got) != 0 {
		t.Fatalf("first login should not match, got %+v", got)
	}
	if got := eval("alice"); len(got) != 1 {
		t.Fatalf("second login should match, got %+v", got)
	}
	if got := eval("bob"); len(got) != 0 {
		t.Fatalf("bob's first login should not match, got %+v", got)
	}
}

func TestSubmitFiresOnMatch(t *testing.T) {
	var mu sync.Mutex
	var got []Match
	done := make(chan struct{}, 1)

	m := NewManager(Config{
		DataDir:     t.TempDir(),
		EvalTimeout: 5 * time.Second,
		OnMatch: func(flow Flow, mt Match) {
			mu.Lock()
			got = append(got, mt)
			mu.Unlock()
			select {
			case done <- struct{}{}:
			default:
			}
		},
	})
	if !m.available {
		t.Skip("python3 not available")
	}
	defer m.Close()

	if _, err := m.CreateScript("big-body", `
def match(flow):
    if len(flow.get("body", "")) > 10:
        return "body too big"
    return False
`, true); err != nil {
		t.Fatal(err)
	}

	m.Submit(Flow{"body": "this body is definitely longer than ten"})

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("OnMatch was not called in time")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0].Reason != "body too big" {
		t.Fatalf("unexpected matches: %+v", got)
	}
}

func TestDisabledScriptNotEvaluated(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.CreateScript("always", `
def match(flow):
    return "always"
`, false); err != nil {
		t.Fatal(err)
	}
	if got := m.Evaluate(Flow{}); len(got) != 0 {
		t.Fatalf("disabled script must not evaluate, got %+v", got)
	}
	// Enable it and it should now match.
	s := m.ListScripts()[0]
	if _, err := m.SetEnabled(s.ID, true); err != nil {
		t.Fatal(err)
	}
	if got := m.Evaluate(Flow{}); len(got) != 1 {
		t.Fatalf("enabled script should match, got %+v", got)
	}
}

func TestScriptsPersistAcrossReload(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(Config{DataDir: dir, EvalTimeout: 5 * time.Second})
	if _, err := m.CreateScript("keep", "def match(flow):\n  return False", true); err != nil {
		t.Fatal(err)
	}
	m.Close()

	m2 := NewManager(Config{DataDir: dir, EvalTimeout: 5 * time.Second})
	defer m2.Close()
	if len(m2.ListScripts()) != 1 {
		t.Fatalf("expected 1 persisted script, got %d", len(m2.ListScripts()))
	}
}

func TestDropDirectivePropagates(t *testing.T) {
	m := newTestManager(t)
	code := `
def match(flow):
    if "alice" in flow.get("body", ""):
        return {"match": True, "reason": "abuse", "drop": 'body contains "alice"'}
    return False
`
	matches, scriptErr, err := m.Test("ban", code, Flow{"body": `{"user":"alice"}`}, 1)
	if err != nil || scriptErr != "" {
		t.Fatalf("test: err=%v scriptErr=%s", err, scriptErr)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %+v", matches)
	}
	if matches[0].Drop != `body contains "alice"` {
		t.Errorf("drop not propagated: %q", matches[0].Drop)
	}
	if matches[0].Reason != "abuse" {
		t.Errorf("reason: %q", matches[0].Reason)
	}

	// A bare drop directive (no explicit match key) still counts as a match.
	matches, _, _ = m.Test("ban2", `
def match(flow):
    return {"drop": 'url contains "/admin"'}
`, Flow{}, 1)
	if len(matches) != 1 || matches[0].Drop != `url contains "/admin"` {
		t.Fatalf("bare drop should match: %+v", matches)
	}
}

func TestTestRepeatExercisesState(t *testing.T) {
	m := newTestManager(t)
	code := `
seen = {}
def match(flow):
    u = flow.get("user")
    seen[u] = seen.get(u, 0) + 1
    if seen[u] > 1:
        return "seen %s x%d" % (u, seen[u])
    return False
`
	// One run: first sighting, no match.
	got, _, err := m.Test("count", code, Flow{"user": "x"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("single run should not match, got %+v", got)
	}
	// Two runs against a fresh worker: the 2nd sighting matches.
	got, _, err = m.Test("count", code, Flow{"user": "x"}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("repeat=2 should match on the 2nd run, got %+v", got)
	}
}
