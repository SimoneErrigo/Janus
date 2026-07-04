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

func TestEvaluateBlockingLaneIsolation(t *testing.T) {
	m := newTestManager(t)

	// A blocking filter: {"drop": True} -> Block. Runs only in the block lane.
	if _, err := m.CreateScript("inline-ban", `
def match(flow):
    if "evil" in flow.get("body", ""):
        return {"match": True, "reason": "inline block", "drop": True}
    return False
`, true, true); err != nil {
		t.Fatal(err)
	}
	// A normal (non-blocking) alert filter. Runs only in the async lane.
	if _, err := m.CreateScript("noisy", `
def match(flow):
    return "always"
`, true, false); err != nil {
		t.Fatal(err)
	}

	// The block lane sees only the blocking filter.
	got := m.EvaluateBlocking(Flow{"body": "some evil payload"})
	if len(got) != 1 {
		t.Fatalf("block lane should return exactly the blocking filter, got %+v", got)
	}
	if got[0].Script != "inline-ban" || !got[0].Block {
		t.Fatalf("expected inline-ban with Block=true, got %+v", got[0])
	}
	if got := m.EvaluateBlocking(Flow{"body": "harmless"}); len(got) != 0 {
		t.Fatalf("blocking filter must not match harmless body, got %+v", got)
	}

	// The async lane (Evaluate) sees only the non-blocking filter — the blocking
	// one is NOT evaluated here, so its state is never double-counted.
	got = m.Evaluate(Flow{"body": "some evil payload"})
	if len(got) != 1 || got[0].Script != "noisy" {
		t.Fatalf("async lane should return only the non-blocking filter, got %+v", got)
	}
}

func TestFlowErgonomicAccessors(t *testing.T) {
	m := newTestManager(t)
	code := `
def match(flow):
    if (flow.headers["cookie"] == "session=abc"          # case-insensitive
            and flow.headers["missing"] == ""            # forgiving
            and flow.header("user-agent") == "curl/8"
            and flow.json().get("n") == 3                # parsed body
            and flow.query["id"] == "9"                  # parsed query
            and flow.query.all("x") == ["1", "2"]
            and flow.cookies["session"] == "abc"
            and flow.path == "/api/x"
            and flow.is_request):
        return "ergonomic ok"
    return False
`
	flow := Flow{
		"service": "t", "direction": "request", "method": "POST",
		"url":     "/api/x?id=9&x=1&x=2",
		"headers": map[string]any{"Cookie": "session=abc", "User-Agent": "curl/8"},
		"body":    `{"n":3}`,
	}
	got, scriptErr, err := m.Test("erg", code, flow, 1)
	if err != nil || scriptErr != "" {
		t.Fatalf("Test: err=%v scriptErr=%s", err, scriptErr)
	}
	if len(got) != 1 || got[0].Reason != "ergonomic ok" {
		t.Fatalf("expected ergonomic match, got %+v", got)
	}
}

func TestFlowBackwardCompatDictStyle(t *testing.T) {
	m := newTestManager(t)
	// The classic dict-style API must keep working unchanged.
	code := `
def match(flow):
    if flow.get("method") == "POST" and flow.get("headers", {}).get("User-Agent", "") == "x":
        return "dict-style ok"
    return False
`
	got, _, err := m.Test("compat", code, Flow{"method": "POST", "headers": map[string]any{"User-Agent": "x"}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Reason != "dict-style ok" {
		t.Fatalf("dict-style compat broken, got %+v", got)
	}
}

func TestFlowHistoryAndCorrelation(t *testing.T) {
	m := newTestManager(t)
	// The response step reads the correlated request via history.
	code := `
def match(flow):
    if flow.is_response and flow.request.url == "/pay":
        return "resp for %s (seen %d msgs)" % (flow.request.url, len(flow.messages))
    return False
`
	flows := []Flow{
		{"service": "api", "direction": "request", "method": "POST", "url": "/pay"},
		{"service": "api", "direction": "response", "status": 200},
	}
	steps, scriptErr, err := m.TestSequence("corr", code, flows, 1)
	if err != nil || scriptErr != "" {
		t.Fatalf("TestSequence: err=%v scriptErr=%s", err, scriptErr)
	}
	if len(steps) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(steps))
	}
	if len(steps[0]) != 0 {
		t.Fatalf("request step should not match, got %+v", steps[0])
	}
	if len(steps[1]) != 1 || steps[1][0].Reason != "resp for /pay (seen 2 msgs)" {
		t.Fatalf("response step should correlate the request, got %+v", steps[1])
	}
}

func TestFlowRecentMessages(t *testing.T) {
	m := newTestManager(t)
	code := `
def match(flow):
    urls = [x.url for x in flow.recent(3)]
    if urls == ["/r1", "/r2", "/r3"]:
        return "recent ok"
    return False
`
	flows := []Flow{
		{"service": "s", "direction": "request", "url": "/r0"},
		{"service": "s", "direction": "request", "url": "/r1"},
		{"service": "s", "direction": "request", "url": "/r2"},
		{"service": "s", "direction": "request", "url": "/r3"},
	}
	steps, _, err := m.TestSequence("recent", code, flows, 1)
	if err != nil {
		t.Fatal(err)
	}
	// Only the last step sees /r1,/r2,/r3 as the 3 most recent.
	if len(steps[3]) != 1 || steps[3][0].Reason != "recent ok" {
		t.Fatalf("recent(3) at last step wrong: %+v", steps[3])
	}
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
	if _, err := m.CreateScript("repeat-login", code, true, false); err != nil {
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
`, true, false); err != nil {
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
`, false, false); err != nil {
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
	if _, err := m.CreateScript("keep", "def match(flow):\n  return False", true, false); err != nil {
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

func TestSequenceCorrelatesReqAndRes(t *testing.T) {
	m := newTestManager(t)
	// Remembers the URL seen on the request, and flags the matching response.
	code := `
last = {}
def match(flow):
    if flow.get("direction") == "request":
        last["url"] = flow.get("url")
        return False
    if flow.get("direction") == "response" and last.get("url") == "/login" and flow.get("status") == 500:
        return "login errored (5xx) for %s" % last["url"]
    return False
`
	flows := []Flow{
		{"direction": "request", "url": "/login", "method": "POST"},
		{"direction": "response", "url": "/login", "status": 500},
	}
	steps, scriptErr, err := m.TestSequence("corr", code, flows, 1)
	if err != nil || scriptErr != "" {
		t.Fatalf("err=%v scriptErr=%s", err, scriptErr)
	}
	if len(steps) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(steps))
	}
	if len(steps[0]) != 0 {
		t.Errorf("request step should not match, got %+v", steps[0])
	}
	if len(steps[1]) != 1 {
		t.Fatalf("response step should match, got %+v", steps[1])
	}
	if steps[1][0].Reason == "" {
		t.Error("expected a reason on the response match")
	}
}
