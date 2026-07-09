package pyfilter

import (
	"bytes"
	"encoding/base64"
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
	got, _ := m.EvaluateBlocking(Flow{"body": "some evil payload"})
	if len(got) != 1 {
		t.Fatalf("block lane should return exactly the blocking filter, got %+v", got)
	}
	if got[0].Script != "inline-ban" || !got[0].Block {
		t.Fatalf("expected inline-ban with Block=true, got %+v", got[0])
	}
	if g, _ := m.EvaluateBlocking(Flow{"body": "harmless"}); len(g) != 0 {
		t.Fatalf("blocking filter must not match harmless body, got %+v", g)
	}

	// The async lane (Evaluate) sees only the non-blocking filter — the blocking
	// one is NOT evaluated here, so its state is never double-counted.
	got = m.Evaluate(Flow{"body": "some evil payload"})
	if len(got) != 1 || got[0].Script != "noisy" {
		t.Fatalf("async lane should return only the non-blocking filter, got %+v", got)
	}
}

func TestBlockingFilterDropsResponse(t *testing.T) {
	m := newTestManager(t)
	// Inline filters run on both directions; a {"drop": True} on a response
	// drops it (the proxy closes the connection before the client sees it).
	if _, err := m.CreateScript("hide-flag", `
def match(flow):
    if flow.is_response and "flag{" in flow.body:
        return {"drop": True, "reason": "flag in response"}
    return False
`, true, true); err != nil {
		t.Fatal(err)
	}
	// A request carrying the same text must NOT match (guards the direction check).
	if got, _ := m.EvaluateBlocking(Flow{"direction": "request", "body": "give me flag{x}"}); len(got) != 0 {
		t.Fatalf("request should not match a response-only filter, got %+v", got)
	}
	got, _ := m.EvaluateBlocking(Flow{"direction": "response", "body": "here is flag{x}"})
	if len(got) != 1 || !got[0].Block {
		t.Fatalf("response with a flag should block, got %+v", got)
	}
}

func TestUtilHelpersAvailable(t *testing.T) {
	m := newTestManager(t)
	// The `util` analysis namespace is injected into every filter. Exercise a
	// few helpers end-to-end so a filter can validate a payload and drop.
	code := `
def match(flow):
    data = flow.json() or {}
    if util.extra_keys(data, ("name", "pw", "url", "file")):   # mass assignment
        return {"drop": True, "reason": "unexpected field"}
    if util.uri_scheme(data.get("url", "")) not in ("", "http", "https"):
        return {"drop": True, "reason": "bad scheme"}
    if data.get("file") and not util.is_base64(data.get("file")):
        return {"drop": True, "reason": "not base64"}
    return False
`
	drops := func(body string) bool {
		mm, se, err := m.Test("u", code, Flow{"body": body}, 1)
		if err != nil || se != "" {
			t.Fatalf("err=%v scriptErr=%s", err, se)
		}
		return len(mm) == 1 && mm[0].Block
	}
	if !drops(`{"name":"a","pw":"b","friends":["victim"]}`) {
		t.Error("mass-assignment should drop")
	}
	if !drops(`{"name":"a","pw":"b","url":"telnet://db:27017"}`) {
		t.Error("dangerous scheme should drop")
	}
	if !drops(`{"name":"a","pw":"b","file":"not base64!!"}`) {
		t.Error("non-base64 file should drop")
	}
	if drops(`{"name":"a","pw":"b","url":"https://ok","file":"YWJj"}`) {
		t.Error("clean request must NOT drop (checker false positive)")
	}
}

func TestUtilQRAndFilePayload(t *testing.T) {
	m := newTestManager(t)
	// A filter that decodes an uploaded image (incl. a QR code) and drops it when
	// a known attack signature is smuggled inside. Modelled on the real "SQLi
	// hidden in a QR PNG" upload challenge.
	code := `
def match(flow):
    hit = util.find_payload(flow.content, qr=True)
    if hit:
        return {"drop": True, "reason": hit["category"] + ":" + hit["label"]}
    return False
`
	// QR PNG (version 2) encoding "' OR '1'='1' -- " — the payload lives in the QR
	// modules, so raw byte scanning can't see it; it must be decoded.
	sqliQR := "iVBORw0KGgoAAAANSUhEUgAAADoAAAA6AQAAAADJwHeFAAAAoUlEQVR42oWRsQpDMQhFQ10D+RXBNZBfF1wD/RXhrgH7SinoG9oMIZzhXL1p8Tnafjy8TaNG+mjfgxCKhUxoibEUwk/cyRqVxDQUjzcRKVkReI+SyFE5ys/sgW3z7DmH2ShnnY4eWs19+8rEeVO3nOWbdXDZVEwOjUymjGvuYnYBRtlrsvCtQwVqh4Lrro1ddrr13FE9PGNQzepkKPP8/eUXjDapUBwIFWcAAAAASUVORK5CYII="
	// A benign QR ("order-4815162342") — the checker's legitimate upload.
	benignQR := "iVBORw0KGgoAAAANSUhEUgAAADoAAAA6AQAAAADJwHeFAAAAnklEQVR42oVRMQoDMQwz9VrIVwxaA/56wOtBvmLIGnAPSunphtaDCUKOZFnqXUN+PFJsQHQ85FOrsJqvK6JmMBACaTfE9MapLpP+SQFYqyq7nza+yEaDm9LUUd7iOuUuqcQZoTGJI12rXdX3qcPIEvQirT0P9yDO02Ey2TNWBjk0CwTvnpGT80Eqp+pnc+aUJWdoC8ckrR4YtOn/K78AfHmnXjvychoAAAAASUVORK5CYII="

	drops := func(b64 string) bool {
		mm, se, err := m.Test("qr", code, Flow{"body_b64": b64}, 1)
		if err != nil || se != "" {
			t.Fatalf("err=%v scriptErr=%s", err, se)
		}
		return len(mm) == 1 && mm[0].Block
	}
	if !drops(sqliQR) {
		t.Error("QR carrying an SQL injection must be decoded and dropped")
	}
	if drops(benignQR) {
		t.Error("benign QR must NOT drop (checker false positive)")
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
	if len(steps[0].Matches) != 0 {
		t.Fatalf("request step should not match, got %+v", steps[0])
	}
	if len(steps[1].Matches) != 1 || steps[1].Matches[0].Reason != "resp for /pay (seen 2 msgs)" {
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
	if len(steps[3].Matches) != 1 || steps[3].Matches[0].Reason != "recent ok" {
		t.Fatalf("recent(3) at last step wrong: %+v", steps[3])
	}
}

func TestFlowRewriteBody(t *testing.T) {
	m := newTestManager(t)
	code := `
def match(flow):
    if "foo" in flow.body:
        flow.body = flow.body.replace("foo", "BAR")   # inline rewrite
        return "rewrote"
    return False
`
	steps, scriptErr, err := m.TestSequence("rw", code,
		[]Flow{{"service": "w", "direction": "request", "body": "a foo b"}}, 1)
	if err != nil || scriptErr != "" {
		t.Fatalf("err=%v scriptErr=%s", err, scriptErr)
	}
	if len(steps) != 1 || string(steps[0].Rewrite) != "a BAR b" {
		t.Fatalf("expected rewrite 'a BAR b', got %q (matches %+v)", string(steps[0].Rewrite), steps[0].Matches)
	}
}

func TestFlowRewriteTCPBytes(t *testing.T) {
	m := newTestManager(t)
	// Exact bytes (incl. non-UTF8) survive via base64.
	code := `
def match(flow):
    msg = flow.messages[-1]
    if b"foo" in msg.content:
        msg.content = msg.content.replace(b"foo", b"BARBAR")
        return "tcp rewrite"
    return False
`
	raw := append([]byte{0x00, 0x01}, append([]byte("foo"), 0xff)...)
	steps, _, err := m.TestSequence("tcprw", code,
		[]Flow{{"service": "t", "direction": "request", "body_b64": base64.StdEncoding.EncodeToString(raw)}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte{0x00, 0x01}, append([]byte("BARBAR"), 0xff)...)
	if !bytes.Equal(steps[0].Rewrite, want) {
		t.Fatalf("tcp rewrite bytes wrong: got %v want %v", steps[0].Rewrite, want)
	}
}

func TestFlowStreamConnAndLines(t *testing.T) {
	m := newTestManager(t)
	// flow.lines reassembles across chunk boundaries; flow.conn persists per
	// connection — no manual buffer / state dict.
	code := `
def match(flow):
    for line in flow.lines:
        flow.conn["n"] = flow.conn.get("n", 0) + 1
        if line == b"boom":
            return "line %d is boom" % flow.conn["n"]
    return False
`
	chunk := func(s string) Flow {
		return Flow{"service": "s", "direction": "request", "src": "1.2.3.4", "sport": 55,
			"body_b64": base64.StdEncoding.EncodeToString([]byte(s))}
	}
	// "hello" and "world" complete on earlier chunks; "boom" on the last.
	flows := []Flow{chunk("he"), chunk("llo\nwor"), chunk("ld\nbo"), chunk("om\n")}
	steps, scriptErr, err := m.TestSequence("stream", code, flows, 1)
	if err != nil || scriptErr != "" {
		t.Fatalf("err=%v scriptErr=%s", err, scriptErr)
	}
	if len(steps[0].Matches) != 0 || len(steps[1].Matches) != 0 {
		t.Fatalf("no line should complete/emit on the first two chunks: %+v", steps[:2])
	}
	if len(steps[3].Matches) != 1 || steps[3].Matches[0].Reason != "line 3 is boom" {
		t.Fatalf("stream reassembly/conn state wrong: %+v", steps[3])
	}
}

func TestFlowCommandsParsing(t *testing.T) {
	m := newTestManager(t)
	// flow.commands() turns a line stream into CLI commands (args + flag-id),
	// reassembled across packets — no hand-written state machine.
	code := `
CMDS = {b"1": ("register", 2), b"2": ("login", 2)}
def match(flow):
    for cmd in flow.commands(CMDS):
        if cmd.name == "register":
            flow.conn.setdefault("regs", set()).add(cmd.args[1])
        elif cmd.name == "login" and cmd.flagid and cmd.args[1] in flow.conn.get("regs", set()):
            return "kill %s/%s" % (cmd.args[0].decode(), cmd.args[1].decode())
    return False
`
	pkt := func(s string, flag bool) Flow {
		f := Flow{"service": "s", "direction": "request", "src": "1.2.3.4", "sport": 9,
			"body_b64": base64.StdEncoding.EncodeToString([]byte(s))}
		if flag {
			f["contains_flagid"] = true
		}
		return f
	}
	// register alice/secret, then login FLAG/secret (username carries a flag id)
	flows := []Flow{
		pkt("1\n", false), pkt("alice\n", false), pkt("secret\n", false),
		pkt("2\n", false), pkt("FLAG\n", true), pkt("secret\n", false),
	}
	steps, scriptErr, err := m.TestSequence("cmds", code, flows, 1)
	if err != nil || scriptErr != "" {
		t.Fatalf("err=%v scriptErr=%s", err, scriptErr)
	}
	if len(steps[5].Matches) != 1 || steps[5].Matches[0].Reason != "kill FLAG/secret" {
		t.Fatalf("commands() correlation wrong: %+v", steps[5])
	}
}

func TestFlowCommandsNamedFields(t *testing.T) {
	m := newTestManager(t)
	// A spec can name a command's arguments; the parsed command then exposes
	// them by name (cmd.user / cmd.pw) so you never unpack a variable-length
	// list. Mixed arities in one table must not crash.
	code := `
CMDS = {b"1": ("register", ("user", "pw")), b"6": ("getvip", ("flight",))}
def match(flow):
    for cmd in flow.commands(CMDS):
        if cmd.name == "register":
            return "reg %s/%s missing=%r" % (cmd.user.decode(), cmd.pw.decode(), cmd.arg(9))
        if cmd.name == "getvip":
            return "vip %s" % cmd.flight.decode()
    return False
`
	pkt := func(s string) Flow {
		return Flow{"service": "s", "direction": "request", "src": "1.2.3.4", "sport": 9,
			"body_b64": base64.StdEncoding.EncodeToString([]byte(s))}
	}
	flows := []Flow{pkt("1\n"), pkt("alice\n"), pkt("secret\n")}
	steps, scriptErr, err := m.TestSequence("named", code, flows, 1)
	if err != nil || scriptErr != "" {
		t.Fatalf("err=%v scriptErr=%s", err, scriptErr)
	}
	if len(steps[2].Matches) != 1 || steps[2].Matches[0].Reason != `reg alice/secret missing=b''` {
		t.Fatalf("named-field access wrong: %+v", steps[2])
	}
}

func TestConnStateIsolatedPerFilter(t *testing.T) {
	m := newTestManager(t)
	// Two filters use the SAME flow.conn key for different things. Per-script
	// namespacing must keep them from clobbering each other.
	if _, err := m.CreateScript("counter", `
def match(flow):
    flow.conn["n"] = flow.conn.get("n", 0) + 1
    return "n=%d" % flow.conn["n"]
`, true, true); err != nil {
		t.Fatal(err)
	}
	if _, err := m.CreateScript("stomper", `
def match(flow):
    flow.conn["n"] = "not-a-number"   # same key, different filter
    return False
`, true, true); err != nil {
		t.Fatal(err)
	}
	f := Flow{"service": "s", "direction": "request", "src": "1.2.3.4", "sport": 9, "body": "x"}
	var last []Match
	for i := 0; i < 3; i++ {
		last, _ = m.EvaluateBlocking(f)
	}
	var reason string
	for _, mm := range last {
		if mm.Script == "counter" {
			reason = mm.Reason
		}
	}
	if reason != "n=3" {
		t.Fatalf("counter should be isolated from stomper, got reason %q", reason)
	}
}

func TestDirectionConstantSkipsOtherSide(t *testing.T) {
	m := newTestManager(t)
	// A module-level DIRECTION lets a script declare its side; the other
	// direction is skipped entirely (no need to guard it in match()).
	code := `
DIRECTION = "response"
def match(flow):
    return "ran"
`
	if got, _, err := m.Test("resp-only", code, Flow{"direction": "request", "body": "x"}, 1); err != nil {
		t.Fatal(err)
	} else if len(got) != 0 {
		t.Fatalf("request should be skipped for a response-only filter, got %+v", got)
	}
	if got, _, err := m.Test("resp-only", code, Flow{"direction": "response", "body": "x"}, 1); err != nil {
		t.Fatal(err)
	} else if len(got) != 1 {
		t.Fatalf("response should run, got %+v", got)
	}
}

func TestFlowCommandsMultiFilterIsolation(t *testing.T) {
	m := newTestManager(t)
	// Two blocking filters parse the same stream with DIFFERENT command tables.
	// The per-message command cache must be keyed by the spec, otherwise the
	// filter that runs first clobbers the parse seen by the second one.
	if _, err := m.CreateScript("only-login", `
CMDS = {b"1": ("register", 2), b"2": ("login", 2)}
def match(flow):
    for cmd in flow.commands(CMDS):
        pass
    return False
`, true, true); err != nil {
		t.Fatal(err)
	}
	if _, err := m.CreateScript("with-getvip", `
CMDS = {b"1": ("register", 2), b"2": ("login", 2), b"6": ("getvip", 1)}
def match(flow):
    for cmd in flow.commands(CMDS):
        if cmd.name == "getvip" and cmd.flagid:
            return {"drop": True, "reason": "getvip flagid"}
    return False
`, true, true); err != nil {
		t.Fatal(err)
	}

	pkt := func(s string, flag bool) Flow {
		f := Flow{"service": "s", "direction": "request", "src": "1.2.3.4", "sport": 9,
			"body_b64": base64.StdEncoding.EncodeToString([]byte(s))}
		if flag {
			f["contains_flagid"] = true
		}
		return f
	}
	// register + login (harmless), then getvip with a flag-ID flight number.
	flows := []Flow{
		pkt("1\n", false), pkt("u\n", false), pkt("p\n", false),
		pkt("6\n", false), pkt("FLAGFLIGHT\n", true),
	}
	var last []Match
	for _, f := range flows {
		last, _ = m.EvaluateBlocking(f)
	}
	var found bool
	for _, mm := range last {
		if mm.Script == "with-getvip" && mm.Block {
			found = true
		}
	}
	if !found {
		t.Fatalf("with-getvip filter must still block despite only-login running first, got %+v", last)
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

func TestDropDirectiveBecomesBlock(t *testing.T) {
	m := newTestManager(t)
	// {"drop": ...} asks to drop the current message inline: any truthy value
	// sets Block (there is no separate content-only "future traffic" rule).
	code := `
def match(flow):
    if "alice" in flow.get("body", ""):
        return {"match": True, "reason": "abuse", "drop": True}
    return False
`
	matches, scriptErr, err := m.Test("ban", code, Flow{"body": `{"user":"alice"}`}, 1)
	if err != nil || scriptErr != "" {
		t.Fatalf("test: err=%v scriptErr=%s", err, scriptErr)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %+v", matches)
	}
	if !matches[0].Block {
		t.Errorf("drop:True should set Block, got %+v", matches[0])
	}
	if matches[0].Reason != "abuse" {
		t.Errorf("reason: %q", matches[0].Reason)
	}

	// A bare drop directive (no explicit match key) still counts as a match,
	// and a truthy string value blocks just like True.
	matches, _, _ = m.Test("ban2", `
def match(flow):
    return {"drop": "too many logins"}
`, Flow{}, 1)
	if len(matches) != 1 || !matches[0].Block {
		t.Fatalf("bare truthy drop should match and block: %+v", matches)
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
	if len(steps[0].Matches) != 0 {
		t.Errorf("request step should not match, got %+v", steps[0])
	}
	if len(steps[1].Matches) != 1 {
		t.Fatalf("response step should match, got %+v", steps[1])
	}
	if steps[1].Matches[0].Reason == "" {
		t.Error("expected a reason on the response match")
	}
}
