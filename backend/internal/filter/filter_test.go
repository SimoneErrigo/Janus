package filter

import (
	"strings"
	"testing"
)

// fakePacket is a deterministic PacketView for tests.
type fakePacket struct {
	body, url, method, proto, svc, dir, src, dst string
	status, round, sport, dport                  int
	headers                                      map[string]string
	flagged, hasFlagID, dropped                  bool
	raw                                          []byte
}

func (f *fakePacket) BodyString() string { return f.body }
func (f *fakePacket) BodyBytes() []byte  { return []byte(f.body) }
func (f *fakePacket) URL() string        { return f.url }
func (f *fakePacket) Method() string     { return f.method }
func (f *fakePacket) Status() int        { return f.status }
func (f *fakePacket) Round() int         { return f.round }
func (f *fakePacket) Protocol() string   { return f.proto }
func (f *fakePacket) ServiceID() string  { return f.svc }
func (f *fakePacket) Direction() string  { return f.dir }
func (f *fakePacket) SrcIP() string      { return f.src }
func (f *fakePacket) DstIP() string      { return f.dst }
func (f *fakePacket) PeerIP() string {
	if f.dir == "request" {
		return f.src
	}
	return f.dst
}
func (f *fakePacket) SrcPort() int { return f.sport }
func (f *fakePacket) DstPort() int { return f.dport }
func (f *fakePacket) Header(name string) string {
	if f.headers == nil {
		return ""
	}
	// case-insensitive
	for k, v := range f.headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}
func (f *fakePacket) HeadersText() string {
	var b strings.Builder
	for k, v := range f.headers {
		b.WriteString(k)
		b.WriteString(": ")
		b.WriteString(v)
		b.WriteByte('\n')
	}
	return b.String()
}
func (f *fakePacket) RawBytes() []byte     { return f.raw }
func (f *fakePacket) Flagged() bool        { return f.flagged }
func (f *fakePacket) ContainsFlagID() bool { return f.hasFlagID }
func (f *fakePacket) Dropped() bool        { return f.dropped }

func basePacket() *fakePacket {
	return &fakePacket{
		body:    `{"user":"pippo","note":"asdrubale"}`,
		url:     "/api/admin/login",
		method:  "POST",
		proto:   "https",
		svc:     "checker",
		dir:     "request",
		src:     "10.0.5.7",
		dst:     "10.0.0.1",
		status:  200,
		round:   7,
		sport:   54321,
		dport:   8080,
		headers: map[string]string{"User-Agent": "curl/7.0", "Authorization": "Bearer abc123", "X-Test": "pluto"},
		raw:     []byte("\x00\x01\x02FLAGZ"),
	}
}

func mustEval(t *testing.T, src string, p PacketView) bool {
	t.Helper()
	fn, err := Compile(src)
	if err != nil {
		t.Fatalf("compile %q: %v", src, err)
	}
	return fn(p)
}

func TestParse_Empty(t *testing.T) {
	ast, err := Parse("   ")
	if err != nil {
		t.Fatal(err)
	}
	if ast != nil {
		t.Fatalf("expected nil AST for empty source, got %#v", ast)
	}
	fn, err := CompileEval(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !fn(basePacket()) {
		t.Fatal("nil expression should match all")
	}
}

func TestPredicate_BasicOps(t *testing.T) {
	p := basePacket()
	cases := []struct {
		expr string
		want bool
	}{
		{`body contains "pippo"`, true},
		{`body contains "absent"`, false},
		{`body icontains "PIPPO"`, true},
		{`url startswith "/api/"`, true},
		{`url endswith "/login"`, true},
		{`url matches "^/api/.*/login$"`, true},
		{`method == "POST"`, true},
		{`method != "GET"`, true},
		{`status == 200`, true},
		{`status >= 200`, true},
		{`status < 300`, true},
		{`status > 999`, false},
		{`round == 7`, true},
		{`round in (6, 7, 8)`, true},
		{`round < 7`, false},
		{`proto == "https"`, true},
		{`service == "checker"`, true},
		{`direction == "request"`, true},
		{`src == "10.0.5.7"`, true},
		{`peer == "10.0.5.7"`, true},
		{`sport > 1000`, true},
		{`dport == 8080`, true},
		{`flagged`, false},
		{`flagged == false`, true},
		{`NOT flagged`, true},
		{`dropped == false`, true},
	}
	for _, c := range cases {
		got := mustEval(t, c.expr, p)
		if got != c.want {
			t.Errorf("%q -> %v, want %v", c.expr, got, c.want)
		}
	}
}

func TestPredicate_Header(t *testing.T) {
	p := basePacket()
	cases := []struct {
		expr string
		want bool
	}{
		{`header.User-Agent contains "curl"`, true},
		{`header.user-agent contains "curl"`, true}, // case-insensitive lookup
		{`header.Authorization startswith "Bearer "`, true},
		{`header.Missing == ""`, true},
		{`header contains "pluto"`, true}, // headers flat text
		{`header matches "User-Agent: curl/.*"`, true},
	}
	for _, c := range cases {
		got := mustEval(t, c.expr, p)
		if got != c.want {
			t.Errorf("%q -> %v, want %v", c.expr, got, c.want)
		}
	}
}

func TestPredicate_In(t *testing.T) {
	p := basePacket()
	cases := []struct {
		expr string
		want bool
	}{
		{`method in ("GET","POST","PUT")`, true},
		{`method in ("GET")`, false},
		{`status in (200, 404)`, true},
		{`status in (404, 500)`, false},
		{`src in (10.0.0.0/8)`, true},
		{`src in (192.168.0.0/16, 172.16.0.0/12)`, false},
		{`src in (10.0.0.0/8, 192.168.0.0/16)`, true},
		{`src in ("10.0.5.7")`, true},
	}
	for _, c := range cases {
		got := mustEval(t, c.expr, p)
		if got != c.want {
			t.Errorf("%q -> %v, want %v", c.expr, got, c.want)
		}
	}
}

func TestPredicate_CIDR_Eq(t *testing.T) {
	p := basePacket()
	if !mustEval(t, `src == "10.0.0.0/8"`, p) {
		t.Error("CIDR eq match failed")
	}
	if mustEval(t, `src == "192.168.0.0/16"`, p) {
		t.Error("CIDR eq false positive")
	}
}

func TestLogical_Precedence(t *testing.T) {
	p := basePacket()

	// AND binds tighter than OR.
	// false OR (true AND true) = true
	if !mustEval(t, `method == "GET" OR (body contains "pippo" AND url startswith "/api/")`, p) {
		t.Error("precedence 1")
	}

	// (false OR true) AND false = false
	if mustEval(t, `(method == "GET" OR body contains "pippo") AND status == 999`, p) {
		t.Error("precedence 2")
	}

	// NOT applies tightly: NOT a AND b == (NOT a) AND b
	if !mustEval(t, `NOT method == "GET" AND status == 200`, p) {
		t.Error("NOT-AND precedence")
	}

	// short-circuit OR with bad regex behind: should not be reached during eval
	// (still must compile though, since compile-time happens before eval)
	if !mustEval(t, `body contains "pippo" OR url matches ".*"`, p) {
		t.Error("short-circuit OR")
	}
}

func TestLogical_Symbols(t *testing.T) {
	p := basePacket()
	cases := map[string]bool{
		`body contains "pippo" && method == "POST"`: true,
		`method == "GET" || method == "POST"`:       true,
		`!flagged`:                                  true,
		`~ flagged`:                                 true,
		`!(method == "GET")`:                        true,
	}
	for expr, want := range cases {
		got := mustEval(t, expr, p)
		if got != want {
			t.Errorf("%q -> %v, want %v", expr, got, want)
		}
	}
}

func TestComplex_UserExample(t *testing.T) {
	// The original user request:
	//   (body contains "pippo" AND header does not contain "asdrubale")
	//   OR (header contains "pluto" or header contains "pippo")
	p := basePacket()
	expr := `(body contains "pippo" AND NOT header contains "asdrubale")
	          OR (header contains "pluto" OR header contains "pippo")`
	if !mustEval(t, expr, p) {
		t.Fatal("complex user expression should match base packet")
	}
}

func TestParse_Errors(t *testing.T) {
	cases := []string{
		`body contains`,                 // missing value
		`body weird "x"`,                // unknown op (parsed as ident? -- ensures error path)
		`(body contains "x"`,            // unbalanced paren
		`body contains "unterminated`,   // unterminated string
		`status > "abc"`,                // type mismatch
		`body > 5`,                      // numeric op on string field
		`unknown_field == "x"`,          // unknown field
		`body matches "(invalid regex"`, // invalid regex
	}
	for _, src := range cases {
		_, err := Compile(src)
		if err == nil {
			t.Errorf("expected error for %q, got nil", src)
		}
	}
}

func TestNot_Negation(t *testing.T) {
	p := basePacket()
	if !mustEval(t, `NOT body contains "absent"`, p) {
		t.Error("NOT-contains")
	}
	if mustEval(t, `NOT body contains "pippo"`, p) {
		t.Error("NOT-contains negative")
	}
	if !mustEval(t, `!(body contains "absent")`, p) {
		t.Error("!() form")
	}
}

func TestBoolFieldShortcut(t *testing.T) {
	p := basePacket()
	p.flagged = true
	if !mustEval(t, `flagged`, p) {
		t.Error("bare flagged true")
	}
	if !mustEval(t, `flagged AND NOT dropped`, p) {
		t.Error("bare flagged AND NOT dropped")
	}
}

func TestRaw_Bytes(t *testing.T) {
	p := basePacket()
	if !mustEval(t, `raw contains "FLAGZ"`, p) {
		t.Error("raw contains")
	}
	if mustEval(t, `raw contains "absent"`, p) {
		t.Error("raw contains negative")
	}
}
