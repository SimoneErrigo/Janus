package sniffer

import (
	"testing"
	"time"
)

// helper: insert a request+response pair for a single TCP connection.
func insertReqRes(t *testing.T, store *PacketStore, serviceID, sessionID string,
	ts time.Time, srcIP string, srcPort int, dstIP string, dstPort int,
	method, urlPath, reqBody string, status int, resBody string,
) {
	t.Helper()
	if err := store.Insert(&Packet{
		ServiceID: serviceID, SessionID: sessionID, Timestamp: ts,
		SrcIP: srcIP, SrcPort: srcPort, DstIP: dstIP, DstPort: dstPort,
		Protocol: "http", Direction: DirectionRequest,
		Method: method, URL: urlPath, BodyString: reqBody,
		Headers: map[string]string{"Content-Type": "application/json"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Insert(&Packet{
		ServiceID: serviceID, SessionID: sessionID, Timestamp: ts.Add(50 * time.Millisecond),
		SrcIP: dstIP, SrcPort: dstPort, DstIP: srcIP, DstPort: srcPort,
		Protocol: "http", Direction: DirectionResponse,
		Status: status, BodyString: resBody,
	}); err != nil {
		t.Fatal(err)
	}
}

func distinctSessions(pkts []*Packet) map[string]bool {
	m := make(map[string]bool)
	for _, p := range pkts {
		m[p.SessionID] = true
	}
	return m
}

// ---------- SNAT scenario ----------
// All traffic arrives from the cloud router IP (10.254.0.1) due to source NAT.
// Three different "attackers" + checksystem all appear as the same src_ip.
// flowByPeerIP must NOT mix their traffic.

func TestFlowByPeerIP_SNAT(t *testing.T) {
	dir := t.TempDir()
	store, err := NewPacketStore(dir)
	if err != nil {
		t.Fatalf("NewPacketStore: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC().Truncate(time.Second)
	gw := "10.254.0.1" // SNAT gateway — same for everyone
	vm := "10.60.1.1"  // our vulnbox
	svc := "svc-web"

	// Attacker 1: POST /login → GET /admin/flag  (2 TCP connections)
	insertReqRes(t, store, svc, svc+"/"+gw+":40001", now,
		gw, 40001, vm, 8080, "POST", "/login",
		`{"user":"a1","pass":"x"}`, 200, `{"ok":true}`)
	insertReqRes(t, store, svc, svc+"/"+gw+":40002", now.Add(2*time.Second),
		gw, 40002, vm, 8080, "GET", "/admin/flag",
		"", 200, `{"flag":"FLAG{aaa}"}`)

	// Attacker 2: GET /api/users → POST /api/read  (2 TCP connections)
	insertReqRes(t, store, svc, svc+"/"+gw+":40003", now.Add(1*time.Second),
		gw, 40003, vm, 8080, "GET", "/api/users",
		"", 200, `[{"id":1}]`)
	insertReqRes(t, store, svc, svc+"/"+gw+":40004", now.Add(3*time.Second),
		gw, 40004, vm, 8080, "POST", "/api/read",
		`{"id":1}`, 200, `{"flag":"FLAG{bbb}"}`)

	// Attacker 3: PUT /note  (1 TCP connection)
	insertReqRes(t, store, svc, svc+"/"+gw+":40005", now.Add(4*time.Second),
		gw, 40005, vm, 8080, "PUT", "/note",
		`{"text":"pwned"}`, 201, `{"id":42}`)

	// Checksystem: GET /health + GET /check  (2 TCP connections)
	insertReqRes(t, store, svc, svc+"/"+gw+":50001", now.Add(500*time.Millisecond),
		gw, 50001, vm, 8080, "GET", "/health",
		"", 200, `ok`)
	insertReqRes(t, store, svc, svc+"/"+gw+":50002", now.Add(5*time.Second),
		gw, 50002, vm, 8080, "GET", "/check",
		"", 200, `ok`)

	// Total: 7 TCP sessions, 14 packets — ALL from 10.254.0.1

	// ---- Query flow starting from Attacker 1's first request ----
	pkt1 := findPacketByURL(t, store, svc, "/login")
	flow, err := store.QueryFlow(pkt1.ID)
	if err != nil {
		t.Fatalf("QueryFlow: %v", err)
	}

	sessions := distinctSessions(flow)
	t.Logf("SNAT flow: %d packets, %d sessions", len(flow), len(sessions))
	for _, p := range flow {
		t.Logf("  sid=%-25s dir=%-8s method=%-4s url=%s", p.SessionID, p.Direction, p.Method, p.URL)
	}

	// With SNAT, we should get ONLY the single TCP session (2 packets),
	// NOT all 14 packets from all 7 sessions.
	if len(sessions) > 1 {
		t.Errorf("SNAT: expected 1 session, got %d — peer IP correlation mixed different attackers", len(sessions))
	}
	if len(flow) != 2 {
		t.Errorf("SNAT: expected 2 packets (req+res), got %d", len(flow))
	}
}

// ---------- Non-SNAT scenario ----------
// Multiple distinct source IPs — peer IP correlation should still work.

func TestFlowByPeerIP_NonSNAT(t *testing.T) {
	dir := t.TempDir()
	store, err := NewPacketStore(dir)
	if err != nil {
		t.Fatalf("NewPacketStore: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC().Truncate(time.Second)
	vm := "10.60.1.1"
	svc := "svc-web"

	// Attacker from 10.81.2.3: 3-step exploit across 3 TCP connections (no auth tokens)
	insertReqRes(t, store, svc, svc+"/10.81.2.3:41001", now,
		"10.81.2.3", 41001, vm, 8080, "POST", "/register",
		`{"user":"evil"}`, 200, `{"ok":true}`)
	insertReqRes(t, store, svc, svc+"/10.81.2.3:41002", now.Add(1*time.Second),
		"10.81.2.3", 41002, vm, 8080, "GET", "/profile",
		"", 200, `{"user":"evil"}`)
	insertReqRes(t, store, svc, svc+"/10.81.2.3:41003", now.Add(2*time.Second),
		"10.81.2.3", 41003, vm, 8080, "GET", "/flag",
		"", 200, `{"flag":"FLAG{xxx}"}`)

	// Noise: different attacker from 10.81.5.7
	insertReqRes(t, store, svc, svc+"/10.81.5.7:42001", now.Add(3*time.Second),
		"10.81.5.7", 42001, vm, 8080, "GET", "/other",
		"", 200, `nope`)

	// Checksystem from 10.10.0.1
	insertReqRes(t, store, svc, svc+"/10.10.0.1:43001", now.Add(4*time.Second),
		"10.10.0.1", 43001, vm, 8080, "GET", "/health",
		"", 200, `ok`)

	// ---- Query flow starting from attacker's first request ----
	pkt1 := findPacketByURL(t, store, svc, "/register")
	flow, err := store.QueryFlow(pkt1.ID)
	if err != nil {
		t.Fatalf("QueryFlow: %v", err)
	}

	sessions := distinctSessions(flow)
	t.Logf("Non-SNAT flow: %d packets, %d sessions", len(flow), len(sessions))
	for _, p := range flow {
		t.Logf("  sid=%-30s dir=%-8s method=%-4s url=%s src=%s", p.SessionID, p.Direction, p.Method, p.URL, p.SrcIP)
	}

	// Should get all 3 sessions from 10.81.2.3 (6 packets), but NOT noise or checksystem
	if len(sessions) != 3 {
		t.Errorf("Non-SNAT: expected 3 sessions from attacker, got %d", len(sessions))
	}
	if len(flow) != 6 {
		t.Errorf("Non-SNAT: expected 6 packets, got %d", len(flow))
	}

	// Verify no packets from other IPs leaked in
	for _, p := range flow {
		if p.Direction == DirectionRequest && p.SrcIP != "10.81.2.3" {
			t.Errorf("Non-SNAT: unexpected request from %s", p.SrcIP)
		}
	}
}

// ---------- Token correlation still preferred over peer IP ----------

func TestFlowTokenCorrelation_WithSNAT(t *testing.T) {
	dir := t.TempDir()
	store, err := NewPacketStore(dir)
	if err != nil {
		t.Fatalf("NewPacketStore: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC().Truncate(time.Second)
	gw := "10.254.0.1"
	vm := "10.60.1.1"
	svc := "svc-auth"

	// Attacker 1: login → get token → use token in second connection
	if err := store.Insert(&Packet{
		ServiceID: svc, SessionID: svc + "/" + gw + ":40001", Timestamp: now,
		SrcIP: gw, SrcPort: 40001, DstIP: vm, DstPort: 8080,
		Protocol: "http", Direction: DirectionRequest,
		Method: "POST", URL: "/login", BodyString: `{"user":"a1","pass":"x"}`,
		Headers: map[string]string{"Content-Type": "application/json"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Insert(&Packet{
		ServiceID: svc, SessionID: svc + "/" + gw + ":40001", Timestamp: now.Add(50 * time.Millisecond),
		SrcIP: vm, SrcPort: 8080, DstIP: gw, DstPort: 40001,
		Protocol: "http", Direction: DirectionResponse,
		Status: 200, BodyString: `{"token":"SUPERTOKEN_A1_1234567890"}`,
	}); err != nil {
		t.Fatal(err)
	}
	// Second connection using the token
	if err := store.Insert(&Packet{
		ServiceID: svc, SessionID: svc + "/" + gw + ":40002", Timestamp: now.Add(2 * time.Second),
		SrcIP: gw, SrcPort: 40002, DstIP: vm, DstPort: 8080,
		Protocol: "http", Direction: DirectionRequest,
		Method: "GET", URL: "/secret",
		Headers: map[string]string{"Authorization": "Bearer SUPERTOKEN_A1_1234567890"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Insert(&Packet{
		ServiceID: svc, SessionID: svc + "/" + gw + ":40002", Timestamp: now.Add(2*time.Second + 50*time.Millisecond),
		SrcIP: vm, SrcPort: 8080, DstIP: gw, DstPort: 40002,
		Protocol: "http", Direction: DirectionResponse,
		Status: 200, BodyString: `{"flag":"FLAG{token_works}"}`,
	}); err != nil {
		t.Fatal(err)
	}

	// Attacker 2 (different exploit, same gateway IP, no shared token)
	insertReqRes(t, store, svc, svc+"/"+gw+":40003", now.Add(1*time.Second),
		gw, 40003, vm, 8080, "GET", "/other-exploit",
		"", 200, `nope`)

	// ---- Query flow from attacker 1's login ----
	pkt1 := findPacketByURL(t, store, svc, "/login")
	flow, err := store.QueryFlow(pkt1.ID)
	if err != nil {
		t.Fatalf("QueryFlow: %v", err)
	}

	sessions := distinctSessions(flow)
	t.Logf("Token+SNAT flow: %d packets, %d sessions", len(flow), len(sessions))
	for _, p := range flow {
		t.Logf("  sid=%-25s dir=%-8s method=%-4s url=%s", p.SessionID, p.Direction, p.Method, p.URL)
	}

	// Token correlation should link the two sessions (login + secret) but NOT attacker 2
	if len(sessions) != 2 {
		t.Errorf("Token+SNAT: expected 2 sessions (login + secret), got %d", len(sessions))
	}
	if len(flow) != 4 {
		t.Errorf("Token+SNAT: expected 4 packets, got %d", len(flow))
	}

	// Verify attacker 2's session is excluded
	for _, p := range flow {
		if p.URL == "/other-exploit" {
			t.Error("Token+SNAT: attacker 2's packet leaked into the flow")
		}
	}
}

// ---------- Cookie-based session correlation ----------
// Simulates a Flask/Express app using Set-Cookie/Cookie headers instead of Bearer tokens.

func TestFlowCookieCorrelation(t *testing.T) {
	dir := t.TempDir()
	store, err := NewPacketStore(dir)
	if err != nil {
		t.Fatalf("NewPacketStore: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC().Truncate(time.Second)
	vm := "10.60.1.1"
	svc := "svc-flask"

	// Step 1: POST /login → server sets session cookie (conn 1)
	if err := store.Insert(&Packet{
		ServiceID: svc, SessionID: svc + "/10.81.3.5:41001", Timestamp: now,
		SrcIP: "10.81.3.5", SrcPort: 41001, DstIP: vm, DstPort: 5000,
		Protocol: "http", Direction: DirectionRequest,
		Method: "POST", URL: "/login",
		BodyString: `{"user":"admin","pass":"admin"}`,
		Headers:    map[string]string{"Content-Type": "application/json"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Insert(&Packet{
		ServiceID: svc, SessionID: svc + "/10.81.3.5:41001", Timestamp: now.Add(50 * time.Millisecond),
		SrcIP: vm, SrcPort: 5000, DstIP: "10.81.3.5", DstPort: 41001,
		Protocol: "http", Direction: DirectionResponse,
		Status: 200, BodyString: `{"ok":true}`,
		Headers: map[string]string{"Set-Cookie": "session=eyJhbGciOiJIUzI1NiJ9.flask_sess_abc123; Path=/; HttpOnly"},
	}); err != nil {
		t.Fatal(err)
	}

	// Step 2: GET /profile — sends cookie (conn 2)
	if err := store.Insert(&Packet{
		ServiceID: svc, SessionID: svc + "/10.81.3.5:41002", Timestamp: now.Add(2 * time.Second),
		SrcIP: "10.81.3.5", SrcPort: 41002, DstIP: vm, DstPort: 5000,
		Protocol: "http", Direction: DirectionRequest,
		Method: "GET", URL: "/profile",
		Headers: map[string]string{"Cookie": "session=eyJhbGciOiJIUzI1NiJ9.flask_sess_abc123"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Insert(&Packet{
		ServiceID: svc, SessionID: svc + "/10.81.3.5:41002", Timestamp: now.Add(2*time.Second + 50*time.Millisecond),
		SrcIP: vm, SrcPort: 5000, DstIP: "10.81.3.5", DstPort: 41002,
		Protocol: "http", Direction: DirectionResponse,
		Status: 200, BodyString: `{"user":"admin","role":"superuser"}`,
	}); err != nil {
		t.Fatal(err)
	}

	// Step 3: GET /admin/secrets — sends cookie (conn 3)
	if err := store.Insert(&Packet{
		ServiceID: svc, SessionID: svc + "/10.81.3.5:41003", Timestamp: now.Add(4 * time.Second),
		SrcIP: "10.81.3.5", SrcPort: 41003, DstIP: vm, DstPort: 5000,
		Protocol: "http", Direction: DirectionRequest,
		Method: "GET", URL: "/admin/secrets",
		Headers: map[string]string{"Cookie": "session=eyJhbGciOiJIUzI1NiJ9.flask_sess_abc123"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Insert(&Packet{
		ServiceID: svc, SessionID: svc + "/10.81.3.5:41003", Timestamp: now.Add(4*time.Second + 50*time.Millisecond),
		SrcIP: vm, SrcPort: 5000, DstIP: "10.81.3.5", DstPort: 41003,
		Protocol: "http", Direction: DirectionResponse,
		Status: 200, BodyString: `{"flag":"FLAG{cookie_monster}"}`,
	}); err != nil {
		t.Fatal(err)
	}

	// Step 4: POST /admin/action — sends cookie (conn 4)
	if err := store.Insert(&Packet{
		ServiceID: svc, SessionID: svc + "/10.81.3.5:41004", Timestamp: now.Add(6 * time.Second),
		SrcIP: "10.81.3.5", SrcPort: 41004, DstIP: vm, DstPort: 5000,
		Protocol: "http", Direction: DirectionRequest,
		Method: "POST", URL: "/admin/action",
		BodyString: `{"action":"dump"}`,
		Headers:    map[string]string{"Cookie": "session=eyJhbGciOiJIUzI1NiJ9.flask_sess_abc123", "Content-Type": "application/json"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Insert(&Packet{
		ServiceID: svc, SessionID: svc + "/10.81.3.5:41004", Timestamp: now.Add(6*time.Second + 50*time.Millisecond),
		SrcIP: vm, SrcPort: 5000, DstIP: "10.81.3.5", DstPort: 41004,
		Protocol: "http", Direction: DirectionResponse,
		Status: 200, BodyString: `{"data":"secret_stuff"}`,
	}); err != nil {
		t.Fatal(err)
	}

	// Noise: different attacker, different cookie
	if err := store.Insert(&Packet{
		ServiceID: svc, SessionID: svc + "/10.81.7.2:42001", Timestamp: now.Add(3 * time.Second),
		SrcIP: "10.81.7.2", SrcPort: 42001, DstIP: vm, DstPort: 5000,
		Protocol: "http", Direction: DirectionRequest,
		Method: "GET", URL: "/other",
		Headers: map[string]string{"Cookie": "session=DIFFERENT_SESSION_VALUE_9999"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Insert(&Packet{
		ServiceID: svc, SessionID: svc + "/10.81.7.2:42001", Timestamp: now.Add(3*time.Second + 50*time.Millisecond),
		SrcIP: vm, SrcPort: 5000, DstIP: "10.81.7.2", DstPort: 42001,
		Protocol: "http", Direction: DirectionResponse,
		Status: 200, BodyString: `nope`,
	}); err != nil {
		t.Fatal(err)
	}

	// ---- Query flow from step 1 (login) ----
	pkt1 := findPacketByURL(t, store, svc, "/login")
	flow, err := store.QueryFlow(pkt1.ID)
	if err != nil {
		t.Fatalf("QueryFlow: %v", err)
	}

	sessions := distinctSessions(flow)
	t.Logf("Cookie flow: %d packets, %d sessions", len(flow), len(sessions))
	for _, p := range flow {
		t.Logf("  sid=%-30s dir=%-8s method=%-4s url=%s", p.SessionID, p.Direction, p.Method, p.URL)
	}

	// Should get all 4 sessions linked by the cookie (8 packets)
	if len(sessions) != 4 {
		t.Errorf("Cookie: expected 4 sessions, got %d", len(sessions))
	}
	if len(flow) != 8 {
		t.Errorf("Cookie: expected 8 packets, got %d", len(flow))
	}

	// Verify noise is excluded
	for _, p := range flow {
		if p.URL == "/other" {
			t.Error("Cookie: noise packet from different session leaked in")
		}
	}
}

// Cookie correlation should work even in SNAT — tokens/cookies override SNAT detection.
func TestFlowCookieCorrelation_WithSNAT(t *testing.T) {
	dir := t.TempDir()
	store, err := NewPacketStore(dir)
	if err != nil {
		t.Fatalf("NewPacketStore: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC().Truncate(time.Second)
	gw := "10.254.0.1"
	vm := "10.60.1.1"
	svc := "svc-php"

	// Attacker 1: 3-step exploit with PHPSESSID cookie (all from gateway IP)
	// Step 1: POST /login → Set-Cookie
	if err := store.Insert(&Packet{
		ServiceID: svc, SessionID: svc + "/" + gw + ":40001", Timestamp: now,
		SrcIP: gw, SrcPort: 40001, DstIP: vm, DstPort: 80,
		Protocol: "http", Direction: DirectionRequest,
		Method: "POST", URL: "/login.php",
		BodyString: `user=admin&pass=admin`,
		Headers:    map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Insert(&Packet{
		ServiceID: svc, SessionID: svc + "/" + gw + ":40001", Timestamp: now.Add(50 * time.Millisecond),
		SrcIP: vm, SrcPort: 80, DstIP: gw, DstPort: 40001,
		Protocol: "http", Direction: DirectionResponse,
		Status: 302, BodyString: ``,
		Headers: map[string]string{"Set-Cookie": "PHPSESSID=a1b2c3d4e5f6g7h8i9j0; Path=/"},
	}); err != nil {
		t.Fatal(err)
	}
	// Step 2: GET /dashboard — Cookie
	if err := store.Insert(&Packet{
		ServiceID: svc, SessionID: svc + "/" + gw + ":40002", Timestamp: now.Add(1 * time.Second),
		SrcIP: gw, SrcPort: 40002, DstIP: vm, DstPort: 80,
		Protocol: "http", Direction: DirectionRequest,
		Method: "GET", URL: "/dashboard.php",
		Headers: map[string]string{"Cookie": "PHPSESSID=a1b2c3d4e5f6g7h8i9j0"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Insert(&Packet{
		ServiceID: svc, SessionID: svc + "/" + gw + ":40002", Timestamp: now.Add(1*time.Second + 50*time.Millisecond),
		SrcIP: vm, SrcPort: 80, DstIP: gw, DstPort: 40002,
		Protocol: "http", Direction: DirectionResponse,
		Status: 200, BodyString: `<h1>Dashboard</h1>`,
	}); err != nil {
		t.Fatal(err)
	}
	// Step 3: GET /flag — Cookie
	if err := store.Insert(&Packet{
		ServiceID: svc, SessionID: svc + "/" + gw + ":40003", Timestamp: now.Add(3 * time.Second),
		SrcIP: gw, SrcPort: 40003, DstIP: vm, DstPort: 80,
		Protocol: "http", Direction: DirectionRequest,
		Method: "GET", URL: "/flag.php",
		Headers: map[string]string{"Cookie": "PHPSESSID=a1b2c3d4e5f6g7h8i9j0"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Insert(&Packet{
		ServiceID: svc, SessionID: svc + "/" + gw + ":40003", Timestamp: now.Add(3*time.Second + 50*time.Millisecond),
		SrcIP: vm, SrcPort: 80, DstIP: gw, DstPort: 40003,
		Protocol: "http", Direction: DirectionResponse,
		Status: 200, BodyString: `FLAG{php_session_works}`,
	}); err != nil {
		t.Fatal(err)
	}

	// Attacker 2: different exploit, different cookie, same gateway IP
	insertReqRes(t, store, svc, svc+"/"+gw+":40010", now.Add(2*time.Second),
		gw, 40010, vm, 80, "GET", "/exploit2",
		"", 200, `nope`)

	// Checksystem
	insertReqRes(t, store, svc, svc+"/"+gw+":50001", now.Add(4*time.Second),
		gw, 50001, vm, 80, "GET", "/health",
		"", 200, `ok`)

	// ---- Query flow from attacker 1's login ----
	pkt1 := findPacketByURL(t, store, svc, "/login.php")
	flow, err := store.QueryFlow(pkt1.ID)
	if err != nil {
		t.Fatalf("QueryFlow: %v", err)
	}

	sessions := distinctSessions(flow)
	t.Logf("Cookie+SNAT flow: %d packets, %d sessions", len(flow), len(sessions))
	for _, p := range flow {
		t.Logf("  sid=%-25s dir=%-8s method=%-4s url=%s", p.SessionID, p.Direction, p.Method, p.URL)
	}

	// Cookie correlation should link all 3 sessions (6 packets)
	// despite SNAT — tokens/cookies bypass peer IP fallback entirely
	if len(sessions) != 3 {
		t.Errorf("Cookie+SNAT: expected 3 sessions, got %d", len(sessions))
	}
	if len(flow) != 6 {
		t.Errorf("Cookie+SNAT: expected 6 packets, got %d", len(flow))
	}

	// Verify attacker 2 and checksystem excluded
	for _, p := range flow {
		if p.URL == "/exploit2" || p.URL == "/health" {
			t.Errorf("Cookie+SNAT: unexpected packet leaked: %s", p.URL)
		}
	}
}

// ---------- ExploitFlow: single run out of a multi-run correlated flow ----------
// Under SNAT an attacker re-runs the same exploit every tick; all runs share the
// victim's session token, so QueryFlow correlates them into one flow. ExploitFlow
// must return only the run containing the anchor packet, so the generated exploit
// keeps the real step order (e.g. login before the authed GET).

func TestExploitFlow_SingleRun(t *testing.T) {
	dir := t.TempDir()
	store, err := NewPacketStore(dir)
	if err != nil {
		t.Fatalf("NewPacketStore: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC().Truncate(time.Second)
	gw := "10.254.0.1" // single SNAT gateway IP for everyone
	vm := "10.60.1.1"
	svc := "svc-soh"
	sA := svc + "/" + gw + ":40001"
	sB := svc + "/" + gw + ":40002"
	tok := `"token":"sharedsession1234"` // links the two runs in QueryFlow

	// Run A (older): user/4 then items — first response carries the shared token.
	insertReqRes(t, store, svc, sA, now, gw, 40001, vm, 80,
		"GET", "/api/user/4", "", 200, `{"user":"victim",`+tok+`}`)
	insertReqRes(t, store, svc, sA, now.Add(100*time.Millisecond), gw, 40001, vm, 80,
		"GET", "/api/user/items", "", 200, `{"items":[]}`)

	// Run B (newer, +30s): user/4 -> login -> items. Login response is the anchor.
	base := now.Add(30 * time.Second)
	insertReqRes(t, store, svc, sB, base, gw, 40002, vm, 80,
		"GET", "/api/user/4", "", 200, `{"user":"victim",`+tok+`}`)
	if err := store.Insert(&Packet{
		ServiceID: svc, SessionID: sB, Timestamp: base.Add(100 * time.Millisecond),
		SrcIP: gw, SrcPort: 40002, DstIP: vm, DstPort: 80, Protocol: "http",
		Direction: DirectionRequest, Method: "POST", URL: "/api/login", BodyString: `{"u":"x"}`,
	}); err != nil {
		t.Fatal(err)
	}
	anchor := &Packet{
		ServiceID: svc, SessionID: sB, Timestamp: base.Add(150 * time.Millisecond),
		SrcIP: vm, SrcPort: 80, DstIP: gw, DstPort: 40002, Protocol: "http",
		Direction: DirectionResponse, Status: 200, BodyString: `{"ok":true,` + tok + `}`,
	}
	if err := store.Insert(anchor); err != nil {
		t.Fatal(err)
	}
	insertReqRes(t, store, svc, sB, base.Add(200*time.Millisecond), gw, 40002, vm, 80,
		"GET", "/api/user/items", "", 200, `{"items":[{"name":"Treasure"}]}`)

	// Sanity: the correlated flow must merge both runs (shared token).
	full, err := store.QueryFlow(anchor.ID)
	if err != nil {
		t.Fatalf("QueryFlow: %v", err)
	}
	if len(distinctSessions(full)) < 2 {
		t.Fatalf("expected both runs correlated into the flow, got sessions %v", distinctSessions(full))
	}

	// ExploitFlow must return only the anchor's run (session :40002).
	run, err := store.ExploitFlow(anchor.ID)
	if err != nil {
		t.Fatalf("ExploitFlow: %v", err)
	}
	if sids := distinctSessions(run); len(sids) != 1 || !sids[sB] {
		t.Fatalf("ExploitFlow should return only the anchor run, got sessions %v (%d packets)", sids, len(run))
	}
	// ...and that run contains login followed by the authed items request.
	var sawLogin, sawItemsAfterLogin bool
	for _, p := range run {
		if p.URL == "/api/login" {
			sawLogin = true
		}
		if p.URL == "/api/user/items" && sawLogin {
			sawItemsAfterLogin = true
		}
	}
	if !sawLogin || !sawItemsAfterLogin {
		t.Fatalf("anchor run should contain login then items; got %d packets", len(run))
	}
}

// ---------- helpers ----------

func findPacketByURL(t *testing.T, store *PacketStore, serviceID, urlPath string) *Packet {
	t.Helper()
	pkts, _, err := store.Query(PacketQuery{ServiceID: serviceID, Limit: 100, SortOrder: "asc"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	for _, p := range pkts {
		if p.URL == urlPath && p.Direction == DirectionRequest {
			return p
		}
	}
	t.Fatalf("packet with URL %q not found", urlPath)
	return nil
}
