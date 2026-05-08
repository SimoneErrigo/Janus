package sniffer

import (
	"testing"
	"time"
)

func setupQueryDSLStore(t *testing.T) *PacketStore {
	t.Helper()
	store, err := NewPacketStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewPacketStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	now := time.Now().UTC().Truncate(time.Second)
	insert := func(pkt *Packet) {
		if err := store.Insert(pkt); err != nil {
			t.Fatal(err)
		}
	}

	insert(&Packet{
		ServiceID: "svc-a", SessionID: "s1", Timestamp: now,
		SrcIP: "10.0.5.7", SrcPort: 4001, DstIP: "10.60.1.1", DstPort: 8080,
		Protocol: "http", Direction: DirectionRequest,
		Method: "POST", URL: "/api/admin/login", BodyString: `{"user":"pippo"}`,
		Headers: map[string]string{"User-Agent": "curl/7.0", "Authorization": "Bearer abc"},
	})
	insert(&Packet{
		ServiceID: "svc-a", SessionID: "s1", Timestamp: now.Add(50 * time.Millisecond),
		SrcIP: "10.60.1.1", SrcPort: 8080, DstIP: "10.0.5.7", DstPort: 4001,
		Protocol: "http", Direction: DirectionResponse,
		Status: 200, BodyString: `{"ok":true}`,
	})
	insert(&Packet{
		ServiceID: "svc-b", SessionID: "s2", Timestamp: now.Add(time.Second),
		SrcIP: "192.168.1.5", SrcPort: 4500, DstIP: "10.60.1.1", DstPort: 9090,
		Protocol: "http", Direction: DirectionRequest,
		Method: "GET", URL: "/health", BodyString: "",
		Headers: map[string]string{"User-Agent": "GoBot/1.0"},
	})
	insert(&Packet{
		ServiceID: "svc-a", SessionID: "s3", Timestamp: now.Add(2 * time.Second),
		SrcIP: "10.0.5.8", SrcPort: 4002, DstIP: "10.60.1.1", DstPort: 8080,
		Protocol: "http", Direction: DirectionRequest,
		Method: "PUT", URL: "/api/upload", BodyString: `{"data":"asdrubale"}`,
		Headers: map[string]string{"X-Test": "pluto"},
	})
	return store
}

func runQ(t *testing.T, store *PacketStore, q string) []*Packet {
	t.Helper()
	pkts, _, err := store.Query(PacketQuery{Q: q, Limit: 100})
	if err != nil {
		t.Fatalf("Query %q: %v", q, err)
	}
	return pkts
}

func TestQueryDSL_BasicPushdown(t *testing.T) {
	store := setupQueryDSLStore(t)

	pkts := runQ(t, store, `service == "svc-a"`)
	if len(pkts) != 3 {
		t.Errorf("svc-a: got %d, want 3", len(pkts))
	}

	pkts = runQ(t, store, `method == "POST"`)
	if len(pkts) != 1 {
		t.Errorf("POST: got %d, want 1", len(pkts))
	}

	pkts = runQ(t, store, `status == 200`)
	if len(pkts) != 1 {
		t.Errorf("status 200: got %d, want 1", len(pkts))
	}
}

func TestQueryDSL_ContainsAndCombined(t *testing.T) {
	store := setupQueryDSLStore(t)

	pkts := runQ(t, store, `body contains "pippo"`)
	if len(pkts) != 1 {
		t.Errorf("body contains pippo: got %d, want 1", len(pkts))
	}

	pkts = runQ(t, store, `(body contains "pippo" OR body contains "asdrubale") AND service == "svc-a"`)
	if len(pkts) != 2 {
		t.Errorf("combined OR/AND: got %d, want 2", len(pkts))
	}

	pkts = runQ(t, store, `url startswith "/api/" AND method != "GET"`)
	if len(pkts) != 2 {
		t.Errorf("startswith + neq: got %d, want 2", len(pkts))
	}
}

func TestQueryDSL_Residual(t *testing.T) {
	store := setupQueryDSLStore(t)

	// regex via `matches` is a residual predicate.
	pkts := runQ(t, store, `url matches "^/api/.*"`)
	if len(pkts) != 2 {
		t.Errorf("regex: got %d, want 2", len(pkts))
	}

	// header.<name> is residual; only the first request has Authorization.
	pkts = runQ(t, store, `header.Authorization startswith "Bearer "`)
	if len(pkts) != 1 {
		t.Errorf("header sub-name: got %d, want 1", len(pkts))
	}

	// CIDR in `in` for IP fields is residual.
	pkts = runQ(t, store, `src in (10.0.0.0/8)`)
	if len(pkts) != 3 {
		t.Errorf("CIDR in: got %d, want 3", len(pkts))
	}
}

func TestQueryDSL_LegacyAndDSLAndNegation(t *testing.T) {
	store := setupQueryDSLStore(t)

	// Legacy contains_body AND-merged with DSL service filter.
	pkts, _, err := store.Query(PacketQuery{
		ContainsBody: "asdrubale",
		Q:            `service == "svc-a"`,
		Limit:        100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(pkts) != 1 {
		t.Errorf("legacy + DSL: got %d, want 1", len(pkts))
	}

	// NOT predicate.
	pkts = runQ(t, store, `NOT body contains "pippo" AND direction == "request"`)
	if len(pkts) != 2 {
		t.Errorf("NOT: got %d, want 2", len(pkts))
	}
}

func TestQueryDSL_InvalidExpression(t *testing.T) {
	store := setupQueryDSLStore(t)

	_, _, err := store.Query(PacketQuery{Q: `body contains`})
	if err == nil {
		t.Fatal("expected error for invalid expression")
	}
}
