package dropper

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/SimoneErrigo/Janus/backend/internal/filter"
)

func TestDeriveExpression_String(t *testing.T) {
	r := &Rule{Type: MatchString, Scope: ScopeBody, Pattern: "pippo"}
	got := DeriveExpression(r)
	want := `body contains "pippo"`
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if _, err := filter.Compile(got); err != nil {
		t.Fatalf("derived expression must parse: %v", err)
	}
}

func TestDeriveExpression_Regex(t *testing.T) {
	r := &Rule{Type: MatchRegex, Scope: ScopeURL, Pattern: `^/admin/.*$`}
	got := DeriveExpression(r)
	want := `url matches "^/admin/.*$"`
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if _, err := filter.Compile(got); err != nil {
		t.Fatalf("derived expression must parse: %v", err)
	}
}

func TestDeriveExpression_BytesHexEscape(t *testing.T) {
	// 0xDEADBEEF → \xDE\xAD\xBE\xEF
	r := &Rule{Type: MatchBytes, Scope: ScopeRaw, Pattern: "DEADBEEF"}
	got := DeriveExpression(r)
	want := `raw contains "\xDE\xAD\xBE\xEF"`
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	// Round-trip through the parser/lexer to make sure \xHH escapes work.
	if _, err := filter.Compile(got); err != nil {
		t.Fatalf("derived expression must parse: %v", err)
	}
}

func TestDeriveExpression_MultiScope(t *testing.T) {
	r := &Rule{Type: MatchString, Scope: Scope("body,header,url"), Pattern: "x"}
	got := DeriveExpression(r)
	want := `(body contains "x" OR header contains "x" OR url contains "x")`
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if _, err := filter.Compile(got); err != nil {
		t.Fatalf("derived expression must parse: %v", err)
	}
}

func TestDeriveExpression_QuoteEscape(t *testing.T) {
	r := &Rule{Type: MatchString, Scope: ScopeBody, Pattern: `say "hi"`}
	got := DeriveExpression(r)
	if _, err := filter.Compile(got); err != nil {
		t.Fatalf("derived expression must parse: %v", err)
	}
}

func TestRuleStore_LoadMigrationFillsExpression(t *testing.T) {
	dir := t.TempDir()
	// Write a legacy rules.json with no Expression field.
	legacy := []map[string]any{
		{
			"id":         "r1",
			"service_id": "svc-a",
			"name":       "old",
			"type":       "string",
			"scope":      "body",
			"pattern":    "pippo",
			"priority":   10,
			"enabled":    true,
			"action":     "drop",
		},
	}
	data, err := json.MarshalIndent(legacy, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rules.json"), data, 0644); err != nil {
		t.Fatal(err)
	}

	store, err := NewRuleStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	r, ok := store.GetRule("r1")
	if !ok {
		t.Fatal("rule missing after load")
	}
	if r.Expression == "" {
		t.Fatal("Expression should have been derived")
	}
	if r.Expression != `body contains "pippo"` {
		t.Fatalf("derived %q, want body contains \"pippo\"", r.Expression)
	}

	// And it must have been persisted back to disk.
	raw, err := os.ReadFile(filepath.Join(dir, "rules.json"))
	if err != nil {
		t.Fatal(err)
	}
	var roundtrip []*Rule
	if err := json.Unmarshal(raw, &roundtrip); err != nil {
		t.Fatal(err)
	}
	if len(roundtrip) != 1 || roundtrip[0].Expression == "" {
		t.Fatalf("Expression not persisted: %#v", roundtrip)
	}
}

func TestEnsureFlagRule_SetsBroadExpression(t *testing.T) {
	dir := t.TempDir()
	store, err := NewRuleStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	regex := "[A-Z0-9]{31}="
	EnsureFlagRule(store, "svc-x", regex)

	r, ok := store.GetRule("flag-auto-svc-x")
	if !ok {
		t.Fatal("flag rule not created")
	}
	want := `body matches "[A-Z0-9]{31}=" OR url matches "[A-Z0-9]{31}=" OR header matches "[A-Z0-9]{31}="`
	if r.Expression != want {
		t.Fatalf("flag rule expression =\n  %q\nwant\n  %q", r.Expression, want)
	}
	if r.Action != ActionAlert {
		t.Fatalf("flag rule action = %s, want alert", r.Action)
	}
	// Make sure the expression compiles.
	if _, err := filter.Compile(r.Expression); err != nil {
		t.Fatalf("flag expression must parse: %v", err)
	}

	// Calling EnsureFlagRule again should be idempotent.
	EnsureFlagRule(store, "svc-x", regex)
	r2, _ := store.GetRule("flag-auto-svc-x")
	if r2.Expression != want {
		t.Fatalf("expression changed unexpectedly")
	}
}

func TestCreateRule_AutoDerivesExpression(t *testing.T) {
	dir := t.TempDir()
	store, err := NewRuleStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	in := &Rule{
		ID:        "r-new",
		ServiceID: "svc-a",
		Name:      "test",
		Type:      MatchString,
		Scope:     ScopeBody,
		Pattern:   "pluto",
		Priority:  5,
		Enabled:   true,
		Action:    ActionDrop,
	}
	if err := store.CreateRule(in); err != nil {
		t.Fatal(err)
	}
	got, _ := store.GetRule("r-new")
	if got.Expression != `body contains "pluto"` {
		t.Fatalf("CreateRule should auto-derive Expression, got %q", got.Expression)
	}
}
