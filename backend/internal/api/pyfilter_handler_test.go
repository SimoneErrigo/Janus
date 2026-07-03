package api

import (
	"testing"

	"github.com/SimoneErrigo/Janus/backend/internal/dropper"
	"github.com/SimoneErrigo/Janus/backend/internal/pyfilter"
)

func newRuleStore(t *testing.T) *dropper.RuleStore {
	t.Helper()
	rs, err := dropper.NewRuleStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewRuleStore: %v", err)
	}
	return rs
}

func TestInstallPyFilterDrop_CreatesContentRule(t *testing.T) {
	rs := newRuleStore(t)
	flow := pyfilter.Flow{"service": "web"}
	m := pyfilter.Match{Script: "repeat-login", Name: "repeat-login", Reason: "abuse", Drop: `body contains "alice"`}

	id, err := InstallPyFilterDrop(rs, flow, m)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	rule, ok := rs.GetRule(id)
	if !ok {
		t.Fatal("rule was not created")
	}
	if rule.Action != dropper.ActionDrop || !rule.Enabled {
		t.Errorf("expected enabled drop rule, got action=%s enabled=%v", rule.Action, rule.Enabled)
	}
	if rule.ServiceID != "web" || rule.Expression != `body contains "alice"` {
		t.Errorf("unexpected rule: %+v", rule)
	}

	// Idempotent: same script+service+expr reuses the same rule id.
	id2, err := InstallPyFilterDrop(rs, flow, m)
	if err != nil {
		t.Fatalf("second install: %v", err)
	}
	if id2 != id {
		t.Errorf("expected dedup to reuse id %q, got %q", id, id2)
	}
	if len(rs.ListRules("web")) != 1 {
		t.Errorf("expected exactly one rule, got %d", len(rs.ListRules("web")))
	}
}

func TestInstallPyFilterDrop_RejectsIPFields(t *testing.T) {
	rs := newRuleStore(t)
	flow := pyfilter.Flow{"service": "web"}
	for _, expr := range []string{
		`src == "10.60.5.7"`,
		`peer in (10.0.0.0/8)`,
		`body contains "x" AND sport == 5000`,
	} {
		_, err := InstallPyFilterDrop(rs, flow, pyfilter.Match{Script: "s", Name: "s", Drop: expr})
		if err == nil {
			t.Errorf("expected %q to be rejected (network field)", expr)
		}
	}
	if n := len(rs.ListRules("web")); n != 0 {
		t.Errorf("no rules should have been created, got %d", n)
	}
}

func TestInstallPyFilterDrop_EmptyIsNoop(t *testing.T) {
	rs := newRuleStore(t)
	id, err := InstallPyFilterDrop(rs, pyfilter.Flow{"service": "web"}, pyfilter.Match{Script: "s", Name: "s"})
	if err != nil || id != "" {
		t.Fatalf("empty drop should be a no-op, got id=%q err=%v", id, err)
	}
}

func TestInstallPyFilterDrop_InvalidExpr(t *testing.T) {
	rs := newRuleStore(t)
	_, err := InstallPyFilterDrop(rs, pyfilter.Flow{"service": "web"}, pyfilter.Match{Script: "s", Name: "s", Drop: `body contains`})
	if err == nil {
		t.Error("expected a parse error for an invalid drop expression")
	}
}
