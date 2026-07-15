package flagids

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const enowarsAttackInfo = `{
  "availableTeams": ["10.1.52.1", "10.1.53.1"],
  "services": {
    "service_1": {
      "10.1.52.1": {
        "7": [["user73"], ["user5"]],
        "8": [["user96"], ["user314"]]
      },
      "10.1.53.1": {"8": [["other-team"]]}
    },
    "service_2": {
      "10.1.52.1": {"8": [["token-1", "token-2"], ["token-1"]]}
    }
  }
}`

func TestParseENOWARSRounded(t *testing.T) {
	got, err := parseENOWARSRounded([]byte(enowarsAttackInfo), "52")
	if err != nil {
		t.Fatal(err)
	}
	want := map[int]map[string][]string{
		7: {"service_1": {"user73", "user5"}},
		8: {
			"service_1": {"user96", "user314"},
			"service_2": {"token-1", "token-2"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected ENOWARS values:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestENOWARSPollerFetchesAllTeamsDocument(t *testing.T) {
	var queryTeam string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queryTeam = r.URL.Query().Get("team")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(enowarsAttackInfo))
	}))
	defer server.Close()

	poller := NewPoller(server.URL, "10.1.52.1", 30, true, "enowars", 120, time.Time{}, 5)
	poller.FetchNow()

	if queryTeam != "" {
		t.Fatalf("ENOWARS request must not include team query, got %q", queryTeam)
	}
	if poller.CurrentRound() != 8 {
		t.Fatalf("current round = %d, want 8", poller.CurrentRound())
	}
	if !poller.ContainsFlagID("account=user314") {
		t.Fatal("expected fetched ENOWARS value to be matched")
	}
	if !poller.ContainsFlagID("account=user5") {
		t.Fatal("expected short ENOWARS value to match on a boundary")
	}
	if poller.ContainsFlagID("account=user50") {
		t.Fatal("short ENOWARS value must not match as a substring")
	}
	if poller.ContainsFlagID("account=other-team") {
		t.Fatal("must not load another team's values")
	}
}

func TestParseENOWARSExpandsJSONStringAttackInfo(t *testing.T) {
	body := `{"services":{"svc":{"10.1.52.1":{"9":[["{\"username\":\"alice73\",\"file\":\"notes99\"}"]]}}}}`
	got, err := parseENOWARSRounded([]byte(body), "52")
	if err != nil {
		t.Fatal(err)
	}
	values := strings.Join(got[9]["svc"], "|")
	for _, wanted := range []string{"alice73", "notes99"} {
		if !strings.Contains(values, wanted) {
			t.Fatalf("expanded values %q do not contain %q", values, wanted)
		}
	}
}

func TestENOWARSPollerKeepsLastGoodSnapshot(t *testing.T) {
	var response atomic.Value
	response.Store(enowarsAttackInfo)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(response.Load().(string)))
	}))
	defer server.Close()

	poller := NewPoller(server.URL, "52", 30, true, "enowars", 60, time.Time{}, 5)
	poller.FetchNow()
	response.Store(`{"services":{"service_1":{"10.1.53.1":{"9":[["other-team"]]}}}}`)
	poller.FetchNow()

	if poller.CurrentRound() != 8 || !poller.ContainsFlagID("account=user314") {
		t.Fatal("a degraded response replaced the last valid ENOWARS snapshot")
	}
	if poller.GetStatus().LastError == "" {
		t.Fatal("degraded response should remain visible in status")
	}
}

func TestENOWARSPollerMergesPartialServices(t *testing.T) {
	var response atomic.Value
	response.Store(enowarsAttackInfo)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(response.Load().(string)))
	}))
	defer server.Close()

	poller := NewPoller(server.URL, "52", 30, true, "enowars", 60, time.Time{}, 5)
	poller.FetchNow()
	response.Store(`{"services":{"service_1":{"10.1.52.1":{"9":[["new-user"]]}}}}`)
	poller.FetchNow()

	if poller.CurrentRound() != 9 || !poller.ContainsFlagID("token=token-1") {
		t.Fatal("partial ENOWARS response discarded a retained service")
	}
}
