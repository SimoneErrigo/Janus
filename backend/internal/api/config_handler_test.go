package api

import (
	"errors"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SimoneErrigo/Janus/backend/internal/config"
	"github.com/SimoneErrigo/Janus/backend/internal/pyfilter"
	"github.com/SimoneErrigo/Janus/backend/internal/scoring"
)

type configTestScorer struct {
	enabled      bool
	configureErr error
	events       []string
	rebuildCalls int
}

func (s *configTestScorer) Status() scoring.Status { return scoring.Status{Enabled: s.enabled} }
func (s *configTestScorer) IsEnabled() bool        { return s.enabled }
func (s *configTestScorer) SetEnabled(enabled bool) {
	s.enabled = enabled
	if enabled {
		s.events = append(s.events, "enable")
	} else {
		s.events = append(s.events, "disable")
	}
}
func (s *configTestScorer) ConfigureBaseline(scoring.BaselineConfig) error {
	s.events = append(s.events, "configure")
	return s.configureErr
}
func (s *configTestScorer) RebuildBaseline() error {
	s.rebuildCalls++
	return nil
}

func TestConfigProcessingTogglesApplyLiveAndRollback(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("DATA_DIR", dataDir)
	t.Setenv("SCORING_ENABLED", "true")
	t.Setenv("PYFILTER_ENABLED", "true")
	if _, err := config.Load(filepath.Join(dataDir, "missing.env")); err != nil {
		t.Fatalf("load config: %v", err)
	}

	pyManager := pyfilter.NewManager(pyfilter.Config{DataDir: dataDir})
	defer pyManager.Close()
	scorer := &configTestScorer{enabled: true}
	server := &Server{pyfilter: pyManager, scoring: scorer}

	request := httptest.NewRequest("PUT", "/api/config", strings.NewReader(`{"scoring_enabled":false,"pyfilter_enabled":false}`))
	response := httptest.NewRecorder()
	server.updateConfig(response, request)
	if response.Code != 200 {
		t.Fatalf("disable response = %d: %s", response.Code, response.Body.String())
	}
	if scorer.enabled || pyManager.RuntimeEnabled() {
		t.Fatal("processing engines remained enabled after config save")
	}
	if current := config.Get(); current.ScoringEnabled || current.PyFilterEnabled {
		t.Fatal("disabled processing state was not published")
	}

	// Enabling configures the scorer while it is still quiescent. If that step
	// fails, both runtime switches and the durable config must return to false.
	scorer.events = nil
	scorer.configureErr = errors.New("baseline unavailable")
	request = httptest.NewRequest("PUT", "/api/config", strings.NewReader(`{"scoring_enabled":true,"pyfilter_enabled":true}`))
	response = httptest.NewRecorder()
	server.updateConfig(response, request)
	if response.Code != 500 {
		t.Fatalf("failed enable response = %d: %s", response.Code, response.Body.String())
	}
	if scorer.enabled || pyManager.RuntimeEnabled() {
		t.Fatal("failed config apply did not restore disabled runtime state")
	}
	if current := config.Get(); current.ScoringEnabled || current.PyFilterEnabled {
		t.Fatal("failed config apply did not restore durable state")
	}
	if len(scorer.events) < 2 || scorer.events[0] != "configure" || scorer.events[1] != "disable" {
		t.Fatalf("unexpected scoring transition order: %v", scorer.events)
	}

	// Leave the package singleton in its default state for any later tests.
	scorer.configureErr = nil
	request = httptest.NewRequest("PUT", "/api/config", strings.NewReader(`{"scoring_enabled":true,"pyfilter_enabled":true}`))
	response = httptest.NewRecorder()
	server.updateConfig(response, request)
	if response.Code != 200 {
		t.Fatalf("restore response = %d: %s", response.Code, response.Body.String())
	}
}

func TestScoringRebuildRejectedWhenDisabled(t *testing.T) {
	scorer := &configTestScorer{enabled: false}
	server := &Server{scoring: scorer}
	request := httptest.NewRequest("POST", "/api/scoring/baseline/rebuild", nil)
	response := httptest.NewRecorder()

	server.handleScoringBaselineRebuild(response, request)

	if response.Code != 409 {
		t.Fatalf("response = %d, want 409: %s", response.Code, response.Body.String())
	}
	if scorer.rebuildCalls != 0 {
		t.Fatalf("disabled scorer rebuilt %d time(s)", scorer.rebuildCalls)
	}
}
