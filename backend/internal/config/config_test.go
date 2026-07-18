package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRuntimeConfigPersistsProcessingToggles(t *testing.T) {
	dataDir := t.TempDir()
	source := &Config{
		DataDir:               dataDir,
		ScoringEnabled:        false,
		PyFilterEnabled:       false,
		BaselineServiceRounds: map[string]BaselineRoundRange{},
	}
	if err := saveRuntimeConfig(source); err != nil {
		t.Fatalf("saveRuntimeConfig: %v", err)
	}

	loaded := &Config{
		DataDir:               dataDir,
		ScoringEnabled:        true,
		PyFilterEnabled:       true,
		BaselineServiceRounds: map[string]BaselineRoundRange{},
	}
	if err := loadRuntimeConfig(loaded); err != nil {
		t.Fatalf("loadRuntimeConfig: %v", err)
	}
	if loaded.ScoringEnabled {
		t.Fatal("ScoringEnabled = true, want persisted false")
	}
	if loaded.PyFilterEnabled {
		t.Fatal("PyFilterEnabled = true, want persisted false")
	}
}

func TestLegacyRuntimeConfigPreservesProcessingDefaults(t *testing.T) {
	dataDir := t.TempDir()
	path := filepath.Join(dataDir, runtimeConfigName)
	if err := os.WriteFile(path, []byte("{\"traffic_mode\":\"live\"}\n"), 0o600); err != nil {
		t.Fatalf("write legacy runtime config: %v", err)
	}

	loaded := &Config{
		DataDir:               dataDir,
		ScoringEnabled:        true,
		PyFilterEnabled:       true,
		BaselineServiceRounds: map[string]BaselineRoundRange{},
	}
	if err := loadRuntimeConfig(loaded); err != nil {
		t.Fatalf("loadRuntimeConfig: %v", err)
	}
	if !loaded.ScoringEnabled {
		t.Fatal("legacy runtime config disabled scoring")
	}
	if !loaded.PyFilterEnabled {
		t.Fatal("legacy runtime config disabled Python filters")
	}
}
