package pyfilter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Script is a persisted Python filter addon.
type Script struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Code    string `json:"code"`
	Enabled bool   `json:"enabled"`
	// Blocking runs this script synchronously on the request hot path (inline),
	// so a match returning {"drop": True} blocks the CURRENT request in real time
	// (like a drop rule) instead of only alerting/installing a future-traffic
	// rule. Non-blocking scripts stay on the async pipeline (zero hot-path cost).
	Blocking  bool  `json:"blocking"`
	CreatedAt int64 `json:"created_at"`
	UpdatedAt int64 `json:"updated_at"`
}

var idSanitize = regexp.MustCompile(`[^a-z0-9._-]+`)

// slugID derives a URL/JSON-safe id from a human name.
func slugID(name string) string {
	s := idSanitize.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-")
	s = strings.Trim(s, "-._")
	if s == "" {
		s = "filter"
	}
	return s
}

// loadScripts reads the persisted script list from disk. A missing file yields
// an empty list (not an error).
func loadScripts(path string) ([]Script, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []Script{}, nil
		}
		return nil, err
	}
	var scripts []Script
	if err := json.Unmarshal(data, &scripts); err != nil {
		return nil, err
	}
	if scripts == nil {
		scripts = []Script{}
	}
	return scripts, nil
}

// saveScripts atomically writes the script list to disk.
func saveScripts(path string, scripts []Script) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(scripts, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
