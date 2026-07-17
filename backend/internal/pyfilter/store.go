package pyfilter

import (
	"encoding/json"
	"fmt"
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
	// Blocking runs this script synchronously on the proxy hot path (inline),
	// so a match returning {"drop": True} drops the CURRENT message in real time
	// (request or response) and flow.body/flow.content rewrites take effect.
	// Non-blocking scripts stay on the async pipeline (alert-only, zero hot-path
	// cost).
	Blocking   bool     `json:"blocking"`
	Mode       string   `json:"mode,omitempty"` // observe | block | rewrite
	ServiceIDs []string `json:"service_ids,omitempty"`
	Directions []string `json:"directions,omitempty"`
	Protocols  []string `json:"protocols,omitempty"`
	CreatedAt  int64    `json:"created_at"`
	UpdatedAt  int64    `json:"updated_at"`
}

func (s *Script) normalize() {
	if s.Mode == "" {
		if s.Blocking {
			s.Mode = "block"
		} else {
			s.Mode = "observe"
		}
	}
	if s.Mode != "observe" && s.Mode != "block" && s.Mode != "rewrite" {
		s.Mode = "observe"
	}
	s.Blocking = s.Mode == "block" || s.Mode == "rewrite"
	if len(s.ServiceIDs) == 0 {
		s.ServiceIDs = []string{"*"}
	}
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
	seen := make(map[string]struct{}, len(scripts))
	for i := range scripts {
		if strings.TrimSpace(scripts[i].ID) == "" {
			return nil, fmt.Errorf("script entry %d has an empty ID", i)
		}
		if _, exists := seen[scripts[i].ID]; exists {
			return nil, fmt.Errorf("duplicate script ID %q", scripts[i].ID)
		}
		seen[scripts[i].ID] = struct{}{}
		scripts[i].normalize()
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
	tmp, err := os.CreateTemp(filepath.Dir(path), ".pyfilters-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
