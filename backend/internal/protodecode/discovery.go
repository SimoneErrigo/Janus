package protodecode

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DiscoverProtoFiles walks dir recursively and returns absolute paths to
// every .proto file found, sorted for stable output. Returns an empty
// slice if the directory is missing or unreadable — callers treat that
// as "no auto-discovered protos".
func DiscoverProtoFiles(dir string) []string {
	if dir == "" {
		return nil
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return nil
	}
	var out []string
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries, keep walking
		}
		if d.IsDir() {
			return nil
		}
		if strings.EqualFold(filepath.Ext(path), ".proto") {
			out = append(out, path)
		}
		return nil
	})
	sort.Strings(out)
	return out
}
