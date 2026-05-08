// Package protodecode resolves gRPC method signatures from user-supplied
// .proto files and decodes wire-format payloads into JSON using the
// matching message type.
package protodecode

import (
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/jhump/protoreflect/desc"
	"github.com/jhump/protoreflect/desc/protoparse"
	"github.com/jhump/protoreflect/dynamic"
)

// serviceEntry holds the parsed descriptors for one service plus a quick
// lookup table from "package.Service/Method" to the method descriptor.
type serviceEntry struct {
	files   []*desc.FileDescriptor
	methods map[string]*desc.MethodDescriptor // key: "pkg.Service/Method"
	loadErr error                             // last parse error, if any
	paths   []string                          // paths used to build this entry
}

// Cache compiles and memoizes proto descriptors per service id. Calls are
// cheap after the first build for a given (service_id, paths) pair.
type Cache struct {
	mu      sync.RWMutex
	entries map[string]*serviceEntry // key: service_id
}

func NewCache() *Cache {
	return &Cache{entries: make(map[string]*serviceEntry)}
}

// Invalidate drops the cached descriptors for a service. Call this on
// service create/update/delete so the next decode picks up fresh paths.
func (c *Cache) Invalidate(serviceID string) {
	c.mu.Lock()
	delete(c.entries, serviceID)
	c.mu.Unlock()
}

// load returns the entry for serviceID, parsing the given paths if not
// already cached or if the path set has changed. An entry with a non-nil
// loadErr is still cached so we don't re-parse broken inputs on every call.
func (c *Cache) load(serviceID string, paths []string) (*serviceEntry, error) {
	c.mu.RLock()
	entry, ok := c.entries[serviceID]
	c.mu.RUnlock()
	if ok && samePaths(entry.paths, paths) {
		if entry.loadErr != nil {
			return nil, entry.loadErr
		}
		return entry, nil
	}

	entry = buildEntry(paths)
	c.mu.Lock()
	c.entries[serviceID] = entry
	c.mu.Unlock()
	if entry.loadErr != nil {
		return nil, entry.loadErr
	}
	return entry, nil
}

func samePaths(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func buildEntry(paths []string) *serviceEntry {
	entry := &serviceEntry{paths: append([]string(nil), paths...), methods: make(map[string]*desc.MethodDescriptor)}
	if len(paths) == 0 {
		entry.loadErr = errors.New("no .proto paths configured")
		return entry
	}

	// protoparse expects file names relative to its ImportPaths. Collect
	// unique parent directories as import paths so absolute paths resolve.
	importDirs := make([]string, 0, len(paths))
	seen := make(map[string]bool)
	fileNames := make([]string, 0, len(paths))
	for _, p := range paths {
		dir, base := filepath.Split(p)
		if dir == "" {
			dir = "."
		}
		dir = filepath.Clean(dir)
		if !seen[dir] {
			seen[dir] = true
			importDirs = append(importDirs, dir)
		}
		fileNames = append(fileNames, base)
	}

	parser := protoparse.Parser{
		ImportPaths:           importDirs,
		IncludeSourceCodeInfo: false,
	}
	files, err := parser.ParseFiles(fileNames...)
	if err != nil {
		entry.loadErr = fmt.Errorf("parsing .proto files: %w", err)
		return entry
	}
	entry.files = files

	for _, fd := range files {
		for _, sd := range fd.GetServices() {
			svcFQN := sd.GetFullyQualifiedName() // e.g. "cheesycheats.Manager"
			for _, md := range sd.GetMethods() {
				key := svcFQN + "/" + md.GetName()
				entry.methods[key] = md
			}
		}
	}
	return entry
}

// MethodKeyFromURL extracts the gRPC method key from a request URL.
// The URL is expected to be of the form "/<package>.<Service>/<Method>".
// Returns ("cheesycheats.Manager/Register", true) for that path.
func MethodKeyFromURL(url string) (string, bool) {
	if url == "" {
		return "", false
	}
	// Strip query string and leading slash
	if i := strings.IndexByte(url, '?'); i >= 0 {
		url = url[:i]
	}
	url = strings.TrimPrefix(url, "/")
	// Must contain exactly one slash separating service from method
	if strings.Count(url, "/") < 1 {
		return "", false
	}
	// Use last slash so we tolerate a leading "/" that wasn't fully stripped
	lastSlash := strings.LastIndexByte(url, '/')
	svc := url[:lastSlash]
	method := url[lastSlash+1:]
	if svc == "" || method == "" {
		return "", false
	}
	return svc + "/" + method, true
}

// peelGRPCFrames strips one or more gRPC-Web/gRPC framing prefixes from
// raw bytes. Each frame is [1 byte compression flag][4 byte length BE].
// Compressed frames are returned with isCompressed=true; the caller may
// choose to skip them (we cannot decompress without knowing the codec).
func peelGRPCFrames(body []byte) ([][]byte, bool, error) {
	frames := make([][]byte, 0, 1)
	compressedSeen := false
	pos := 0
	for pos < len(body) {
		if pos+5 > len(body) {
			return nil, false, fmt.Errorf("truncated gRPC frame header at offset %d", pos)
		}
		flag := body[pos]
		if flag != 0 && flag != 1 {
			return nil, false, fmt.Errorf("invalid gRPC compression flag 0x%02x", flag)
		}
		length := binary.BigEndian.Uint32(body[pos+1 : pos+5])
		if pos+5+int(length) > len(body) {
			return nil, false, fmt.Errorf("truncated gRPC frame body at offset %d", pos)
		}
		if flag == 1 {
			compressedSeen = true
		}
		frames = append(frames, body[pos+5:pos+5+int(length)])
		pos += 5 + int(length)
	}
	if len(frames) == 0 {
		return nil, false, errors.New("no gRPC frames found")
	}
	return frames, compressedSeen, nil
}

// DecodeResult is the JSON-serializable output of a successful decode.
type DecodeResult struct {
	Method        string   `json:"method"`         // e.g. "cheesycheats.Manager/Register"
	MessageType   string   `json:"message_type"`   // e.g. "cheesycheats.RegisterRequest"
	Direction     string   `json:"direction"`      // "request" or "response"
	Frames        []Frame  `json:"frames"`         // one entry per gRPC frame
	Compressed    bool     `json:"compressed,omitempty"`
	Notes         []string `json:"notes,omitempty"`
}

type Frame struct {
	JSON  string `json:"json,omitempty"`  // pretty JSON of the decoded message
	Error string `json:"error,omitempty"` // populated if this frame failed to decode
	Bytes int    `json:"bytes"`           // length of the inner protobuf payload
}

// ResolveMessageType loads the descriptors for serviceID/protoPaths and
// returns the input or output message descriptor for the given gRPC method
// URL. Used by callers that need the descriptor without doing a full body
// decode (e.g. encoding a single field for click-to-filter).
func (c *Cache) ResolveMessageType(serviceID string, protoPaths []string, url string, direction string) (*desc.MessageDescriptor, error) {
	entry, err := c.load(serviceID, protoPaths)
	if err != nil {
		return nil, err
	}
	key, ok := MethodKeyFromURL(url)
	if !ok {
		return nil, fmt.Errorf("URL %q is not a valid gRPC path", url)
	}
	md, ok := entry.methods[key]
	if !ok {
		return nil, fmt.Errorf("method %q not found in configured .proto files", key)
	}
	if direction == "response" {
		return md.GetOutputType(), nil
	}
	return md.GetInputType(), nil
}

// Decode resolves the method from URL, peels gRPC framing from body, and
// decodes each frame as the method's input or output type (depending on
// direction). The result includes per-frame JSON or per-frame errors.
func (c *Cache) Decode(serviceID string, protoPaths []string, url string, direction string, body []byte) (*DecodeResult, error) {
	entry, err := c.load(serviceID, protoPaths)
	if err != nil {
		return nil, err
	}
	key, ok := MethodKeyFromURL(url)
	if !ok {
		return nil, fmt.Errorf("URL %q is not a valid gRPC path", url)
	}
	md, ok := entry.methods[key]
	if !ok {
		return nil, fmt.Errorf("method %q not found in configured .proto files", key)
	}

	var msgType *desc.MessageDescriptor
	if direction == "response" {
		msgType = md.GetOutputType()
	} else {
		msgType = md.GetInputType()
	}

	frames, compressed, err := peelGRPCFrames(body)
	if err != nil {
		return nil, fmt.Errorf("invalid gRPC framing: %w", err)
	}

	result := &DecodeResult{
		Method:      key,
		MessageType: msgType.GetFullyQualifiedName(),
		Direction:   direction,
		Compressed:  compressed,
	}

	for _, frame := range frames {
		f := Frame{Bytes: len(frame)}
		if compressed {
			f.Error = "compressed frame — cannot decode without the gRPC codec"
			result.Frames = append(result.Frames, f)
			continue
		}
		dyn := dynamic.NewMessage(msgType)
		if err := dyn.Unmarshal(frame); err != nil {
			f.Error = err.Error()
			result.Frames = append(result.Frames, f)
			continue
		}
		jsonBytes, err := dyn.MarshalJSONIndent()
		if err != nil {
			f.Error = "decoded but failed to marshal JSON: " + err.Error()
			result.Frames = append(result.Frames, f)
			continue
		}
		f.JSON = string(jsonBytes)
		result.Frames = append(result.Frames, f)
	}
	return result, nil
}
