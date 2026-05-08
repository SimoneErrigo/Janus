package api

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/SimoneErrigo/Janus/backend/internal/protodecode"
	"github.com/jhump/protoreflect/desc"
	"github.com/jhump/protoreflect/dynamic"
	"google.golang.org/protobuf/types/descriptorpb"
)

// encodeFieldRequest describes the leaf field the user clicked on in the
// Decoded panel. The frontend passes JSON names (gRPC default for protobuf
// → JSON conversion is camelCase). We fall back to the proto-defined name
// for users editing payloads by hand.
type encodeFieldRequest struct {
	ServiceID string      `json:"service_id"`
	Method    string      `json:"method"`    // "package.Service/Method" or full URL
	Direction string      `json:"direction"` // "request" | "response"
	Field     string      `json:"field"`     // JSON name (preferred) or proto name
	Value     interface{} `json:"value"`     // JSON-typed value to encode
}

type encodeFieldResponse struct {
	BytesHex  string `json:"bytes_hex"`        // raw protobuf bytes for this field, hex
	Escaped   string `json:"escaped"`          // backslash-escaped form for `raw contains "..."`
	Predicate string `json:"predicate"`        // ready-to-paste filter predicate
	Method    string `json:"method,omitempty"` // resolved method key
	Field     string `json:"field,omitempty"`  // resolved field name
}

// handleProtoEncodeField encodes a single protobuf field+value into the exact
// wire bytes that would appear in a request/response body. The frontend uses
// this to build `raw contains "\x..."` filters and drop rules from a click on
// the Decoded view, without forcing the user to compute varints by hand.
func (s *Server) handleProtoEncodeField(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req encodeFieldRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.ServiceID == "" || req.Method == "" || req.Field == "" {
		http.Error(w, "service_id, method and field are required", http.StatusBadRequest)
		return
	}
	if req.Direction != "request" && req.Direction != "response" {
		req.Direction = "request"
	}

	svc, ok := s.store.GetService(req.ServiceID)
	if !ok {
		http.Error(w, "service not found", http.StatusNotFound)
		return
	}
	paths := svc.ProtoPaths
	cacheKey := svc.ID
	if len(paths) == 0 {
		paths = protodecode.DiscoverProtoFiles(s.protoDir)
		cacheKey = "__discovery__"
	}
	if len(paths) == 0 {
		http.Error(w, "no .proto paths configured for this service and none auto-discovered", http.StatusBadRequest)
		return
	}

	md, err := s.protoCache.ResolveMessageType(cacheKey, paths, req.Method, req.Direction)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	fd := findFieldByJSONOrProtoName(md, req.Field)
	if fd == nil {
		http.Error(w, fmt.Sprintf("field %q not found in %s", req.Field, md.GetFullyQualifiedName()), http.StatusBadRequest)
		return
	}

	goVal, err := coerceValueForField(fd, req.Value)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	dyn := dynamic.NewMessage(md)
	if err := dyn.TrySetField(fd, goVal); err != nil {
		http.Error(w, "set field: "+err.Error(), http.StatusBadRequest)
		return
	}
	raw, err := dyn.Marshal()
	if err != nil {
		http.Error(w, "marshal: "+err.Error(), http.StatusInternalServerError)
		return
	}

	hexStr := hex.EncodeToString(raw)
	escaped := bytesToFilterEscape(raw)
	predicate := fmt.Sprintf(`raw contains "%s"`, escaped)

	writeJSON(w, http.StatusOK, encodeFieldResponse{
		BytesHex:  hexStr,
		Escaped:   escaped,
		Predicate: predicate,
		Method:    req.Method,
		Field:     fd.GetName(),
	})
}

// findFieldByJSONOrProtoName looks up a field on a message descriptor using
// the JSON name first (the form the user clicks on in the Decoded panel —
// gRPC defaults to camelCase) then the original proto-defined name.
func findFieldByJSONOrProtoName(md *desc.MessageDescriptor, name string) *desc.FieldDescriptor {
	for _, f := range md.GetFields() {
		if f.GetJSONName() == name {
			return f
		}
	}
	return md.FindFieldByName(name)
}

// coerceValueForField converts a JSON-decoded value into the Go type that
// protoreflect's TrySetField expects for the given field descriptor. We
// stay conservative here — supporting only the scalar types the user can
// realistically click on in the Decoded panel — and reject anything else
// with a clear error. Callers should bring the value as it appears in JSON
// (numbers stay numbers, strings stay strings, etc.).
func coerceValueForField(fd *desc.FieldDescriptor, val interface{}) (interface{}, error) {
	if fd.IsRepeated() {
		return nil, fmt.Errorf("repeated fields are not supported yet for click-to-filter")
	}
	if fd.IsMap() {
		return nil, fmt.Errorf("map fields are not supported yet for click-to-filter")
	}
	switch fd.GetType() {
	case descriptorpb.FieldDescriptorProto_TYPE_STRING:
		s, ok := val.(string)
		if !ok {
			return nil, fmt.Errorf("field %s expects a string", fd.GetName())
		}
		return s, nil
	case descriptorpb.FieldDescriptorProto_TYPE_BOOL:
		b, ok := val.(bool)
		if !ok {
			return nil, fmt.Errorf("field %s expects a bool", fd.GetName())
		}
		return b, nil
	case descriptorpb.FieldDescriptorProto_TYPE_INT32,
		descriptorpb.FieldDescriptorProto_TYPE_SINT32,
		descriptorpb.FieldDescriptorProto_TYPE_SFIXED32:
		n, err := toInt64(val)
		if err != nil {
			return nil, fmt.Errorf("field %s: %w", fd.GetName(), err)
		}
		return int32(n), nil
	case descriptorpb.FieldDescriptorProto_TYPE_UINT32,
		descriptorpb.FieldDescriptorProto_TYPE_FIXED32:
		n, err := toUint64(val)
		if err != nil {
			return nil, fmt.Errorf("field %s: %w", fd.GetName(), err)
		}
		return uint32(n), nil
	case descriptorpb.FieldDescriptorProto_TYPE_INT64,
		descriptorpb.FieldDescriptorProto_TYPE_SINT64,
		descriptorpb.FieldDescriptorProto_TYPE_SFIXED64:
		n, err := toInt64(val)
		if err != nil {
			return nil, fmt.Errorf("field %s: %w", fd.GetName(), err)
		}
		return n, nil
	case descriptorpb.FieldDescriptorProto_TYPE_UINT64,
		descriptorpb.FieldDescriptorProto_TYPE_FIXED64:
		n, err := toUint64(val)
		if err != nil {
			return nil, fmt.Errorf("field %s: %w", fd.GetName(), err)
		}
		return n, nil
	case descriptorpb.FieldDescriptorProto_TYPE_FLOAT:
		f, err := toFloat64(val)
		if err != nil {
			return nil, fmt.Errorf("field %s: %w", fd.GetName(), err)
		}
		return float32(f), nil
	case descriptorpb.FieldDescriptorProto_TYPE_DOUBLE:
		f, err := toFloat64(val)
		if err != nil {
			return nil, fmt.Errorf("field %s: %w", fd.GetName(), err)
		}
		return f, nil
	case descriptorpb.FieldDescriptorProto_TYPE_ENUM:
		// Accept either the enum name (string) or its numeric value.
		if s, ok := val.(string); ok {
			ev := fd.GetEnumType().FindValueByName(s)
			if ev == nil {
				return nil, fmt.Errorf("field %s: unknown enum value %q", fd.GetName(), s)
			}
			return ev.GetNumber(), nil
		}
		n, err := toInt64(val)
		if err != nil {
			return nil, fmt.Errorf("field %s: %w", fd.GetName(), err)
		}
		return int32(n), nil
	case descriptorpb.FieldDescriptorProto_TYPE_BYTES:
		// protoreflect's JSON marshaler encodes bytes as base64 (proto3 default).
		// Accept hex too as a convenience for hand-edited values.
		s, ok := val.(string)
		if !ok {
			return nil, fmt.Errorf("field %s expects bytes as a base64 or hex string", fd.GetName())
		}
		s = strings.TrimSpace(s)
		if b, err := base64.StdEncoding.DecodeString(s); err == nil {
			return b, nil
		}
		if b, err := base64.URLEncoding.DecodeString(s); err == nil {
			return b, nil
		}
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("field %s: not valid base64 or hex", fd.GetName())
		}
		return b, nil
	case descriptorpb.FieldDescriptorProto_TYPE_MESSAGE,
		descriptorpb.FieldDescriptorProto_TYPE_GROUP:
		return nil, fmt.Errorf("message/group fields are not supported for click-to-filter — pick a leaf field")
	}
	return nil, fmt.Errorf("unsupported field type %s", fd.GetType())
}

func toInt64(v interface{}) (int64, error) {
	switch n := v.(type) {
	case float64:
		return int64(n), nil
	case json.Number:
		return n.Int64()
	case string:
		return strconv.ParseInt(strings.TrimSpace(n), 10, 64)
	case int64:
		return n, nil
	case int:
		return int64(n), nil
	}
	return 0, fmt.Errorf("expected number, got %T", v)
}

func toUint64(v interface{}) (uint64, error) {
	switch n := v.(type) {
	case float64:
		if n < 0 {
			return 0, fmt.Errorf("negative value not allowed for unsigned field")
		}
		return uint64(n), nil
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, err
		}
		if i < 0 {
			return 0, fmt.Errorf("negative value not allowed for unsigned field")
		}
		return uint64(i), nil
	case string:
		return strconv.ParseUint(strings.TrimSpace(n), 10, 64)
	case uint64:
		return n, nil
	case int64:
		if n < 0 {
			return 0, fmt.Errorf("negative value not allowed for unsigned field")
		}
		return uint64(n), nil
	}
	return 0, fmt.Errorf("expected non-negative number, got %T", v)
}

func toFloat64(v interface{}) (float64, error) {
	switch n := v.(type) {
	case float64:
		return n, nil
	case json.Number:
		return n.Float64()
	case string:
		return strconv.ParseFloat(strings.TrimSpace(n), 64)
	}
	return 0, fmt.Errorf("expected number, got %T", v)
}

// bytesToFilterEscape produces the inner content of a `raw contains "..."`
// expression: printable ASCII goes through verbatim, everything else becomes
// a `\xHH` byte escape. Mirrors the syntax accepted by the filter parser
// (FILTERS.md: "\xHH" hex byte escape).
func bytesToFilterEscape(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b) * 4)
	for _, c := range b {
		switch {
		case c == '\\' || c == '"':
			sb.WriteByte('\\')
			sb.WriteByte(c)
		case c >= 0x20 && c <= 0x7e:
			sb.WriteByte(c)
		default:
			fmt.Fprintf(&sb, "\\x%02x", c)
		}
	}
	return sb.String()
}
