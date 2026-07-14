// Package customdecode renders raw packet bodies into a structured tree
// using a user-defined Protocol (see storage.CustomProtocol). It is the
// declarative counterpart of internal/protodecode for arbitrary binary
// protocols whose layout is described from the Janus frontend rather than
// from a .proto file.
//
// The decoder walks an ordered list of fields, reads bytes from the body
// incrementally, and emits a JSON-friendly value for each field. On
// truncation or any unexpected condition, the field gets an "error" entry
// and decoding stops gracefully — callers always get a partial tree, never
// a panic.
package customdecode

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"

	"github.com/SimoneErrigo/Janus/backend/internal/storage"
)

// DecodeResult is the JSON-serializable payload returned to the frontend.
// It mirrors the shape of protodecode.DecodeResult so the existing
// collapsible tree renderer can be reused. `Messages` is always non-empty
// and contains one entry per decoded message: live-captured packets
// produce a single message, but PCAP imports often pack many concatenated
// messages from the same TCP direction into a single Janus packet, and
// looping the field list lets us surface them all instead of one message
// plus trailing hex.
type DecodeResult struct {
	Protocol  string           `json:"protocol"`               // protocol name
	Direction string           `json:"direction"`              // "request" | "response"
	Messages  [][]DecodedField `json:"messages"`               // ordered list of decoded messages
	Trailing  string           `json:"trailing_hex,omitempty"` // bytes left over after the last full message
	Error     string           `json:"error,omitempty"`        // last fatal error (if any)
}

// DecodedField is one entry in the tree. `Value` is one of: a primitive
// (string/number/bool), a hex string for byte fields, []DecodedField for
// nested structs, or nil if Error is set.
type DecodedField struct {
	Name  string         `json:"name"`
	Type  string         `json:"type"`
	Value interface{}    `json:"value,omitempty"`
	Hex   string         `json:"hex,omitempty"`  // raw bytes for byte-shaped fields
	Enum  string         `json:"enum,omitempty"` // resolved enum label for numeric fields
	Sub   []DecodedField `json:"sub,omitempty"`  // nested struct fields (dispatch)
	Error string         `json:"error,omitempty"`
}

const (
	maxDecodedMessages = 4 * 1024
	maxDecodedFields   = 16 * 1024
	maxDispatchDepth   = 32
	maxDecodedInput    = 1 << 20
)

type decodeBudget struct {
	fields int
	err    error
}

func (b *decodeBudget) stop(err error) {
	if b.err == nil {
		b.err = err
	}
}

// cursor walks the body buffer, returning typed reads or an error if the
// buffer is too short. It captures endianness once so individual reads
// don't have to.
type cursor struct {
	buf  []byte
	pos  int
	endi storage.Endian
}

func (c *cursor) order() binary.ByteOrder {
	if c.endi == storage.EndianBig {
		return binary.BigEndian
	}
	return binary.LittleEndian
}

func (c *cursor) need(n int) error {
	if c.pos+n > len(c.buf) {
		return fmt.Errorf("truncated: need %d bytes at offset %d, have %d", n, c.pos, len(c.buf)-c.pos)
	}
	return nil
}

func (c *cursor) readU8() (uint8, error) {
	if err := c.need(1); err != nil {
		return 0, err
	}
	v := c.buf[c.pos]
	c.pos++
	return v, nil
}

func (c *cursor) readU16() (uint16, error) {
	if err := c.need(2); err != nil {
		return 0, err
	}
	v := c.order().Uint16(c.buf[c.pos:])
	c.pos += 2
	return v, nil
}

func (c *cursor) readU32() (uint32, error) {
	if err := c.need(4); err != nil {
		return 0, err
	}
	v := c.order().Uint32(c.buf[c.pos:])
	c.pos += 4
	return v, nil
}

func (c *cursor) readU64() (uint64, error) {
	if err := c.need(8); err != nil {
		return 0, err
	}
	v := c.order().Uint64(c.buf[c.pos:])
	c.pos += 8
	return v, nil
}

func (c *cursor) readBytes(n int) ([]byte, error) {
	if n < 0 {
		return nil, fmt.Errorf("negative length %d", n)
	}
	if err := c.need(n); err != nil {
		return nil, err
	}
	out := c.buf[c.pos : c.pos+n]
	c.pos += n
	return out, nil
}

// Decode renders body into a DecodeResult according to the protocol and
// direction. It returns ("request" | "response") fields from the protocol;
// any other direction value falls back to request fields. The decoder
// loops the field list while there are bytes left in the buffer so a
// single packet carrying multiple concatenated messages — as is typical
// for raw TCP services imported from a tcpdump PCAP — is decoded as a
// list of messages rather than a single message followed by hex trailing
// bytes. Live captures usually produce one message per Janus packet, in
// which case this loop just runs once.
func Decode(p *storage.CustomProtocol, direction string, body []byte) *DecodeResult {
	fields := p.RequestFields
	if direction == "response" {
		fields = p.ResponseFields
	}
	omitted := 0
	if len(body) > maxDecodedInput {
		omitted = len(body) - maxDecodedInput
		body = body[:maxDecodedInput]
	}
	c := &cursor{buf: body, endi: p.Endian}

	out := &DecodeResult{
		Protocol:  p.Name,
		Direction: direction,
	}
	if omitted > 0 {
		out.Error = fmt.Sprintf("decode input limited to %d bytes (%d omitted)", maxDecodedInput, omitted)
	}
	budget := &decodeBudget{}
	if len(fields) == 0 {
		// Nothing configured for this direction — surface the body as a
		// single trailing-hex blob so the user sees what's there.
		if len(c.buf) > 0 {
			out.Trailing = hex.EncodeToString(c.buf)
		}
		return out
	}

	for c.pos < len(c.buf) {
		if len(out.Messages) >= maxDecodedMessages {
			budget.stop(fmt.Errorf("decoded message count exceeds %d", maxDecodedMessages))
			break
		}
		startPos := c.pos
		msg := decodeFields(c, fields, p, budget, 0)
		if len(msg) > 0 {
			out.Messages = append(out.Messages, msg)
		}
		if budget.err != nil {
			break
		}
		// Decoded a message that consumed zero bytes (e.g. an empty field
		// list, or every field hit a truncation error on the very first
		// byte). Stop instead of looping forever.
		if c.pos == startPos {
			break
		}
		// If the last field in the message reported an error, decodeFields
		// already returned early — anything left in the buffer is partial
		// and shouldn't be re-parsed as another message.
		if len(msg) > 0 && msg[len(msg)-1].Error != "" {
			break
		}
	}
	if budget.err != nil {
		if out.Error != "" {
			out.Error += "; "
		}
		out.Error += budget.err.Error()
	}
	if len(out.Messages) == 0 {
		// Body was empty: still return one empty message rather than nil so
		// the frontend has something coherent to render.
		out.Messages = append(out.Messages, []DecodedField{})
	}
	if c.pos < len(c.buf) {
		out.Trailing = hex.EncodeToString(c.buf[c.pos:])
	}
	return out
}

// decodeFields walks an ordered field list. `siblings` carries the values
// already decoded *at this level* so dispatch fields can resolve their
// enum-typed source by name.
func decodeFields(c *cursor, fields []storage.ProtocolField, p *storage.CustomProtocol, budget *decodeBudget, depth int) []DecodedField {
	siblings := make(map[string]interface{}, len(fields))
	siblingEnumLabel := make(map[string]string, len(fields))
	out := make([]DecodedField, 0, len(fields))

	for _, f := range fields {
		if budget.fields >= maxDecodedFields {
			budget.stop(fmt.Errorf("decoded field count exceeds %d", maxDecodedFields))
			return out
		}
		budget.fields++
		df := DecodedField{Name: f.Name, Type: string(f.Type)}
		val, label, sub, hexs, err := readField(c, f, p, siblings, siblingEnumLabel, budget, depth)
		df.Value, df.Enum, df.Sub, df.Hex = val, label, sub, hexs
		if err != nil {
			df.Error = err.Error()
			out = append(out, df)
			// Stop processing further fields once we hit a truncation or
			// dispatch failure — every subsequent field would just produce
			// a chain of "truncated" errors. The frontend can still render
			// what we have.
			return out
		}
		// Track sibling values for later dispatch / future cross-field uses.
		siblings[f.Name] = val
		siblingEnumLabel[f.Name] = label
		out = append(out, df)
	}
	return out
}

// readField executes one field's read against the cursor. The return tuple
// is (value, enumLabel, subFields, hex, error).
func readField(c *cursor, f storage.ProtocolField, p *storage.CustomProtocol, siblings map[string]interface{}, siblingLabels map[string]string, budget *decodeBudget, depth int) (interface{}, string, []DecodedField, string, error) {
	switch f.Type {
	case storage.FieldU8:
		v, err := c.readU8()
		if err != nil {
			return nil, "", nil, "", err
		}
		return uint64(v), enumLabel(p, f.EnumRef, uint64(v)), nil, "", nil
	case storage.FieldU16:
		v, err := c.readU16()
		if err != nil {
			return nil, "", nil, "", err
		}
		return uint64(v), enumLabel(p, f.EnumRef, uint64(v)), nil, "", nil
	case storage.FieldU32:
		v, err := c.readU32()
		if err != nil {
			return nil, "", nil, "", err
		}
		return uint64(v), enumLabel(p, f.EnumRef, uint64(v)), nil, "", nil
	case storage.FieldU64:
		v, err := c.readU64()
		if err != nil {
			return nil, "", nil, "", err
		}
		return v, enumLabel(p, f.EnumRef, v), nil, "", nil
	case storage.FieldI8:
		v, err := c.readU8()
		if err != nil {
			return nil, "", nil, "", err
		}
		s := int64(int8(v))
		return s, enumLabel(p, f.EnumRef, uint64(s)), nil, "", nil
	case storage.FieldI16:
		v, err := c.readU16()
		if err != nil {
			return nil, "", nil, "", err
		}
		s := int64(int16(v))
		return s, enumLabel(p, f.EnumRef, uint64(s)), nil, "", nil
	case storage.FieldI32:
		v, err := c.readU32()
		if err != nil {
			return nil, "", nil, "", err
		}
		s := int64(int32(v))
		return s, enumLabel(p, f.EnumRef, uint64(s)), nil, "", nil
	case storage.FieldI64:
		v, err := c.readU64()
		if err != nil {
			return nil, "", nil, "", err
		}
		s := int64(v)
		return s, enumLabel(p, f.EnumRef, uint64(s)), nil, "", nil
	case storage.FieldF32:
		v, err := c.readU32()
		if err != nil {
			return nil, "", nil, "", err
		}
		return float64(math.Float32frombits(v)), "", nil, "", nil
	case storage.FieldF64:
		v, err := c.readU64()
		if err != nil {
			return nil, "", nil, "", err
		}
		return math.Float64frombits(v), "", nil, "", nil
	case storage.FieldBytesFixed:
		b, err := c.readBytes(f.Length)
		if err != nil {
			return nil, "", nil, "", err
		}
		return nil, "", nil, hex.EncodeToString(b), nil
	case storage.FieldStringFixed:
		b, err := c.readBytes(f.Length)
		if err != nil {
			return nil, "", nil, "", err
		}
		return trimNul(string(b)), "", nil, "", nil
	case storage.FieldStringLPU8:
		n, err := c.readU8()
		if err != nil {
			return nil, "", nil, "", err
		}
		b, err := c.readBytes(int(n))
		if err != nil {
			return nil, "", nil, "", err
		}
		return trimNul(string(b)), "", nil, "", nil
	case storage.FieldStringLPU16:
		n, err := c.readU16()
		if err != nil {
			return nil, "", nil, "", err
		}
		b, err := c.readBytes(int(n))
		if err != nil {
			return nil, "", nil, "", err
		}
		return trimNul(string(b)), "", nil, "", nil
	case storage.FieldBytesLPU8:
		n, err := c.readU8()
		if err != nil {
			return nil, "", nil, "", err
		}
		b, err := c.readBytes(int(n))
		if err != nil {
			return nil, "", nil, "", err
		}
		return nil, "", nil, hex.EncodeToString(b), nil
	case storage.FieldBytesLPU16:
		n, err := c.readU16()
		if err != nil {
			return nil, "", nil, "", err
		}
		b, err := c.readBytes(int(n))
		if err != nil {
			return nil, "", nil, "", err
		}
		return nil, "", nil, hex.EncodeToString(b), nil
	case storage.FieldRemaining:
		b := c.buf[c.pos:]
		c.pos = len(c.buf)
		return nil, "", nil, hex.EncodeToString(b), nil
	case storage.FieldBytesComp:
		// Length = ceil(value(length_from) * value(length_mul_from) / length_div).
		// length_mul_from defaults to 1, length_div defaults to 1. Both
		// references must point at numeric fields decoded earlier in the
		// same scope; otherwise we surface a clear error so the protocol
		// editor is forced to fix the wiring instead of decoding garbage.
		if f.LengthFrom == "" {
			return nil, "", nil, "", fmt.Errorf("bytes_computed field %q: length_from is required", f.Name)
		}
		base, err := siblingNumeric(siblings, f.LengthFrom)
		if err != nil {
			return nil, "", nil, "", fmt.Errorf("bytes_computed %q: %w", f.Name, err)
		}
		mult := uint64(1)
		if f.LengthMulFrom != "" {
			m, err := siblingNumeric(siblings, f.LengthMulFrom)
			if err != nil {
				return nil, "", nil, "", fmt.Errorf("bytes_computed %q: %w", f.Name, err)
			}
			mult = m
		}
		div := uint64(1)
		if f.LengthDiv > 0 {
			div = uint64(f.LengthDiv)
		}
		// Ceiling division so dim*dim/8 rounds up the same way the wire
		// format does for bit-packed payloads.
		total := base * mult
		n := (total + div - 1) / div
		if n > uint64(len(c.buf)-c.pos) {
			return nil, "", nil, "", fmt.Errorf("bytes_computed %q: need %d bytes, %d available", f.Name, n, len(c.buf)-c.pos)
		}
		b, err := c.readBytes(int(n))
		if err != nil {
			return nil, "", nil, "", err
		}
		return nil, "", nil, hex.EncodeToString(b), nil
	case storage.FieldDispatch:
		// Resolve the source field's enum label, then look up a matching
		// struct in the protocol. If either is missing, we fall back to a
		// "remaining bytes" sentinel so the user still sees something.
		if f.DispatchOn == "" {
			return nil, "", nil, "", fmt.Errorf("dispatch field %q has no dispatch_on", f.Name)
		}
		label, ok := siblingLabels[f.DispatchOn]
		if !ok || label == "" {
			// Try a stringified numeric fallback (so dispatch can also be
			// done on raw integer values without an enum mapping, by
			// naming a struct "0", "1", ...).
			if v, ok := siblings[f.DispatchOn]; ok {
				label = fmt.Sprintf("%v", v)
			}
		}
		if label == "" {
			return nil, "", nil, "", fmt.Errorf("dispatch field %q: source field %q not found or has no value", f.Name, f.DispatchOn)
		}
		strct, ok := p.Structs[label]
		if !ok {
			// Unknown variant — surface as remaining bytes so the user can
			// see what's there and update the protocol.
			b := c.buf[c.pos:]
			c.pos = len(c.buf)
			return nil, label, nil, hex.EncodeToString(b), nil
		}
		if depth >= maxDispatchDepth {
			err := fmt.Errorf("dispatch nesting exceeds %d", maxDispatchDepth)
			budget.stop(err)
			return nil, label, nil, "", err
		}
		sub := decodeFields(c, strct, p, budget, depth+1)
		if budget.err != nil {
			return nil, label, sub, "", budget.err
		}
		return nil, label, sub, "", nil
	}
	return nil, "", nil, "", fmt.Errorf("unsupported field type %q", f.Type)
}

// enumLabel resolves a numeric value to its label using the protocol's
// enum table. Returns "" when there is no enum reference or no match —
// numeric fields without an enum just render as numbers.
func enumLabel(p *storage.CustomProtocol, enumRef string, v uint64) string {
	if enumRef == "" {
		return ""
	}
	tbl, ok := p.Enums[enumRef]
	if !ok {
		return ""
	}
	if lbl, ok := tbl[strconv.FormatUint(v, 10)]; ok {
		return lbl
	}
	return ""
}

// siblingNumeric returns the value of a previously-decoded sibling field
// as an unsigned integer. Negative signed values are clamped to 0 so the
// length computation can't produce a wraparound. Used by bytes_computed
// to pull its length from one or two earlier fields.
func siblingNumeric(siblings map[string]interface{}, name string) (uint64, error) {
	v, ok := siblings[name]
	if !ok {
		return 0, fmt.Errorf("field %q not found among preceding fields", name)
	}
	switch n := v.(type) {
	case uint64:
		return n, nil
	case int64:
		if n < 0 {
			return 0, nil
		}
		return uint64(n), nil
	case float64:
		if n < 0 {
			return 0, nil
		}
		return uint64(n), nil
	}
	return 0, fmt.Errorf("field %q is not numeric (%T)", name, v)
}

// trimNul drops trailing NUL bytes from fixed-size strings, matching what
// users intuitively expect ("hi\x00\x00\x00" → "hi"). Length-prefixed
// strings normally don't carry padding but the trim is harmless.
func trimNul(s string) string {
	for len(s) > 0 && s[len(s)-1] == 0 {
		s = s[:len(s)-1]
	}
	return s
}
