package protoimport

import (
	"testing"

	"github.com/SimoneErrigo/Janus/backend/internal/storage"
)

// sampleClient is the real Minesweeper-style challenge client from the brief,
// trimmed to the parts the importer is expected to understand.
const sampleClient = `
import time
import struct

from enum import Enum

class Network():

    class ReqType(Enum):
        SIGNUP = 0
        LOGIN = 1
        CREATE_BOARD = 2
        LOAD_BOARD = 3
        PLAY = 4
        UNCOVER = 5
        CHECK_WIN = 6
        QUIT = 7

    class ReqHdr():
        def __init__(self, type, len):
            self.ts = int(time.time())
            self.type = type.value
            self.len = len

        @property
        def bytes(self):
            return struct.pack('<IBH', self.ts, self.type, self.len)

    class Str():
        def __init__(self, data):
            self.data = data if isinstance(data, bytes) else data.encode()

        @property
        def bytes(self):
            return struct.pack('<B', len(self.data)) + self.data

    class Board():
        def __init__(self, board):
            self.board = board

        @property
        def bytes(self):
            cells = [cell for row in self.board for cell in row]
            bs = [0] * ((len(cells) + 7) // 8)
            for i, cell in enumerate(cells):
                if cell == Marker.FLAG:
                    bs[i // 8] |= 1 << (i % 8)
            return struct.pack('<Q', len(self.board)) + bytes(bs)

    @staticmethod
    def net_send_req(conn, type, data):
        hdr = Network.ReqHdr(type, len(data))
        req = hdr.bytes + data
        conn.sendall(req)

    @staticmethod
    def proto_get_u8(conn):
        return struct.unpack('<B', Network.recv(conn, 1))[0]
`

func fieldNames(fields []storage.ProtocolField) []string {
	out := make([]string, len(fields))
	for i, f := range fields {
		out[i] = f.Name
	}
	return out
}

func findField(fields []storage.ProtocolField, name string) (storage.ProtocolField, bool) {
	for _, f := range fields {
		if f.Name == name {
			return f, true
		}
	}
	return storage.ProtocolField{}, false
}

func TestParseSampleClient(t *testing.T) {
	proto, _, err := Parse(sampleClient)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	// Endianness comes from the '<' prefix.
	if proto.Endian != storage.EndianLittle {
		t.Errorf("endian = %q, want little", proto.Endian)
	}

	// Enum.
	rt, ok := proto.Enums["ReqType"]
	if !ok {
		t.Fatalf("ReqType enum not parsed; enums = %v", proto.Enums)
	}
	if rt["0"] != "SIGNUP" || rt["7"] != "QUIT" || rt["4"] != "PLAY" {
		t.Errorf("ReqType mapping wrong: %v", rt)
	}
	if len(rt) != 8 {
		t.Errorf("ReqType has %d entries, want 8", len(rt))
	}

	// ReqHdr struct: ts:u32, type:u8, len:u16.
	hdr, ok := proto.Structs["ReqHdr"]
	if !ok {
		t.Fatalf("ReqHdr struct not parsed; structs = %v", proto.Structs)
	}
	wantNames := []string{"ts", "type", "len"}
	if got := fieldNames(hdr); !equalStrings(got, wantNames) {
		t.Fatalf("ReqHdr field names = %v, want %v", got, wantNames)
	}
	wantTypes := []storage.FieldType{storage.FieldU32, storage.FieldU8, storage.FieldU16}
	for i, wt := range wantTypes {
		if hdr[i].Type != wt {
			t.Errorf("ReqHdr[%d] type = %q, want %q", i, hdr[i].Type, wt)
		}
	}
	// `self.type = type.value` links the type field to the sole enum.
	if typeField, ok := findField(hdr, "type"); !ok || typeField.EnumRef != "ReqType" {
		t.Errorf("ReqHdr type field = %+v, want enum_ref ReqType", typeField)
	}

	// Str struct: single length-prefixed field from `pack('<B', len(x)) + x`.
	str, ok := proto.Structs["Str"]
	if !ok || len(str) != 1 {
		t.Fatalf("Str struct = %v, want one field", str)
	}
	if str[0].Name != "data" || str[0].Type != storage.FieldStringLPU8 {
		t.Errorf("Str field = %+v, want data/string_lp_u8", str[0])
	}

	// Board struct: the u64 dimension prefix followed by the bit-packed cells,
	// imported as board:u64 + bs:bytes_computed(board × board ÷ 8).
	board, ok := proto.Structs["Board"]
	if !ok {
		t.Fatalf("Board struct not parsed")
	}
	dim, ok := findField(board, "board")
	if !ok || dim.Type != storage.FieldU64 {
		t.Errorf("Board dimension field = %+v, want board/u64", dim)
	}
	cells, ok := findField(board, "bs")
	if !ok || cells.Type != storage.FieldBytesComp {
		t.Fatalf("Board bs field = %+v, want bytes_computed", cells)
	}
	if cells.LengthFrom != "board" || cells.LengthMulFrom != "board" || cells.LengthDiv != 8 {
		t.Errorf("Board bs geometry = from %q mul %q div %d, want board/board/8",
			cells.LengthFrom, cells.LengthMulFrom, cells.LengthDiv)
	}

	// Request auto-wiring: header fields + dispatch on the enum-typed field.
	if len(proto.RequestFields) == 0 {
		t.Fatalf("RequestFields not auto-wired")
	}
	last := proto.RequestFields[len(proto.RequestFields)-1]
	if last.Type != storage.FieldDispatch || last.DispatchOn != "type" {
		t.Errorf("request dispatch field = %+v, want dispatch on 'type'", last)
	}
	if got := fieldNames(proto.RequestFields); !equalStrings(got, []string{"ts", "type", "len", "body"}) {
		t.Errorf("RequestFields = %v, want ts/type/len/body", got)
	}
}

// TestParseBoardOnly checks the user-facing "paste just the Board class" flow:
// the bit-packing custom logic is captured without any surrounding context.
func TestParseBoardOnly(t *testing.T) {
	code := `
class Board():
    def __init__(self, board):
        self.board = board

    def bytes(self):
        cells = [cell for row in self.board for cell in row]
        bs = [0] * ((len(cells) + 7) // 8)
        for i, cell in enumerate(cells):
            if cell == Marker.FLAG:
                bs[i // 8] |= 1 << (i % 8)
        return struct.pack('<Q', len(self.board)) + bytes(bs)
`
	proto, _, err := Parse(code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	board, ok := proto.Structs["Board"]
	if !ok || len(board) != 2 {
		t.Fatalf("Board struct = %v, want two fields", board)
	}
	if board[0].Name != "board" || board[0].Type != storage.FieldU64 {
		t.Errorf("Board[0] = %+v, want board/u64", board[0])
	}
	if board[1].Type != storage.FieldBytesComp || board[1].LengthMulFrom != "board" || board[1].LengthDiv != 8 {
		t.Errorf("Board[1] = %+v, want bytes_computed board×board÷8", board[1])
	}
}

// TestParseEnumOnly checks the other user-facing flow: pasting just an Enum
// class sets up the enum table with no structs required.
func TestParseEnumOnly(t *testing.T) {
	code := `
class ReqType(Enum):
    SIGNUP = 0
    LOGIN = 1
    CREATE_BOARD = 2
    QUIT = 7
`
	proto, _, err := Parse(code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	rt := proto.Enums["ReqType"]
	if rt["0"] != "SIGNUP" || rt["7"] != "QUIT" || len(rt) != 4 {
		t.Errorf("ReqType = %v, want 4 entries incl SIGNUP/QUIT", rt)
	}
}

// TestNoDecorators verifies the parser doesn't depend on @property /
// @staticmethod: the same class without decorators imports identically.
func TestNoDecorators(t *testing.T) {
	code := `
class ReqHdr():
    def __init__(self, type, len):
        self.ts = int(time.time())
        self.type = type.value
        self.len = len

    def bytes(self):
        return struct.pack('<IBH', self.ts, self.type, self.len)

class ReqType(Enum):
    SIGNUP = 0
    LOGIN = 1
`
	proto, _, err := Parse(code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	hdr, ok := proto.Structs["ReqHdr"]
	if !ok {
		t.Fatalf("ReqHdr not parsed without decorators")
	}
	if got := fieldNames(hdr); !equalStrings(got, []string{"ts", "type", "len"}) {
		t.Errorf("ReqHdr fields = %v, want ts/type/len", got)
	}
	if tf, _ := findField(hdr, "type"); tf.EnumRef != "ReqType" {
		t.Errorf("type field enum_ref = %q, want ReqType", tf.EnumRef)
	}
}

func TestParseUnpackWarning(t *testing.T) {
	_, warns, err := Parse(sampleClient)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if !containsSubstr(warns, "struct.unpack detected") {
		t.Errorf("expected struct.unpack warning, got %v", warns)
	}
}

// TestDirectValueAndInlineLength covers two variations common in other clients:
// the enum value is packed directly (`op.value`, no intermediate attribute) and
// the payload length lives inside a multi-field pack rather than its own prefix.
func TestDirectValueAndInlineLength(t *testing.T) {
	code := `
class Op(Enum):
    PING = 0
    PONG = 1

class Msg():
    def bytes(self):
        return struct.pack('<BH', self.op.value, len(self.payload)) + self.payload
`
	proto, _, err := Parse(code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	msg := proto.Structs["Msg"]
	if got := fieldNames(msg); !equalStrings(got, []string{"op", "payload_len", "payload"}) {
		t.Fatalf("Msg fields = %v, want op/payload_len/payload", got)
	}
	if msg[0].EnumRef != "Op" {
		t.Errorf("op enum_ref = %q, want Op (direct .value not linked)", msg[0].EnumRef)
	}
	if msg[2].Type != storage.FieldBytesComp || msg[2].LengthFrom != "payload_len" {
		t.Errorf("payload = %+v, want bytes_computed from payload_len", msg[2])
	}
}

// TestBytearrayBitBuffer checks the bit-packed grid idiom is recognized when
// the buffer is built with bytearray(...) instead of [0] * (...).
func TestBytearrayBitBuffer(t *testing.T) {
	code := `
class Grid():
    def __init__(self, board):
        self.board = board
    def bytes(self):
        cells = [c for row in self.board for c in row]
        buf = bytearray((len(cells) + 7) // 8)
        return struct.pack('<Q', len(self.board)) + bytes(buf)
`
	proto, _, err := Parse(code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	g := proto.Structs["Grid"]
	if len(g) != 2 || g[0].Name != "board" || g[0].Type != storage.FieldU64 {
		t.Fatalf("Grid[0] = %+v, want board/u64", g)
	}
	if g[1].Type != storage.FieldBytesComp || g[1].LengthFrom != "board" || g[1].LengthMulFrom != "board" || g[1].LengthDiv != 8 {
		t.Errorf("Grid[1] = %+v, want bytes_computed board×board÷8", g[1])
	}
}

// TestNumericLiteralField ensures a magic-number field doesn't get a garbage
// name derived from the hex literal.
func TestNumericLiteralField(t *testing.T) {
	code := `
class Packet():
    def bytes(self):
        return struct.pack('>IH', 0xdeadbeef, len(self.name)) + self.name
`
	proto, _, err := Parse(code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if proto.Endian != storage.EndianBig {
		t.Errorf("endian = %q, want big", proto.Endian)
	}
	p := proto.Structs["Packet"]
	if p[0].Name != "field1" || p[0].Type != storage.FieldU32 {
		t.Errorf("magic field = %+v, want field1/u32 (no garbage name)", p[0])
	}
	if got := fieldNames(p); !equalStrings(got, []string{"field1", "name_len", "name"}) {
		t.Errorf("Packet fields = %v, want field1/name_len/name", got)
	}
}

// TestOneDimBitBuffer checks a linear (non-grid) bit-packed payload keeps the
// prefix count without a spurious ×multiplier.
func TestOneDimBitBuffer(t *testing.T) {
	code := `
class Flags():
    def __init__(self, bits):
        self.bits = bits
    def bytes(self):
        packed = [0] * ((len(self.bits) + 7) // 8)
        return struct.pack('<H', len(self.bits)) + bytes(packed)
`
	proto, warns, err := Parse(code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	f := proto.Structs["Flags"]
	if len(f) != 2 || f[0].Name != "bits" || f[0].Type != storage.FieldU16 {
		t.Fatalf("Flags[0] = %+v, want bits/u16", f)
	}
	comp := f[1]
	if comp.Type != storage.FieldBytesComp || comp.LengthFrom != "bits" || comp.LengthDiv != 8 || comp.LengthMulFrom != "" {
		t.Errorf("Flags[1] = %+v, want bytes_computed from bits ÷8 (no multiplier)", comp)
	}
	for _, w := range warns {
		if containsSubstr([]string{w}, "check the multiplier") || containsSubstr([]string{w}, "set the ×multiplier") {
			t.Errorf("unexpected multiplier warning for 1-D buffer: %q", w)
		}
	}
}

func TestExpandFormatTypes(t *testing.T) {
	endian, set, specs, warns := expandFormat("<bBhHiIqQfd")
	if !set || endian != storage.EndianLittle {
		t.Fatalf("endian set=%v val=%q", set, endian)
	}
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %v", warns)
	}
	want := []storage.FieldType{
		storage.FieldI8, storage.FieldU8, storage.FieldI16, storage.FieldU16,
		storage.FieldI32, storage.FieldU32, storage.FieldI64, storage.FieldU64,
		storage.FieldF32, storage.FieldF64,
	}
	if len(specs) != len(want) {
		t.Fatalf("got %d specs, want %d", len(specs), len(want))
	}
	for i, wt := range want {
		if specs[i].ftype != wt {
			t.Errorf("specs[%d] = %q, want %q", i, specs[i].ftype, wt)
		}
	}
}

func TestExpandFormatBigEndianAndCounts(t *testing.T) {
	endian, set, specs, _ := expandFormat(">4s8B16x")
	if !set || endian != storage.EndianBig {
		t.Fatalf("endian set=%v val=%q", set, endian)
	}
	// 4s -> one 4-byte string; 8B -> eight u8; 16x -> one 16-byte pad.
	if len(specs) != 1+8+1 {
		t.Fatalf("got %d specs, want 10", len(specs))
	}
	if specs[0].ftype != storage.FieldStringFixed || specs[0].length != 4 {
		t.Errorf("specs[0] = %+v, want string_fixed len 4", specs[0])
	}
	for i := 1; i <= 8; i++ {
		if specs[i].ftype != storage.FieldU8 {
			t.Errorf("specs[%d] = %q, want u8", i, specs[i].ftype)
		}
	}
	pad := specs[9]
	if pad.ftype != storage.FieldBytesFixed || pad.length != 16 || pad.consumesArg {
		t.Errorf("pad spec = %+v, want 16-byte non-consuming bytes_fixed", pad)
	}
}

func TestExpandFormatUnsupportedChar(t *testing.T) {
	_, _, specs, warns := expandFormat("<BzB")
	if len(specs) != 2 {
		t.Errorf("got %d specs, want 2 (z skipped)", len(specs))
	}
	if !containsSubstr(warns, "unsupported struct format char") {
		t.Errorf("expected unsupported-char warning, got %v", warns)
	}
}

func TestParseEnumValueAutoAndHex(t *testing.T) {
	code := `
class Flags(Enum):
    A = 0x01
    B = 0x02
    C = auto()
    D = auto()
`
	proto, _, err := Parse(code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	f := proto.Enums["Flags"]
	if f["1"] != "A" || f["2"] != "B" {
		t.Errorf("hex enum values wrong: %v", f)
	}
	// auto() continues from last explicit (2) -> 3, 4.
	if f["3"] != "C" || f["4"] != "D" {
		t.Errorf("auto() enum values wrong: %v", f)
	}
}

func TestArgName(t *testing.T) {
	cases := map[string]string{
		"self.ts":            "ts",
		"self.type.value":    "type",
		"len(self.data)":     "data",
		"bytes(bs)":          "bs",
		"self.len":           "len",
		"self.data.encode()": "data",
		"int(time.time())":   "time", // best effort
	}
	for in, want := range cases {
		if got := argName(in); got != want {
			t.Errorf("argName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseEmpty(t *testing.T) {
	if _, _, err := Parse("   \n  "); err == nil {
		t.Errorf("expected error for empty input")
	}
	if _, _, err := Parse("x = 1\nprint(x)\n"); err == nil {
		t.Errorf("expected error when nothing parseable")
	}
}

func equalStrings(a, b []string) bool {
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

func containsSubstr(warns []string, sub string) bool {
	for _, w := range warns {
		if len(w) >= len(sub) && (w == sub || contains(w, sub)) {
			return true
		}
	}
	return false
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
