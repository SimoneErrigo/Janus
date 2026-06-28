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
            return struct.pack('<Q', len(self.board)) + bytes(bs)

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

	// Str struct: single length-prefixed field from `pack('<B', len(x)) + x`.
	str, ok := proto.Structs["Str"]
	if !ok || len(str) != 1 {
		t.Fatalf("Str struct = %v, want one field", str)
	}
	if str[0].Name != "data" || str[0].Type != storage.FieldStringLPU8 {
		t.Errorf("Str field = %+v, want data/string_lp_u8", str[0])
	}

	// Board struct: u64 length has no length-prefixed type, so it becomes a
	// length field + remaining_bytes.
	board, ok := proto.Structs["Board"]
	if !ok {
		t.Fatalf("Board struct not parsed")
	}
	if _, ok := findField(board, "bs_len"); !ok {
		t.Errorf("Board missing bs_len field: %v", fieldNames(board))
	}
	rem, ok := findField(board, "bs")
	if !ok || rem.Type != storage.FieldRemaining {
		t.Errorf("Board bs field = %+v, want remaining_bytes", rem)
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
