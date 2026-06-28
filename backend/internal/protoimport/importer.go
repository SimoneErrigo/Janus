// Package protoimport turns pasted Python source into a draft
// storage.CustomProtocol. It is a convenience layer over the manual protocol
// editor: CTF challenge clients almost always describe their wire format with
// the standard library's `struct` module and `enum.Enum`, and that idiom maps
// directly onto Janus' field types.
//
// The parser never executes the pasted code. It pattern-matches the common
// shapes:
//
//   - `class Foo(Enum): NAME = N`            -> an entry in Enums
//   - `struct.pack('<IBH', self.a, ...)`     -> a struct whose fields come from
//     the format string, named after the packed arguments
//   - `struct.pack('<B', len(x)) + x`        -> a single length-prefixed field
//
// Anything it can't map cleanly (unsupported format chars, `auto()` enums,
// variable-length trailing payloads, reply parsing done with struct.unpack)
// is reported as a warning rather than failing the whole import. The result
// is a draft: RequestFields/ResponseFields are left empty for the user to
// assemble in the editor from the imported enums and structs.
package protoimport

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/SimoneErrigo/Janus/backend/internal/storage"
)

// Parse converts Python source into a draft protocol plus a list of
// human-readable warnings. It returns an error only when there is nothing
// usable to parse at all.
func Parse(code string) (*storage.CustomProtocol, []string, error) {
	if strings.TrimSpace(code) == "" {
		return nil, nil, fmt.Errorf("no code provided")
	}
	lines := strings.Split(code, "\n")
	classes := findClasses(lines)

	var warns []string
	enums := map[string]map[string]string{}
	structs := map[string][]storage.ProtocolField{}
	var endian storage.Endian
	endianSet := false

	// Enums first: each Enum-based class becomes a numeric -> label table.
	for _, cl := range classes {
		if !cl.isEnum {
			continue
		}
		tbl, w := parseEnumBody(cl, lines)
		warns = append(warns, w...)
		if len(tbl) > 0 {
			enums[cl.name] = tbl
		}
	}

	// Structs: every struct.pack(...) line is attributed to its innermost
	// enclosing non-enum class and contributes its fields to that struct.
	for i, line := range lines {
		if !strings.Contains(line, "struct.pack(") {
			continue
		}
		name := "Message"
		if cl := innermostClass(classes, i, indentOf(line)); cl != nil {
			name = cl.name
		}
		fields, e, eSet, w := parseStructLine(line, name)
		warns = append(warns, w...)
		if eSet {
			if !endianSet {
				endian, endianSet = e, true
			} else if e != endian {
				warns = append(warns, fmt.Sprintf("struct %q uses %s-endian but protocol is already %s-endian; keeping %s", name, e, endian, endian))
			}
		}
		if len(fields) > 0 {
			structs[name] = append(structs[name], fields...)
		}
	}

	// struct.unpack is how replies are usually decoded, but in real clients
	// that logic is spread across helper functions (proto_get_u32, ...) and
	// can't be reconstructed mechanically. Flag it so the user knows to fill
	// in the response side by hand.
	for _, line := range lines {
		if strings.Contains(line, "struct.unpack(") {
			warns = append(warns, "struct.unpack detected: response/reply layout was not imported — define response fields manually")
			break
		}
	}

	// Ensure field names are unique within each struct (the decoder and the
	// editor both require it).
	for name, fl := range structs {
		structs[name] = dedupNames(fl)
	}

	if len(enums) == 0 && len(structs) == 0 {
		return nil, warns, fmt.Errorf("no enums or struct.pack definitions found")
	}

	proto := &storage.CustomProtocol{
		Endian:  endian,
		Enums:   enums,
		Structs: structs,
	}
	return proto, warns, nil
}

// classInfo records a `class` header and the line range of its body.
type classInfo struct {
	name   string
	indent int
	start  int // header line index
	end    int // first line index at or below the header indent (exclusive)
	isEnum bool
}

var classHeaderRe = regexp.MustCompile(`^(\s*)class\s+(\w+)\s*(\(([^)]*)\))?\s*:`)

func findClasses(lines []string) []classInfo {
	var out []classInfo
	for i, line := range lines {
		m := classHeaderRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		indent := len(m[1])
		out = append(out, classInfo{
			name:   m[2],
			indent: indent,
			start:  i,
			end:    blockEnd(lines, i, indent),
			isEnum: strings.Contains(m[4], "Enum"),
		})
	}
	return out
}

// blockEnd returns the exclusive end of the block whose header sits at
// headerIdx/indent: the first later non-blank line indented at or below the
// header.
func blockEnd(lines []string, headerIdx, indent int) int {
	for j := headerIdx + 1; j < len(lines); j++ {
		if strings.TrimSpace(lines[j]) == "" {
			continue
		}
		if indentOf(lines[j]) <= indent {
			return j
		}
	}
	return len(lines)
}

func indentOf(line string) int {
	n := 0
	for _, r := range line {
		switch r {
		case ' ':
			n++
		case '\t':
			n += 4
		default:
			return n
		}
	}
	return n
}

// innermostClass returns the deepest-nested non-enum class whose body covers
// lineIdx and whose header is less indented than the line itself.
func innermostClass(classes []classInfo, lineIdx, lineIndent int) *classInfo {
	var best *classInfo
	for i := range classes {
		c := &classes[i]
		if c.isEnum || lineIdx <= c.start || lineIdx >= c.end || c.indent >= lineIndent {
			continue
		}
		if best == nil || c.indent > best.indent {
			best = c
		}
	}
	return best
}

var enumMemberRe = regexp.MustCompile(`^\s*([A-Za-z_]\w*)\s*=\s*(.+?)\s*(?:#.*)?$`)

// parseEnumBody reads `NAME = value` members from an Enum class body.
func parseEnumBody(cl classInfo, lines []string) (map[string]string, []string) {
	tbl := map[string]string{}
	var warns []string
	next := 1 // Python's enum.auto() starts at 1
	for j := cl.start + 1; j < cl.end; j++ {
		trimmed := strings.TrimSpace(lines[j])
		if trimmed == "" || strings.HasPrefix(trimmed, "def ") ||
			strings.HasPrefix(trimmed, "class ") || strings.HasPrefix(trimmed, "@") {
			continue
		}
		m := enumMemberRe.FindStringSubmatch(lines[j])
		if m == nil {
			continue
		}
		member := m[1]
		if strings.HasPrefix(member, "__") {
			continue // dunder / config attribute, not a real member
		}
		val, ok := parseEnumValue(strings.TrimSpace(m[2]), &next)
		if !ok {
			warns = append(warns, fmt.Sprintf("enum %s.%s: value %q not understood, skipped", cl.name, member, strings.TrimSpace(m[2])))
			continue
		}
		tbl[strconv.Itoa(val)] = member
	}
	return tbl, warns
}

// parseEnumValue understands decimal/hex integer literals and `auto()`,
// advancing *next so a run of auto() members increments like Python's.
func parseEnumValue(expr string, next *int) (int, bool) {
	if expr == "auto()" || expr == "enum.auto()" {
		v := *next
		*next = v + 1
		return v, true
	}
	s := expr
	neg := false
	if strings.HasPrefix(s, "-") {
		neg, s = true, s[1:]
	}
	base := 10
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		base, s = 16, s[2:]
	}
	v64, err := strconv.ParseInt(s, base, 64)
	if err != nil {
		return 0, false
	}
	v := int(v64)
	if neg {
		v = -v
	}
	*next = v + 1
	return v, true
}

// formatSpec is one element produced by expanding a struct format string.
type formatSpec struct {
	ftype       storage.FieldType
	length      int    // bytes_fixed / string_fixed
	consumesArg bool   // pad bytes ('x') don't consume a pack argument
	defaultName string // used when no argument name is available
}

// parseStructLine turns a single line containing struct.pack(...) into fields.
func parseStructLine(line, structName string) ([]storage.ProtocolField, storage.Endian, bool, []string) {
	expr := stripComment(line)
	if idx := strings.Index(expr, "return "); idx >= 0 {
		expr = expr[idx+len("return "):]
	}
	expr = strings.TrimSpace(expr)

	var fields []storage.ProtocolField
	var warns []string
	var endian storage.Endian
	endianSet := false

	terms := splitTopLevel(expr, '+')
	for i := 0; i < len(terms); i++ {
		term := strings.TrimSpace(terms[i])
		if !strings.Contains(term, "struct.pack(") {
			// Bare trailing payload (e.g. `+ self.data`) without a length
			// prefix: best we can do is a remaining-bytes field.
			name := argName(term)
			if name == "" {
				name = "payload"
			}
			fields = append(fields, storage.ProtocolField{Name: name, Type: storage.FieldRemaining})
			warns = append(warns, fmt.Sprintf("struct %q: term %q is variable-length; imported %q as remaining_bytes — consider bytes_computed", structName, term, name))
			continue
		}

		specs, args, e, eSet, w := parsePack(term)
		warns = append(warns, w...)
		if eSet && !endianSet {
			endian, endianSet = e, true
		}

		// Length-prefix idiom: struct.pack('<B'|'<H', len(x)) followed by the
		// payload term x. Collapse the two into one length-prefixed field.
		if len(specs) == 1 && isIntType(specs[0].ftype) && len(args) == 1 &&
			isLenCall(args[0]) && i+1 < len(terms) &&
			!strings.Contains(terms[i+1], "struct.pack(") {
			payload := strings.TrimSpace(terms[i+1])
			pname := argName(payload)
			if pname == "" {
				pname = "payload"
			}
			if lp, ok := lpStringType(specs[0].ftype); ok {
				fields = append(fields, storage.ProtocolField{Name: pname, Type: lp})
				warns = append(warns, fmt.Sprintf("struct %q: field %q imported as %s; switch to a bytes_lp_* type if the payload is binary", structName, pname, lp))
			} else {
				// No length-prefixed type wider than 16 bits exists.
				fields = append(fields,
					storage.ProtocolField{Name: pname + "_len", Type: specs[0].ftype},
					storage.ProtocolField{Name: pname, Type: storage.FieldRemaining},
				)
				warns = append(warns, fmt.Sprintf("struct %q: %s length prefix has no built-in length-prefixed type; imported %q as a length field + remaining_bytes — consider bytes_computed", structName, specs[0].ftype, pname))
			}
			i++ // consumed the payload term too
			continue
		}

		fs := emitSpecs(specs, args)
		fields = append(fields, fs...)
	}
	return fields, endian, endianSet, warns
}

// parsePack extracts the format string and argument expressions from a single
// struct.pack(...) call and expands the format into specs.
func parsePack(term string) ([]formatSpec, []string, storage.Endian, bool, []string) {
	inside, ok := callArgs(term, "struct.pack")
	if !ok {
		return nil, nil, "", false, []string{fmt.Sprintf("could not parse struct.pack in %q", term)}
	}
	parts := splitTopLevel(inside, ',')
	if len(parts) == 0 {
		return nil, nil, "", false, []string{"empty struct.pack"}
	}
	fmtStr, ok := stringLiteral(parts[0])
	if !ok {
		return nil, nil, "", false, []string{fmt.Sprintf("struct.pack format is not a string literal: %s", strings.TrimSpace(parts[0]))}
	}
	endian, endianSet, specs, warns := expandFormat(fmtStr)
	return specs, trimAll(parts[1:]), endian, endianSet, warns
}

// emitSpecs pairs each arg-consuming spec with the next packed argument name.
func emitSpecs(specs []formatSpec, args []string) []storage.ProtocolField {
	out := make([]storage.ProtocolField, 0, len(specs))
	ai := 0
	for _, sp := range specs {
		name := ""
		if sp.consumesArg && ai < len(args) {
			name = argName(args[ai])
			ai++
		}
		if name == "" {
			if sp.defaultName != "" {
				name = sp.defaultName
			} else {
				name = fmt.Sprintf("field%d", len(out)+1)
			}
		}
		f := storage.ProtocolField{Name: name, Type: sp.ftype}
		if sp.length > 0 {
			f.Length = sp.length
		}
		out = append(out, f)
	}
	return out
}

// expandFormat walks a struct format string, returning the byte order (if a
// prefix specified one) and one spec per produced field.
func expandFormat(f string) (storage.Endian, bool, []formatSpec, []string) {
	var specs []formatSpec
	var warns []string
	var endian storage.Endian
	endianSet := false

	for i := 0; i < len(f); {
		switch f[i] {
		case '<', '=', '@':
			endian, endianSet = storage.EndianLittle, true
			i++
			continue
		case '>', '!':
			endian, endianSet = storage.EndianBig, true
			i++
			continue
		case ' ':
			i++
			continue
		}
		count, hasCount := 0, false
		for i < len(f) && f[i] >= '0' && f[i] <= '9' {
			count = count*10 + int(f[i]-'0')
			hasCount = true
			i++
		}
		if i >= len(f) {
			break
		}
		t := f[i]
		i++
		if !hasCount {
			count = 1
		}
		switch t {
		case 'x':
			specs = append(specs, formatSpec{ftype: storage.FieldBytesFixed, length: count, defaultName: "pad"})
		case 's':
			specs = append(specs, formatSpec{ftype: storage.FieldStringFixed, length: count, consumesArg: true})
		case 'p':
			specs = append(specs, formatSpec{ftype: storage.FieldBytesFixed, length: count, consumesArg: true, defaultName: "pstr"})
			warns = append(warns, "format 'p' (Pascal string) imported as bytes_fixed")
		case 'c':
			for k := 0; k < count; k++ {
				specs = append(specs, formatSpec{ftype: storage.FieldBytesFixed, length: 1, consumesArg: true})
			}
		case 'e':
			for k := 0; k < count; k++ {
				specs = append(specs, formatSpec{ftype: storage.FieldBytesFixed, length: 2, consumesArg: true})
			}
			warns = append(warns, "format 'e' (float16) imported as 2 raw bytes (no native f16 type)")
		default:
			ft, ok := mapType(t)
			if !ok {
				warns = append(warns, fmt.Sprintf("unsupported struct format char %q, skipped", string(t)))
				continue
			}
			for k := 0; k < count; k++ {
				specs = append(specs, formatSpec{ftype: ft, consumesArg: true})
			}
		}
	}
	return endian, endianSet, specs, warns
}

func mapType(c byte) (storage.FieldType, bool) {
	switch c {
	case 'b':
		return storage.FieldI8, true
	case 'B', '?':
		return storage.FieldU8, true
	case 'h':
		return storage.FieldI16, true
	case 'H':
		return storage.FieldU16, true
	case 'i', 'l':
		return storage.FieldI32, true
	case 'I', 'L':
		return storage.FieldU32, true
	case 'q', 'n':
		return storage.FieldI64, true
	case 'Q', 'N', 'P':
		return storage.FieldU64, true
	case 'f':
		return storage.FieldF32, true
	case 'd':
		return storage.FieldF64, true
	}
	return "", false
}

// --- small expression helpers -------------------------------------------------

var identRe = regexp.MustCompile(`[A-Za-z_]\w*`)
var wrapperCallRe = regexp.MustCompile(`^(?:len|bytes|bytearray|int|str|struct\.pack|struct\.unpack)\s*\((.*)\)\s*$`)

// argName extracts a sensible field name from a packed argument expression:
// `self.ts` -> "ts", `self.type.value` -> "type", `len(self.data)` -> "data",
// `bytes(bs)` -> "bs". Returns "" when nothing usable is found.
func argName(expr string) string {
	s := strings.TrimSpace(expr)
	for {
		m := wrapperCallRe.FindStringSubmatch(s)
		if m == nil {
			break
		}
		s = strings.TrimSpace(m[1])
	}
	toks := identRe.FindAllString(s, -1)
	for i := len(toks) - 1; i >= 0; i-- {
		switch toks[i] {
		case "self", "value", "encode", "decode":
			continue
		}
		return toks[i]
	}
	return ""
}

func isLenCall(expr string) bool {
	return strings.HasPrefix(strings.TrimSpace(expr), "len(")
}

func isIntType(ft storage.FieldType) bool {
	switch ft {
	case storage.FieldU8, storage.FieldU16, storage.FieldU32, storage.FieldU64,
		storage.FieldI8, storage.FieldI16, storage.FieldI32, storage.FieldI64:
		return true
	}
	return false
}

func lpStringType(ft storage.FieldType) (storage.FieldType, bool) {
	switch ft {
	case storage.FieldU8, storage.FieldI8:
		return storage.FieldStringLPU8, true
	case storage.FieldU16, storage.FieldI16:
		return storage.FieldStringLPU16, true
	}
	return "", false
}

// stripComment removes a trailing `# ...` comment that is not inside a string
// literal.
func stripComment(line string) string {
	var inStr byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		if inStr != 0 {
			if c == inStr && (i == 0 || line[i-1] != '\\') {
				inStr = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			inStr = c
		case '#':
			return line[:i]
		}
	}
	return line
}

// callArgs returns the substring between the parentheses of the first `fn(`
// call in s, respecting nested brackets and string literals.
func callArgs(s, fn string) (string, bool) {
	idx := strings.Index(s, fn+"(")
	if idx < 0 {
		return "", false
	}
	start := idx + len(fn) + 1
	depth := 1
	var inStr byte
	for i := start; i < len(s); i++ {
		c := s[i]
		if inStr != 0 {
			if c == inStr && s[i-1] != '\\' {
				inStr = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			inStr = c
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth == 0 {
				return s[start:i], true
			}
		}
	}
	return "", false
}

// splitTopLevel splits s on sep, ignoring separators inside brackets or string
// literals.
func splitTopLevel(s string, sep byte) []string {
	var out []string
	depth := 0
	var inStr byte
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inStr != 0 {
			if c == inStr && s[i-1] != '\\' {
				inStr = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			inStr = c
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case sep:
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, s[start:])
	return out
}

// stringLiteral unwraps a (possibly prefixed) Python string literal.
func stringLiteral(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		q := s[0]
		if (q == '\'' || q == '"') && s[len(s)-1] == q {
			return s[1 : len(s)-1], true
		}
	}
	// b'...', r'...', f'...' prefixes
	if len(s) >= 1 {
		switch s[0] {
		case 'b', 'B', 'r', 'R', 'f', 'F':
			return stringLiteral(s[1:])
		}
	}
	return "", false
}

func trimAll(parts []string) []string {
	out := make([]string, len(parts))
	for i, p := range parts {
		out[i] = strings.TrimSpace(p)
	}
	return out
}

// dedupNames makes field names unique within a struct by suffixing collisions.
func dedupNames(fields []storage.ProtocolField) []storage.ProtocolField {
	seen := map[string]int{}
	for i := range fields {
		name := fields[i].Name
		if name == "" {
			name = fmt.Sprintf("field%d", i+1)
		}
		if n, ok := seen[name]; ok {
			seen[name] = n + 1
			name = fmt.Sprintf("%s_%d", name, n+1)
		} else {
			seen[name] = 1
		}
		fields[i].Name = name
	}
	return fields
}
