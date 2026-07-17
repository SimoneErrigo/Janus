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
	enumFieldOf := map[string]string{} // struct name -> its enum-typed field (for dispatch)
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
	// With exactly one enum we can safely attach it to fields packed from a
	// `.value` attribute; with several we can't tell which one applies.
	soleEnum := ""
	if len(enums) == 1 {
		for n := range enums {
			soleEnum = n
		}
	}

	// One struct per non-enum class, parsed with the class's local-variable
	// context so custom payload-building logic (bit-packed grids,
	// length-prefixed blobs) maps onto a field instead of being dropped.
	for ci, cl := range classes {
		if cl.isEnum {
			continue
		}
		fields, e, eSet, enumField, w := parseClassStruct(classes, ci, lines, soleEnum)
		warns = append(warns, w...)
		if eSet {
			if !endianSet {
				endian, endianSet = e, true
			} else if e != endian {
				warns = append(warns, fmt.Sprintf("struct %q uses %s-endian but protocol is already %s-endian; keeping %s", cl.name, e, endian, endian))
			}
		}
		if len(fields) > 0 {
			structs[cl.name] = append(structs[cl.name], fields...)
			if enumField != "" {
				enumFieldOf[cl.name] = enumField
			}
		}
	}

	// struct.pack lines outside any class become a single "Message" struct so
	// pasting a bare packing expression still yields something.
	for i, line := range lines {
		if !strings.Contains(line, "struct.pack(") || insideAnyClass(classes, i) {
			continue
		}
		fields, e, eSet, w := parseBytesLine(line, "Message", nil, nil, soleEnum)
		warns = append(warns, w...)
		if eSet && !endianSet {
			endian, endianSet = e, true
		}
		if len(fields) > 0 {
			structs["Message"] = append(structs["Message"], fields...)
		}
	}

	// Replies are usually decoded with struct.unpack spread across helper
	// functions and conditionals; that control flow can't be reconstructed
	// mechanically, so point the user at the Response tab.
	for _, line := range lines {
		if strings.Contains(line, "struct.unpack(") {
			warns = append(warns, "struct.unpack detected: response layout wasn't imported automatically — wire Response fields in the editor (the imported structs are there to copy from)")
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

	// Request auto-wiring: many clients prepend a header struct to every
	// request body (the `hdr.bytes + data` idiom). When we can see that, lay
	// the request out as the header fields followed by a dispatch on the
	// header's enum field so the paste decodes immediately.
	if req, w := buildRequestFields(lines, structs, enumFieldOf); req != nil {
		proto.RequestFields = req
		warns = append(warns, w...)
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

// insideAnyClass reports whether line lineIdx falls within any class body.
func insideAnyClass(classes []classInfo, lineIdx int) bool {
	for _, c := range classes {
		if lineIdx > c.start && lineIdx < c.end {
			return true
		}
	}
	return false
}

// ownBodyLines returns the line indices that belong directly to class ci —
// inside its body but not inside any more-deeply-nested class. This lets us
// treat each class as its own struct without the outer class swallowing the
// struct.pack lines of the classes nested in it.
func ownBodyLines(classes []classInfo, ci int) []int {
	c := classes[ci]
	var out []int
	for j := c.start + 1; j < c.end; j++ {
		nested := false
		for k := range classes {
			if k == ci {
				continue
			}
			d := classes[k]
			if d.start > c.start && d.end <= c.end && j >= d.start && j < d.end {
				nested = true // j lives in a class nested inside c
				break
			}
		}
		if !nested {
			out = append(out, j)
		}
	}
	return out
}

var selfAssignRe = regexp.MustCompile(`^\s*self\.(\w+)\s*=\s*(.+)$`)
var localVarRe = regexp.MustCompile(`^\s*([A-Za-z_]\w*)\s*=\s*(.+)$`)

// parseClassStruct turns one non-enum class into a struct. It first scans the
// class body for `self.x = ...` assignments (to spot enum-typed attributes)
// and plain `name = ...` locals (so payload-building logic can be resolved),
// then expands every struct.pack line in the class into fields. The returned
// enumField, if any, is the field the request dispatch should key on.
func parseClassStruct(classes []classInfo, ci int, lines []string, soleEnum string) ([]storage.ProtocolField, storage.Endian, bool, string, []string) {
	own := ownBodyLines(classes, ci)

	enumAttrs := map[string]bool{}
	localVars := map[string]string{}
	for _, j := range own {
		line := stripComment(lines[j])
		if m := selfAssignRe.FindStringSubmatch(line); m != nil {
			// `self.type = type.value` marks `type` as carrying an enum value.
			if strings.Contains(m[2], ".value") {
				enumAttrs[m[1]] = true
			}
			continue
		}
		if m := localVarRe.FindStringSubmatch(line); m != nil {
			localVars[m[1]] = strings.TrimSpace(m[2])
		}
	}

	var fields []storage.ProtocolField
	var warns []string
	var endian storage.Endian
	endianSet := false
	for _, j := range own {
		if !strings.Contains(lines[j], "struct.pack(") {
			continue
		}
		fs, e, eSet, w := parseBytesLine(lines[j], classes[ci].name, localVars, enumAttrs, soleEnum)
		warns = append(warns, w...)
		if eSet && !endianSet {
			endian, endianSet = e, true
		}
		fields = append(fields, fs...)
	}

	// The dispatch source is the first enum-typed integer field — one linked to
	// an enum (direct `x.value`) or flagged via a `self.x = y.value` attribute.
	enumField := ""
	for _, f := range fields {
		if !isIntType(f.Type) {
			continue
		}
		if f.EnumRef != "" || enumAttrs[f.Name] {
			enumField = f.Name
			break
		}
	}
	return fields, endian, endianSet, enumField, warns
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

// parseBytesLine turns a single line containing struct.pack(...) into fields.
// localVars/enumAttrs carry the enclosing class context (nil when parsing a
// bare top-level expression): localVars lets a computed-length payload be
// resolved to a bytes_computed field, and enumAttrs links `.value` fields to
// the sole enum.
func parseBytesLine(line, structName string, localVars map[string]string, enumAttrs map[string]bool, soleEnum string) ([]storage.ProtocolField, storage.Endian, bool, []string) {
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
			// Bare trailing payload (e.g. `+ self.data`) not consumed by a
			// preceding length prefix: best we can do is a remaining-bytes field.
			name := argName(term)
			if name == "" {
				name = "payload"
			}
			fields = append(fields, storage.ProtocolField{Name: name, Type: storage.FieldRemaining})
			warns = append(warns, fmt.Sprintf("struct %q: term %q is variable-length with no length prefix; imported %q as remaining_bytes", structName, term, name))
			continue
		}

		specs, args, e, eSet, w := parsePack(term)
		warns = append(warns, w...)
		if eSet && !endianSet {
			endian, endianSet = e, true
		}

		// A length-delimited payload appears when this pack's last argument is
		// len(x) and the next term is that payload x. This covers both a pure
		// length prefix (`pack('<H', len(x)) + x`) and a length carried inside a
		// larger header (`pack('<BH', op.value, len(x)) + x`).
		payloadFollows := i+1 < len(terms) && !strings.Contains(terms[i+1], "struct.pack(")
		lastIsLen := len(specs) > 0 && specs[len(specs)-1].consumesArg &&
			isIntType(specs[len(specs)-1].ftype) && len(args) > 0 && isLenCall(args[len(args)-1])

		if payloadFollows && lastIsLen {
			payload := strings.TrimSpace(terms[i+1])
			lenType := specs[len(specs)-1].ftype
			prefixName := argName(args[len(args)-1]) // x from len(x)

			if len(specs) == 1 {
				// Pure length prefix. Prefer capturing custom packing logic
				// (bit-packed grids) as bytes_computed, then a length-prefixed
				// string, and finally a length field + bytes_computed blob.
				if comp, ok := computedPayload(payload, prefixName, lenType, localVars, structName, &warns); ok {
					fields = append(fields, comp...)
					i++
					continue
				}
				pname := argName(payload)
				if pname == "" {
					pname = "payload"
				}
				if lp, ok := lpStringType(lenType); ok {
					fields = append(fields, storage.ProtocolField{Name: pname, Type: lp})
					warns = append(warns, fmt.Sprintf("struct %q: field %q imported as %s; switch to a bytes_lp_* type if the payload is binary", structName, pname, lp))
				} else {
					lenName := prefixName + "_len"
					fields = append(fields,
						storage.ProtocolField{Name: lenName, Type: lenType},
						storage.ProtocolField{Name: pname, Type: storage.FieldBytesComp, LengthFrom: lenName},
					)
				}
				i++
				continue
			}

			// Length carried inside a multi-field header: emit the whole header
			// (the last field is the length), then the payload as bytes_computed
			// keyed on it.
			emitted := emitSpecs(specs, args, soleEnum)
			fields = append(fields, emitted...)
			lenName := emitted[len(emitted)-1].Name
			if bcf, ok := computedBytesField(payload, lenName, localVars, structName, &warns); ok {
				fields = append(fields, bcf)
			} else {
				pname := argName(payload)
				if pname == "" || pname == lenName {
					pname = "payload"
				}
				fields = append(fields, storage.ProtocolField{Name: pname, Type: storage.FieldBytesComp, LengthFrom: lenName})
			}
			i++
			continue
		}

		fields = append(fields, emitSpecs(specs, args, soleEnum)...)
	}

	// Attach the sole enum to fields packed from a `self.x = y.value`
	// attribute (the direct `y.value` case is already linked in emitSpecs).
	if soleEnum != "" && len(enumAttrs) > 0 {
		for idx := range fields {
			if enumAttrs[fields[idx].Name] && isIntType(fields[idx].Type) && fields[idx].EnumRef == "" {
				fields[idx].EnumRef = soleEnum
			}
		}
	}
	return fields, endian, endianSet, warns
}

var bitBufMulRe = regexp.MustCompile(`^\[\s*0\s*\]\s*\*\s*(.+)$`)         // [0] * <sizeExpr>
var bitBufCtorRe = regexp.MustCompile(`^(?:bytearray|bytes)\s*\((.+)\)$`) // bytearray(<sizeExpr>)
var floorDivRe = regexp.MustCompile(`//\s*(\d+)`)                         // // 8
var lenCallRe = regexp.MustCompile(`len\(\s*([A-Za-z_][\w.]*)\s*\)`)      // len(cells)
var forInRe = regexp.MustCompile(`for\s+\w+\s+in\s+([A-Za-z_][\w.]*)`)    // for row in self.board

// computedPayload expresses a computed-length payload as a prefix integer
// field plus a bytes_computed field. The canonical shape is a bit-packed grid:
//
//	cells = [c for row in self.board for c in row]
//	bs    = [0] * ((len(cells) + 7) // 8)
//	return struct.pack('<Q', len(self.board)) + bytes(bs)
//
// which imports as: board:<int>, bs:bytes_computed(board × board ÷ 8). Used for
// a pure length prefix; the multi-field-header case emits the length field
// separately and calls computedBytesField directly.
func computedPayload(payload, prefixName string, prefixType storage.FieldType, localVars map[string]string, structName string, warns *[]string) ([]storage.ProtocolField, bool) {
	if prefixName == "" {
		return nil, false
	}
	bcf, ok := computedBytesField(payload, prefixName, localVars, structName, warns)
	if !ok {
		return nil, false
	}
	return []storage.ProtocolField{
		{Name: prefixName, Type: prefixType},
		bcf,
	}, true
}

// computedBytesField turns a payload buffer whose byte length is built from a
// bit-packing expression into a single bytes_computed field keyed on an
// already-known length field (lenField). It understands the buffer being sized
// as `[0] * (...)`, `bytearray(...)` or `bytes(...)`, a `// N` bit-to-byte
// divisor, and a flattened 2D grid (`for .. for ..`) which multiplies the
// length by itself. Returns ok=false when the payload isn't a recognizable
// computed buffer.
func computedBytesField(payload, lenField string, localVars map[string]string, structName string, warns *[]string) (storage.ProtocolField, bool) {
	if localVars == nil {
		return storage.ProtocolField{}, false
	}
	bufVar := argName(payload) // bytes(bs) -> bs, bs -> bs
	if bufVar == "" {
		return storage.ProtocolField{}, false
	}
	def := strings.TrimSpace(localVars[bufVar])
	if def == "" {
		return storage.ProtocolField{}, false
	}
	sizeExpr := ""
	if m := bitBufMulRe.FindStringSubmatch(def); m != nil {
		sizeExpr = m[1]
	} else if m := bitBufCtorRe.FindStringSubmatch(def); m != nil {
		sizeExpr = m[1]
	} else {
		return storage.ProtocolField{}, false
	}
	lm := lenCallRe.FindStringSubmatch(sizeExpr)
	if lm == nil {
		return storage.ProtocolField{}, false // size isn't len(...)-based
	}
	div := 0
	if d := floorDivRe.FindStringSubmatch(sizeExpr); d != nil {
		div, _ = strconv.Atoi(d[1])
	}
	inner := argName(lm[1]) // len(self.bits) -> bits, len(cells) -> cells

	// A double comprehension (`for .. for ..`) flattens a 2D grid, so the byte
	// count is prefix × prefix; a single loop keeps it linear.
	dims, base := 1, inner
	if idef, ok := localVars[inner]; ok {
		fors := forInRe.FindAllStringSubmatch(idef, -1)
		if len(fors) >= 1 {
			base = argName(fors[0][1]) // self.board -> board
		}
		if len(fors) >= 2 {
			dims = 2
		}
	}

	f := storage.ProtocolField{Name: bufVar, Type: storage.FieldBytesComp, LengthFrom: lenField}
	if div > 1 {
		f.LengthDiv = div
	}
	if dims >= 2 && base == lenField {
		f.LengthMulFrom = lenField // prefix × prefix (square grid)
	} else if dims >= 2 && base != "" && base != lenField {
		*warns = append(*warns, fmt.Sprintf("struct %q: bit-packed payload flattens %q but the length prefix counts %q; imported bytes_computed keys off %q — set the ×multiplier in the editor", structName, base, lenField, lenField))
	}
	return f, true
}

var bytesConcatRe = regexp.MustCompile(`(\w+)\.bytes\s*\+`)                // hdr.bytes + data
var ctorAssignRe = regexp.MustCompile(`^\s*(\w+)\s*=\s*[\w.]*?(\w+)\s*\(`) // hdr = Network.ReqHdr(...)

// buildRequestFields lays out the request when the client prepends a header
// struct to every body (`<var>.bytes + data`). It flattens the header struct
// and appends a dispatch on the header's enum field (or a remaining-bytes body
// when there's no enum to key on). Returns nil when no header idiom is found,
// leaving the request for the user to build manually.
func buildRequestFields(lines []string, structs map[string][]storage.ProtocolField, enumFieldOf map[string]string) ([]storage.ProtocolField, []string) {
	headerVar := ""
	for _, line := range lines {
		if m := bytesConcatRe.FindStringSubmatch(stripComment(line)); m != nil {
			headerVar = m[1]
			break
		}
	}
	if headerVar == "" {
		return nil, nil
	}

	// Resolve the variable to the struct it was built from. It might be a
	// struct name directly (`ReqHdr.bytes`) or a local bound to a constructor.
	headerStruct := ""
	if _, ok := structs[headerVar]; ok {
		headerStruct = headerVar
	} else {
		for _, line := range lines {
			m := ctorAssignRe.FindStringSubmatch(stripComment(line))
			if m == nil || m[1] != headerVar {
				continue
			}
			if _, ok := structs[m[2]]; ok {
				headerStruct = m[2]
				break
			}
		}
	}
	if headerStruct == "" {
		return nil, nil
	}

	hdr := structs[headerStruct]
	req := make([]storage.ProtocolField, len(hdr))
	copy(req, hdr)
	var warns []string
	if ef := enumFieldOf[headerStruct]; ef != "" {
		req = append(req, storage.ProtocolField{Name: "body", Type: storage.FieldDispatch, DispatchOn: ef})
		warns = append(warns, fmt.Sprintf("request auto-wired as header %q + dispatch on %q — add a struct named after each %q label so bodies decode; unknown types show as raw bytes", headerStruct, ef, ef))
	} else {
		req = append(req, storage.ProtocolField{Name: "body", Type: storage.FieldRemaining})
		warns = append(warns, fmt.Sprintf("request auto-wired as header %q + remaining body; no enum field to dispatch on — set one in the Request tab if the body varies by type", headerStruct))
	}
	return req, warns
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

// emitSpecs pairs each arg-consuming spec with the next packed argument. Names
// come from the argument (`self.ts` -> "ts"); a `len(x)` argument names its
// field "x_len" since it's the length of a following payload, and an argument
// carrying an enum value (`op.value`) is linked to soleEnum when there is one.
func emitSpecs(specs []formatSpec, args []string, soleEnum string) []storage.ProtocolField {
	out := make([]storage.ProtocolField, 0, len(specs))
	ai := 0
	for _, sp := range specs {
		name := ""
		isEnum := false
		if sp.consumesArg && ai < len(args) {
			arg := args[ai]
			ai++
			switch {
			case isLenCall(arg):
				if inner := argName(arg); inner != "" {
					name = inner + "_len"
				}
			default:
				name = argName(arg)
				if soleEnum != "" && strings.Contains(arg, ".value") {
					isEnum = true
				}
			}
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
		if isEnum && isIntType(sp.ftype) {
			f.EnumRef = soleEnum
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
var numLiteralRe = regexp.MustCompile(`^[+-]?(0[xXbBoO][0-9A-Fa-f]+|\d[\d_]*\.?\d*([eE][+-]?\d+)?)$`)

// argName extracts a sensible field name from a packed argument expression:
// `self.ts` -> "ts", `self.type.value` -> "type", `len(self.data)` -> "data",
// `bytes(bs)` -> "bs". A bare numeric literal (`0xdeadbeef`, `42`) has no
// meaningful name, so it — and anything else with no usable identifier —
// returns "".
func argName(expr string) string {
	s := strings.TrimSpace(expr)
	for {
		m := wrapperCallRe.FindStringSubmatch(s)
		if m == nil {
			break
		}
		s = strings.TrimSpace(m[1])
	}
	if numLiteralRe.MatchString(s) {
		return ""
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
