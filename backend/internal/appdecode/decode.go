// Package appdecode provides small, deterministic protocol decoders. Decoding
// is observational: malformed input returns decode_error and is still forwarded.
package appdecode

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/SimoneErrigo/Janus/backend/internal/storage"
)

func Decode(spec storage.ServiceSpec, wire []byte) map[string]any {
	switch spec.Application.Profile {
	case storage.ApplicationDNS:
		payload := wire
		if spec.Listener.Transport == storage.TransportTCP && len(payload) >= 2 {
			payload = payload[2:]
		}
		return namespace("dns", decodeDNS(payload))
	case storage.ApplicationRESP:
		return namespace("resp", decodeRESP(wire))
	case storage.ApplicationMQTT:
		return namespace("mqtt", decodeMQTT(wire))
	default:
		return nil
	}
}

func namespace(name string, value map[string]any) map[string]any {
	if len(value) == 0 {
		return nil
	}
	return map[string]any{name: value}
}

func decodeDNS(b []byte) map[string]any {
	out := map[string]any{}
	if len(b) < 12 {
		out["decode_error"] = "DNS header is shorter than 12 bytes"
		return out
	}
	flags := binary.BigEndian.Uint16(b[2:4])
	qd := int(binary.BigEndian.Uint16(b[4:6]))
	out["id"] = int(binary.BigEndian.Uint16(b[:2]))
	out["qr"] = flags>>15 == 1
	out["opcode"] = int((flags >> 11) & 0xf)
	out["rcode"] = int(flags & 0xf)
	out["questions"] = qd
	out["answers"] = int(binary.BigEndian.Uint16(b[6:8]))
	if qd == 0 {
		return out
	}
	name, next, err := dnsName(b, 12, 0)
	if err != nil {
		out["decode_error"] = err.Error()
		return out
	}
	out["qname"] = name
	if next+4 > len(b) {
		out["decode_error"] = "truncated DNS question"
		return out
	}
	out["qtype"] = int(binary.BigEndian.Uint16(b[next : next+2]))
	out["qclass"] = int(binary.BigEndian.Uint16(b[next+2 : next+4]))
	return out
}

func dnsName(b []byte, off, depth int) (string, int, error) {
	if depth > 8 || off >= len(b) {
		return "", off, fmt.Errorf("invalid DNS name")
	}
	labels := make([]string, 0, 4)
	next := off
	jumped := false
	for {
		if off >= len(b) {
			return "", next, fmt.Errorf("truncated DNS name")
		}
		n := int(b[off])
		if n == 0 {
			if !jumped {
				next = off + 1
			}
			return strings.Join(labels, "."), next, nil
		}
		if n&0xc0 == 0xc0 {
			if off+1 >= len(b) {
				return "", next, fmt.Errorf("truncated DNS compression pointer")
			}
			ptr := int(binary.BigEndian.Uint16(b[off:off+2]) & 0x3fff)
			suffix, _, err := dnsName(b, ptr, depth+1)
			if err != nil {
				return "", next, err
			}
			labels = append(labels, suffix)
			if !jumped {
				next = off + 2
			}
			return strings.Join(labels, "."), next, nil
		}
		if n > 63 || off+1+n > len(b) {
			return "", next, fmt.Errorf("invalid DNS label")
		}
		labels = append(labels, string(b[off+1:off+1+n]))
		off += n + 1
		if !jumped {
			next = off
		}
	}
}

type respValue struct {
	kind     string
	text     string
	children []respValue
}

const maxRESPDecodedValues = 16 * 1024

func decodeRESP(b []byte) map[string]any {
	out := map[string]any{}
	budget := maxRESPDecodedValues
	v, _, err := parseRESP(b, 0, 0, &budget)
	if err != nil {
		out["decode_error"] = err.Error()
		return out
	}
	out["kind"] = v.kind
	if v.kind == "array" {
		args := make([]string, 0, len(v.children))
		for _, child := range v.children {
			args = append(args, child.text)
		}
		if len(args) > 0 {
			out["command"] = strings.ToUpper(args[0])
			out["args"] = args[1:]
		}
	} else if v.text != "" {
		out["value"] = v.text
	}
	return out
}

func parseRESP(b []byte, off, depth int, budget *int) (respValue, int, error) {
	if depth > 16 || off >= len(b) {
		return respValue{}, off, fmt.Errorf("truncated RESP value")
	}
	if *budget <= 0 {
		return respValue{}, off, fmt.Errorf("RESP value count exceeds %d", maxRESPDecodedValues)
	}
	*budget = *budget - 1
	prefix := b[off]
	line, next, err := readCRLF(b, off+1)
	if err != nil {
		return respValue{}, off, err
	}
	switch prefix {
	case '+':
		return respValue{kind: "simple", text: line}, next, nil
	case '-':
		return respValue{kind: "error", text: line}, next, nil
	case ':':
		return respValue{kind: "integer", text: line}, next, nil
	case '$':
		n, err := strconv.Atoi(line)
		if err != nil || n < -1 {
			return respValue{}, off, fmt.Errorf("invalid RESP bulk length")
		}
		if n == -1 {
			return respValue{kind: "null"}, next, nil
		}
		remaining := len(b) - next
		if n > remaining || remaining-n < 2 {
			return respValue{}, off, fmt.Errorf("truncated RESP bulk string")
		}
		value := b[next : next+n]
		if b[next+n] != '\r' || b[next+n+1] != '\n' {
			return respValue{}, off, fmt.Errorf("invalid RESP bulk terminator")
		}
		text := fmt.Sprintf("<%d binary bytes>", len(value))
		if utf8.Valid(value) {
			text = string(value)
		}
		return respValue{kind: "bulk", text: text}, next + n + 2, nil
	case '*':
		n, err := strconv.Atoi(line)
		if err != nil || n < -1 {
			return respValue{}, off, fmt.Errorf("invalid RESP array length")
		}
		if n == -1 {
			return respValue{kind: "null"}, next, nil
		}
		// Every encoded RESP value needs at least a prefix and CRLF. Reject
		// impossible or excessive declarations before using n as a capacity.
		if n > (len(b)-next)/3 {
			return respValue{}, off, fmt.Errorf("truncated RESP array")
		}
		if n > *budget {
			return respValue{}, off, fmt.Errorf("RESP value count exceeds %d", maxRESPDecodedValues)
		}
		v := respValue{kind: "array", children: make([]respValue, 0, n)}
		for i := 0; i < n; i++ {
			child, end, err := parseRESP(b, next, depth+1, budget)
			if err != nil {
				return respValue{}, off, err
			}
			v.children = append(v.children, child)
			next = end
		}
		return v, next, nil
	default:
		return respValue{}, off, fmt.Errorf("unknown RESP prefix 0x%02x", prefix)
	}
}

func readCRLF(b []byte, off int) (string, int, error) {
	for i := off; i+1 < len(b); i++ {
		if b[i] == '\r' && b[i+1] == '\n' {
			return string(b[off:i]), i + 2, nil
		}
	}
	return "", off, fmt.Errorf("truncated CRLF line")
}

var mqttPacketNames = []string{"reserved", "connect", "connack", "publish", "puback", "pubrec", "pubrel", "pubcomp", "subscribe", "suback", "unsubscribe", "unsuback", "pingreq", "pingresp", "disconnect", "auth"}

func decodeMQTT(b []byte) map[string]any {
	out := map[string]any{}
	if len(b) < 2 {
		out["decode_error"] = "truncated MQTT header"
		return out
	}
	typ := int(b[0] >> 4)
	out["type"] = typ
	if typ < len(mqttPacketNames) {
		out["packet"] = mqttPacketNames[typ]
	}
	out["dup"] = b[0]&8 != 0
	out["qos"] = int((b[0] >> 1) & 3)
	out["retain"] = b[0]&1 != 0
	remaining, used, ok := mqttRemaining(b[1:])
	if !ok {
		out["decode_error"] = "invalid MQTT remaining length"
		return out
	}
	out["remaining_length"] = remaining
	payload := b[1+used:]
	if len(payload) < remaining {
		out["decode_error"] = "truncated MQTT payload"
		return out
	}
	payload = payload[:remaining]
	switch typ {
	case 1:
		if _, rest, ok := mqttString(payload); ok && len(rest) >= 4 {
			rest = rest[4:]
			if client, _, ok := mqttString(rest); ok {
				out["client_id"] = client
			}
		}
	case 3:
		if topic, _, ok := mqttString(payload); ok {
			out["topic"] = topic
		}
	case 8, 10:
		if len(payload) >= 2 {
			if topic, _, ok := mqttString(payload[2:]); ok {
				out["topic"] = topic
			}
		}
	}
	return out
}

func mqttRemaining(b []byte) (int, int, bool) {
	value, multiplier := 0, 1
	for i := 0; i < len(b) && i < 4; i++ {
		value += int(b[i]&127) * multiplier
		if b[i]&128 == 0 {
			return value, i + 1, true
		}
		multiplier *= 128
	}
	return 0, 0, false
}

func mqttString(b []byte) (string, []byte, bool) {
	if len(b) < 2 {
		return "", b, false
	}
	n := int(binary.BigEndian.Uint16(b[:2]))
	if 2+n > len(b) {
		return "", b, false
	}
	return string(b[2 : 2+n]), b[2+n:], true
}
