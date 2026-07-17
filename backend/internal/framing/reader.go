// Package framing turns transport streams into stable application message
// boundaries. A Reader is connection-local and therefore owns no global state.
package framing

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/SimoneErrigo/Janus/backend/internal/storage"
)

const (
	defaultChunkSize = 32 * 1024
	defaultMaxFrame  = 1 << 20
)

var ErrFrameTooLarge = errors.New("frame exceeds configured maximum")

type Reader struct {
	source *bufio.Reader
	spec   storage.FramingSpec
	eof    bool
}

func NewReader(source io.Reader, spec storage.FramingSpec) (*Reader, error) {
	if source == nil {
		return nil, fmt.Errorf("framing source is nil")
	}
	if spec.Mode == "" {
		spec.Mode = storage.FramingRaw
	}
	switch spec.Mode {
	case storage.FramingRaw, storage.FramingLine, storage.FramingDelimiter,
		storage.FramingFixed, storage.FramingLengthPrefix, storage.FramingRESP,
		storage.FramingMQTT:
	case storage.FramingHTTP, storage.FramingCustom:
		return nil, fmt.Errorf("framing mode %q is handled by an application adapter", spec.Mode)
	default:
		return nil, fmt.Errorf("unknown framing mode %q", spec.Mode)
	}
	if spec.Mode == storage.FramingFixed && (spec.FixedLength <= 0 || spec.FixedLength > defaultMaxFrame) {
		return nil, fmt.Errorf("fixed framing requires fixed_length between 1 and %d", defaultMaxFrame)
	}
	if spec.Mode == storage.FramingLengthPrefix && spec.PrefixBytes != 1 && spec.PrefixBytes != 2 && spec.PrefixBytes != 4 {
		return nil, fmt.Errorf("length-prefix framing requires prefix_bytes 1, 2, or 4")
	}
	if spec.Mode == storage.FramingLine && spec.Delimiter == "" {
		spec.Delimiter = "\n"
	}
	if spec.Mode == storage.FramingDelimiter && spec.Delimiter == "" {
		return nil, fmt.Errorf("delimiter framing requires delimiter")
	}
	if len(spec.Delimiter) > defaultMaxFrame {
		return nil, fmt.Errorf("framing delimiter exceeds %d bytes", defaultMaxFrame)
	}
	return &Reader{source: bufio.NewReader(source), spec: spec}, nil
}

func (r *Reader) Next() ([]byte, error) {
	if r.eof {
		return nil, io.EOF
	}
	switch r.spec.Mode {
	case storage.FramingRaw:
		buf := make([]byte, defaultChunkSize)
		n, err := r.source.Read(buf)
		return r.finish(buf[:n], err)
	case storage.FramingLine, storage.FramingDelimiter:
		return r.readDelimited([]byte(r.spec.Delimiter))
	case storage.FramingFixed:
		buf := make([]byte, r.spec.FixedLength)
		n, err := io.ReadFull(r.source, buf)
		return r.finish(buf[:n], err)
	case storage.FramingLengthPrefix:
		return r.readLengthPrefixed()
	case storage.FramingRESP:
		return r.readRESP()
	case storage.FramingMQTT:
		return r.readMQTT()
	default:
		return nil, fmt.Errorf("unsupported framing mode %q", r.spec.Mode)
	}
}

func (r *Reader) readRESP() ([]byte, error) {
	frame, err := r.readRESPValue(0)
	if err != nil && len(frame) > 0 {
		// Preserve transport availability on malformed input. The bytes already
		// consumed are forwarded and this direction degrades to raw chunks.
		r.spec.Mode = storage.FramingRaw
		return frame, nil
	}
	return r.finish(frame, err)
}

func (r *Reader) readRESPValue(depth int) ([]byte, error) {
	if depth > 16 {
		return nil, fmt.Errorf("RESP nesting is too deep")
	}
	prefix, err := r.source.ReadByte()
	if err != nil {
		return nil, err
	}
	frame := []byte{prefix}
	lineBytes, err := r.readBoundedLine()
	line := string(lineBytes)
	frame = append(frame, line...)
	if err != nil {
		return frame, err
	}
	if len(line) < 2 || line[len(line)-2:] != "\r\n" {
		return frame, fmt.Errorf("invalid RESP line ending")
	}
	number, parseErr := strconv.Atoi(strings.TrimSuffix(line, "\r\n"))
	switch prefix {
	case '+', '-', ':':
		return frame, nil
	case '$':
		if parseErr != nil || number < -1 {
			return frame, fmt.Errorf("invalid RESP bulk length")
		}
		if number == -1 {
			return frame, nil
		}
		if number > defaultMaxFrame {
			return frame, ErrFrameTooLarge
		}
		payload := make([]byte, number+2)
		n, readErr := io.ReadFull(r.source, payload)
		frame = append(frame, payload[:n]...)
		if readErr == nil && (payload[number] != '\r' || payload[number+1] != '\n') {
			return frame, fmt.Errorf("invalid RESP bulk terminator")
		}
		return frame, readErr
	case '*':
		if parseErr != nil || number < -1 {
			return frame, fmt.Errorf("invalid RESP array length")
		}
		if number == -1 {
			return frame, nil
		}
		for i := 0; i < number; i++ {
			part, readErr := r.readRESPValue(depth + 1)
			frame = append(frame, part...)
			if len(frame) > defaultMaxFrame {
				return frame, ErrFrameTooLarge
			}
			if readErr != nil {
				return frame, readErr
			}
		}
		return frame, nil
	default:
		return frame, fmt.Errorf("unknown RESP prefix 0x%02x", prefix)
	}
}

// readBoundedLine avoids bufio.ReadString's unbounded accumulation when a peer
// never sends a newline. The final fragment is retained so fail-open mode can
// forward every byte already consumed.
func (r *Reader) readBoundedLine() ([]byte, error) {
	var line []byte
	for {
		part, err := r.source.ReadSlice('\n')
		line = append(line, part...)
		if len(line) > defaultMaxFrame {
			return line, ErrFrameTooLarge
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return line, err
	}
}

func (r *Reader) readMQTT() ([]byte, error) {
	first, err := r.source.ReadByte()
	if err != nil {
		return nil, err
	}
	frame := []byte{first}
	remaining, multiplier := 0, 1
	for i := 0; i < 4; i++ {
		b, readErr := r.source.ReadByte()
		if readErr != nil {
			return r.finish(frame, readErr)
		}
		frame = append(frame, b)
		remaining += int(b&127) * multiplier
		if b&128 == 0 {
			if remaining > defaultMaxFrame {
				r.spec.Mode = storage.FramingRaw
				return frame, nil
			}
			payload := make([]byte, remaining)
			n, payloadErr := io.ReadFull(r.source, payload)
			frame = append(frame, payload[:n]...)
			return r.finish(frame, payloadErr)
		}
		multiplier *= 128
	}
	r.spec.Mode = storage.FramingRaw
	return frame, nil
}

func (r *Reader) finish(data []byte, err error) ([]byte, error) {
	if len(data) > 0 {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			r.eof = true
		}
		return append([]byte(nil), data...), nil
	}
	if err == nil {
		return nil, nil
	}
	if err == io.ErrUnexpectedEOF {
		err = io.EOF
	}
	if err == io.EOF {
		r.eof = true
	}
	return nil, err
}

func (r *Reader) readDelimited(delimiter []byte) ([]byte, error) {
	var frame []byte
	last := delimiter[len(delimiter)-1]
	for {
		part, err := r.source.ReadSlice(last)
		frame = append(frame, part...)
		if len(frame) > defaultMaxFrame {
			// Preserve availability: forward the accumulated bytes and degrade
			// this connection direction to raw chunks instead of dropping data.
			r.spec.Mode = storage.FramingRaw
			return frame, nil
		}
		if bytes.HasSuffix(frame, delimiter) {
			return frame, nil
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil {
			return r.finish(frame, err)
		}
	}
}

func (r *Reader) readLengthPrefixed() ([]byte, error) {
	prefix := make([]byte, r.spec.PrefixBytes)
	n, err := io.ReadFull(r.source, prefix)
	if err != nil {
		return r.finish(prefix[:n], err)
	}
	var size uint32
	var order binary.ByteOrder = binary.BigEndian
	if r.spec.LittleEndian {
		order = binary.LittleEndian
	}
	switch len(prefix) {
	case 1:
		size = uint32(prefix[0])
	case 2:
		size = uint32(order.Uint16(prefix))
	case 4:
		size = order.Uint32(prefix)
	}
	if size > defaultMaxFrame {
		// The prefix has already been consumed. Emit it unchanged and continue
		// in raw mode so the oversized payload is forwarded without loss.
		r.spec.Mode = storage.FramingRaw
		return prefix, nil
	}
	payload := make([]byte, int(size))
	n, err = io.ReadFull(r.source, payload)
	frame := append(prefix, payload[:n]...)
	return r.finish(frame, err)
}
