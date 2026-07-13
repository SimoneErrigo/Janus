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
		storage.FramingFixed, storage.FramingLengthPrefix:
	case storage.FramingHTTP, storage.FramingCustom:
		return nil, fmt.Errorf("framing mode %q is handled by an application adapter", spec.Mode)
	default:
		return nil, fmt.Errorf("unknown framing mode %q", spec.Mode)
	}
	if spec.Mode == storage.FramingFixed && spec.FixedLength <= 0 {
		return nil, fmt.Errorf("fixed framing requires fixed_length > 0")
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
	default:
		return nil, fmt.Errorf("unsupported framing mode %q", r.spec.Mode)
	}
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
		part, err := r.source.ReadBytes(last)
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
