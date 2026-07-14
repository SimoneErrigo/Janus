// Package pcap writes captured packets as standard .pcap files (libpcap format).
// It wraps each stored packet with synthetic Ethernet + IPv4 + TCP/UDP headers
// so the result opens correctly in Wireshark and other pcap-aware tools.
// No external dependencies are required — the pcap file format is simple enough
// to implement in ~120 lines of pure Go.
package pcap

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/SimoneErrigo/Janus/backend/internal/sniffer"
)

// pcap global header constants (libpcap format, little-endian)
const (
	pcapMagic   uint32 = 0xa1b2c3d4
	pcapMajor   uint16 = 2
	pcapMinor   uint16 = 4
	pcapSnapLen uint32 = 65535
	pcapEthLink uint32 = 1 // LINKTYPE_ETHERNET
	maxTCPChunk        = int(pcapSnapLen) - 14 - 20 - 20
	maxUDPChunk        = int(pcapSnapLen) - 14 - 20 - 8
)

// seqState tracks TCP sequence numbers per session to produce a valid bidirectional stream.
type seqState struct {
	clientSeq uint32 // bytes sent by the client (request direction)
	serverSeq uint32 // bytes sent by the server (response direction)
}

// statusText returns a minimal HTTP reason phrase for common status codes.
func statusText(code int) string {
	switch code {
	case 200:
		return "OK"
	case 201:
		return "Created"
	case 204:
		return "No Content"
	case 301:
		return "Moved Permanently"
	case 302:
		return "Found"
	case 304:
		return "Not Modified"
	case 400:
		return "Bad Request"
	case 401:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 500:
		return "Internal Server Error"
	default:
		return "Unknown"
	}
}

// buildHTTPPayload reconstructs a raw HTTP request or response from the stored fields.
// For raw TCP packets (no method/status), it returns the body bytes unchanged.
func buildHTTPPayload(pkt *sniffer.Packet) []byte {
	body := pkt.Body
	if len(body) == 0 && pkt.BodyString != "" {
		body = []byte(pkt.BodyString)
	}

	// Raw TCP — return body as-is
	if pkt.Method == "" && pkt.Status == 0 {
		return body
	}

	var sb strings.Builder
	if pkt.Direction == sniffer.DirectionRequest {
		method := pkt.Method
		if method == "" {
			method = "GET"
		}
		url := pkt.URL
		if url == "" {
			url = "/"
		}
		fmt.Fprintf(&sb, "%s %s HTTP/1.1\r\n", method, url)
	} else {
		code := pkt.Status
		if code == 0 {
			code = 200
		}
		fmt.Fprintf(&sb, "HTTP/1.1 %d %s\r\n", code, statusText(code))
	}

	for k, v := range pkt.Headers {
		// Stored bodies have already been de-chunked by net/http. Emit one
		// authoritative length instead of producing contradictory framing.
		if strings.EqualFold(k, "Content-Length") || strings.EqualFold(k, "Transfer-Encoding") {
			continue
		}
		fmt.Fprintf(&sb, "%s: %s\r\n", k, v)
	}
	if len(body) > 0 {
		fmt.Fprintf(&sb, "Content-Length: %d\r\n", len(body))
	}
	sb.WriteString("\r\n")

	result := []byte(sb.String())
	return append(result, body...)
}

func packetPayload(pkt *sniffer.Packet) []byte {
	protocol := strings.ToLower(pkt.Protocol)
	switch protocol {
	case "http", "https", "h2", "h2c", "grpc", "grpc-h2c":
		return buildHTTPPayload(pkt)
	default:
		if len(pkt.Body) > 0 {
			return pkt.Body
		}
		return []byte(pkt.BodyString)
	}
}

func isUDP(pkt *sniffer.Packet) bool {
	switch strings.ToLower(pkt.Protocol) {
	case "udp", "dns":
		return true
	default:
		return false
	}
}

// toIPv4 parses an IP string and returns its 4-byte IPv4 form.
// Falls back to 127.0.0.1 for IPv6 or unparseable addresses.
func toIPv4(ipStr string) []byte {
	if ip := net.ParseIP(ipStr).To4(); ip != nil {
		return []byte(ip)
	}
	return []byte{127, 0, 0, 1}
}

// WriteGlobalHeader writes the 24-byte pcap file header to w.
func WriteGlobalHeader(w io.Writer) error {
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:], pcapMagic)
	binary.LittleEndian.PutUint16(hdr[4:], pcapMajor)
	binary.LittleEndian.PutUint16(hdr[6:], pcapMinor)
	// bytes 8-15: thiszone=0, sigfigs=0 — left as zero
	binary.LittleEndian.PutUint32(hdr[16:], pcapSnapLen)
	binary.LittleEndian.PutUint32(hdr[20:], pcapEthLink)
	_, err := w.Write(hdr)
	return err
}

// writePacket emits one or more valid frames. Large TCP payloads are segmented
// and large synthetic UDP payloads are represented as multiple datagrams, so
// IPv4 lengths and PCAP captured lengths never wrap or exceed snaplen.
func writePacket(w io.Writer, pkt *sniffer.Packet, state *seqState) error {
	payload := packetPayload(pkt)
	chunkSize := maxTCPChunk
	if isUDP(pkt) {
		chunkSize = maxUDPChunk
	}
	if len(payload) == 0 {
		return writeTransportFrame(w, pkt, state, nil, 0)
	}
	for offset, index := 0, 0; offset < len(payload); index++ {
		end := offset + chunkSize
		if end > len(payload) {
			end = len(payload)
		}
		if err := writeTransportFrame(w, pkt, state, payload[offset:end], index); err != nil {
			return err
		}
		offset = end
	}
	return nil
}

func writeTransportFrame(w io.Writer, pkt *sniffer.Packet, state *seqState, payload []byte, index int) error {
	udp := isUDP(pkt)
	transportLen := 20
	protocol := byte(6)
	if udp {
		transportLen = 8
		protocol = 17
	}
	totalIPLen := 20 + transportLen + len(payload)
	frame := make([]byte, 14+totalIPLen)

	// Ethernet header
	// dst: 00:00:00:00:00:02, src: 00:00:00:00:00:01, EtherType: 0x0800 (IPv4)
	frame[5] = 0x02
	frame[11] = 0x01
	frame[12] = 0x08
	frame[13] = 0x00

	// IPv4 header (offset 14, 20 bytes)
	ip := frame[14:]
	ip[0] = 0x45 // version=4, IHL=5
	binary.BigEndian.PutUint16(ip[2:], uint16(totalIPLen))
	binary.BigEndian.PutUint16(ip[6:], 0x4000) // don't fragment
	ip[8] = 64                                 // TTL
	ip[9] = protocol
	// ip[10:12] = checksum — left as 0 (Wireshark handles unchecked checksums)
	copy(ip[12:16], toIPv4(pkt.SrcIP))
	copy(ip[16:20], toIPv4(pkt.DstIP))

	transport := frame[34:]
	binary.BigEndian.PutUint16(transport[0:], uint16(pkt.SrcPort))
	binary.BigEndian.PutUint16(transport[2:], uint16(pkt.DstPort))
	if udp {
		binary.BigEndian.PutUint16(transport[4:], uint16(8+len(payload)))
		copy(transport[8:], payload)
	} else {
		isReq := pkt.Direction == sniffer.DirectionRequest
		var seq, ack uint32
		if isReq {
			seq, ack = state.clientSeq, state.serverSeq
			state.clientSeq += uint32(len(payload))
		} else {
			seq, ack = state.serverSeq, state.clientSeq
			state.serverSeq += uint32(len(payload))
		}
		binary.BigEndian.PutUint32(transport[4:], seq)
		binary.BigEndian.PutUint32(transport[8:], ack)
		transport[12] = 0x50
		transport[13] = 0x18
		binary.BigEndian.PutUint16(transport[14:], 65535)
		copy(transport[20:], payload)
	}

	// PCAP packet record (16-byte header)
	ts := pkt.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	if index > 0 {
		ts = ts.Add(time.Duration(index) * time.Microsecond)
	}
	recHdr := make([]byte, 16)
	binary.LittleEndian.PutUint32(recHdr[0:], uint32(ts.Unix()))
	binary.LittleEndian.PutUint32(recHdr[4:], uint32(ts.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(recHdr[8:], uint32(len(frame)))
	binary.LittleEndian.PutUint32(recHdr[12:], uint32(len(frame)))

	if _, err := w.Write(recHdr); err != nil {
		return err
	}
	_, err := w.Write(frame)
	return err
}

// WritePcap writes all packets to w as a valid pcap file, sorted by timestamp.
func WritePcap(w io.Writer, packets []*sniffer.Packet) error {
	if err := WriteGlobalHeader(w); err != nil {
		return err
	}

	// Sort ascending so Wireshark sees the conversation in order
	sorted := make([]*sniffer.Packet, len(packets))
	copy(sorted, packets)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Timestamp.Before(sorted[j].Timestamp)
	})

	seqMap := make(map[string]*seqState)
	for _, pkt := range sorted {
		sid := pkt.SessionID
		if sid == "" {
			sid = fmt.Sprintf("%s:%d-%s:%d", pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort)
		}
		if _, ok := seqMap[sid]; !ok {
			seqMap[sid] = &seqState{clientSeq: 1000, serverSeq: 2000}
		}
		if err := writePacket(w, pkt, seqMap[sid]); err != nil {
			return err
		}
	}
	return nil
}
