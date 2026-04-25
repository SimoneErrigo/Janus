package pcap

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/SimoneErrigo/Janus/backend/internal/sniffer"
)

// ---- PCAP file format constants ----

const (
	pcapMagicNative  uint32 = 0xa1b2c3d4 // little-endian timestamps (μs)
	pcapMagicSwapped uint32 = 0xd4c3b2a1 // big-endian
	pcapMagicNanoLE  uint32 = 0xa1b23c4d // nanosecond variant LE
	pcapMagicNanoBE  uint32 = 0x4d3cb2a1 // nanosecond variant BE

	linkEthernet uint32 = 1
	linkNull     uint32 = 0
	linkRaw      uint32 = 101
	linkLinuxSLL uint32 = 113
	linkIPv4     uint32 = 228
)

// ---- TCP segment and stream types ----

type segment struct {
	seq     uint32
	flags   uint8
	payload []byte
	ts      time.Time
}

// connKey identifies a TCP connection; normalized so the lexicographically
// smaller endpoint is always "a".
type connKey struct {
	aIP, bIP     string
	aPort, bPort uint16
}

func normalizeConn(srcIP, dstIP string, srcPort, dstPort uint16) (connKey, bool) {
	aFirst := srcIP < dstIP || (srcIP == dstIP && srcPort <= dstPort)
	if aFirst {
		return connKey{aIP: srcIP, bIP: dstIP, aPort: srcPort, bPort: dstPort}, true
	}
	return connKey{aIP: dstIP, bIP: srcIP, aPort: dstPort, bPort: srcPort}, false
}

// dirKey uniquely identifies one directional half of a connection.
type dirKey struct {
	srcIP, dstIP string
	srcPort, dstPort uint16
}

// ---- Reader state ----

type pcapReader struct {
	swap   bool // byte-order swap needed
	nano   bool // timestamps in nanoseconds
	link   uint32
	segs   map[dirKey][]segment
	synDir map[connKey]dirKey // which direction sent SYN
}

func newPcapReader() *pcapReader {
	return &pcapReader{
		segs:   make(map[dirKey][]segment),
		synDir: make(map[connKey]dirKey),
	}
}

// ---- Low-level parsing ----

func (p *pcapReader) u16(b []byte) uint16 {
	if p.swap {
		return binary.BigEndian.Uint16(b)
	}
	return binary.LittleEndian.Uint16(b)
}

func (p *pcapReader) u32(b []byte) uint32 {
	if p.swap {
		return binary.BigEndian.Uint32(b)
	}
	return binary.LittleEndian.Uint32(b)
}

func readGlobal(r io.Reader) (*pcapReader, error) {
	hdr := make([]byte, 24)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, fmt.Errorf("reading pcap global header: %w", err)
	}
	magic := binary.LittleEndian.Uint32(hdr[0:])
	pr := newPcapReader()
	switch magic {
	case pcapMagicNative:
	case pcapMagicNanoLE:
		pr.nano = true
	case pcapMagicSwapped:
		pr.swap = true
	case pcapMagicNanoBE:
		pr.swap = true
		pr.nano = true
	default:
		return nil, fmt.Errorf("unrecognised pcap magic: 0x%x", magic)
	}
	pr.link = pr.u32(hdr[20:])
	return pr, nil
}

// stripLinkHeader removes the link-layer encapsulation and returns the IP payload.
func (p *pcapReader) stripLink(pkt []byte) []byte {
	switch p.link {
	case linkEthernet:
		if len(pkt) < 14 {
			return nil
		}
		ethertype := binary.BigEndian.Uint16(pkt[12:])
		if ethertype == 0x8100 { // 802.1Q VLAN
			if len(pkt) < 18 {
				return nil
			}
			return pkt[18:]
		}
		if ethertype != 0x0800 { // not IPv4
			return nil
		}
		return pkt[14:]
	case linkNull:
		if len(pkt) < 4 {
			return nil
		}
		family := binary.LittleEndian.Uint32(pkt[0:])
		if family != 2 { // AF_INET
			return nil
		}
		return pkt[4:]
	case linkRaw, linkIPv4:
		return pkt
	case linkLinuxSLL:
		if len(pkt) < 16 {
			return nil
		}
		ethertype := binary.BigEndian.Uint16(pkt[14:])
		if ethertype != 0x0800 {
			return nil
		}
		return pkt[16:]
	default:
		return nil
	}
}

// parseTCP extracts a TCP segment from an IP payload.
// Returns (srcIP, dstIP, srcPort, dstPort, seq, flags, payload, ok).
func parseTCP(ipPkt []byte) (string, string, uint16, uint16, uint32, uint8, []byte, bool) {
	if len(ipPkt) < 20 {
		return "", "", 0, 0, 0, 0, nil, false
	}
	version := ipPkt[0] >> 4
	if version != 4 {
		return "", "", 0, 0, 0, 0, nil, false
	}
	ihl := int(ipPkt[0]&0x0f) * 4
	if ihl < 20 || len(ipPkt) < ihl {
		return "", "", 0, 0, 0, 0, nil, false
	}
	proto := ipPkt[9]
	if proto != 6 { // TCP
		return "", "", 0, 0, 0, 0, nil, false
	}
	totalLen := int(binary.BigEndian.Uint16(ipPkt[2:]))
	if totalLen > len(ipPkt) {
		totalLen = len(ipPkt)
	}
	srcIP := fmt.Sprintf("%d.%d.%d.%d", ipPkt[12], ipPkt[13], ipPkt[14], ipPkt[15])
	dstIP := fmt.Sprintf("%d.%d.%d.%d", ipPkt[16], ipPkt[17], ipPkt[18], ipPkt[19])
	tcp := ipPkt[ihl:]
	if len(tcp) < 20 {
		return "", "", 0, 0, 0, 0, nil, false
	}
	srcPort := binary.BigEndian.Uint16(tcp[0:])
	dstPort := binary.BigEndian.Uint16(tcp[2:])
	seq := binary.BigEndian.Uint32(tcp[4:])
	dataOffset := int((tcp[12] >> 4) * 4)
	if dataOffset < 20 || dataOffset > len(tcp) {
		return "", "", 0, 0, 0, 0, nil, false
	}
	flags := tcp[13]
	payload := tcp[dataOffset : totalLen-ihl]
	return srcIP, dstIP, srcPort, dstPort, seq, flags, payload, true
}

func (p *pcapReader) readRecords(r io.Reader) error {
	rechdr := make([]byte, 16)
	for {
		if _, err := io.ReadFull(r, rechdr); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return nil
			}
			return err
		}
		tsSec := p.u32(rechdr[0:])
		tsFrac := p.u32(rechdr[4:])
		inclLen := p.u32(rechdr[8:])

		data := make([]byte, inclLen)
		if _, err := io.ReadFull(r, data); err != nil {
			return err
		}

		var ts time.Time
		if p.nano {
			ts = time.Unix(int64(tsSec), int64(tsFrac)).UTC()
		} else {
			ts = time.Unix(int64(tsSec), int64(tsFrac)*1000).UTC()
		}

		ipPkt := p.stripLink(data)
		if ipPkt == nil {
			continue
		}

		srcIP, dstIP, srcPort, dstPort, seq, flags, payload, ok := parseTCP(ipPkt)
		if !ok {
			continue
		}

		dk := dirKey{srcIP: srcIP, dstIP: dstIP, srcPort: srcPort, dstPort: dstPort}

		// Track SYN direction
		if flags&0x02 != 0 && flags&0x10 == 0 { // SYN without ACK
			ck, _ := normalizeConn(srcIP, dstIP, srcPort, dstPort)
			if _, seen := p.synDir[ck]; !seen {
				p.synDir[ck] = dk
			}
		}

		if len(payload) > 0 {
			p.segs[dk] = append(p.segs[dk], segment{seq: seq, flags: flags, payload: payload, ts: ts})
		}
	}
}

// assembleDir concatenates payloads from one direction, sorted by seq.
func assembleDir(segs []segment) ([]byte, []time.Time) {
	if len(segs) == 0 {
		return nil, nil
	}
	sort.Slice(segs, func(i, j int) bool {
		return segs[i].seq < segs[j].seq
	})

	var result []byte
	var ts []time.Time
	lastEnd := uint32(0)
	for _, s := range segs {
		end := s.seq + uint32(len(s.payload))
		if len(result) > 0 && s.seq < lastEnd {
			// overlap/retransmit: skip already-seen bytes
			skip := int(lastEnd - s.seq)
			if skip >= len(s.payload) {
				continue
			}
			result = append(result, s.payload[skip:]...)
		} else {
			result = append(result, s.payload...)
		}
		ts = append(ts, s.ts)
		lastEnd = end
	}
	return result, ts
}

// ---- HTTP parsing ----

func parseHTTPPairs(reqData, respData []byte, sessionID, serviceID, srcIP, dstIP string, srcPort, dstPort uint16) []*sniffer.Packet {
	var packets []*sniffer.Packet

	reqReader := bufio.NewReader(bytes.NewReader(reqData))
	respReader := bufio.NewReader(bytes.NewReader(respData))

	reqTimestamp := time.Now()
	respTimestamp := time.Now()

	for i := 0; ; i++ {
		req, err := http.ReadRequest(reqReader)
		if err != nil {
			break
		}
		body, _ := io.ReadAll(req.Body)
		req.Body.Close()

		headers := make(map[string]string)
		for k, vs := range req.Header {
			headers[k] = strings.Join(vs, ", ")
		}

		pkt := &sniffer.Packet{
			ServiceID:    serviceID,
			SessionID:    sessionID,
			Timestamp:    reqTimestamp,
			SrcIP:        srcIP,
			SrcPort:      int(srcPort),
			DstIP:        dstIP,
			DstPort:      int(dstPort),
			Protocol:     "http",
			Direction:    sniffer.DirectionRequest,
			Method:       req.Method,
			URL:          req.RequestURI,
			Headers:      headers,
			Body:         body,
			MatchedRules: []sniffer.MatchedRuleInfo{},
		}
		if len(body) > 0 {
			pkt.BodyString = string(body)
		}
		packets = append(packets, pkt)

		// Try to read matching response
		resp, rerr := http.ReadResponse(respReader, nil)
		if rerr != nil {
			break
		}
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		respHeaders := make(map[string]string)
		for k, vs := range resp.Header {
			respHeaders[k] = strings.Join(vs, ", ")
		}

		rpkt := &sniffer.Packet{
			ServiceID:    serviceID,
			SessionID:    sessionID,
			Timestamp:    respTimestamp,
			SrcIP:        dstIP,
			SrcPort:      int(dstPort),
			DstIP:        srcIP,
			DstPort:      int(srcPort),
			Protocol:     "http",
			Direction:    sniffer.DirectionResponse,
			Status:       resp.StatusCode,
			Headers:      respHeaders,
			Body:         respBody,
			MatchedRules: []sniffer.MatchedRuleInfo{},
		}
		if len(respBody) > 0 {
			rpkt.BodyString = string(respBody)
		}
		packets = append(packets, rpkt)
	}
	return packets
}

// ---- Top-level API ----

// ParsePCAPAsPackets reads a .pcap file and returns reconstructed packets
// ready to be inserted into the packet store. serviceID is set on every packet.
// If flagRegex is non-nil, it is used to flag packets containing flag patterns.
// If flagChecker is non-nil, it is used to check for flag ID values.
func ParsePCAPAsPackets(r io.Reader, serviceID string, flagRegex *regexp.Regexp, flagChecker sniffer.FlagIDChecker) ([]*sniffer.Packet, error) {
	pr, err := readGlobal(r)
	if err != nil {
		return nil, err
	}
	if err := pr.readRecords(r); err != nil {
		return nil, err
	}

	// Identify unique connections (bidirectional pairs)
	seenConns := make(map[connKey]bool)
	for dk := range pr.segs {
		ck, _ := normalizeConn(dk.srcIP, dk.dstIP, dk.srcPort, dk.dstPort)
		seenConns[ck] = true
	}

	var allPackets []*sniffer.Packet

	for ck := range seenConns {
		// Determine client direction (sent SYN) or fallback to "a" side
		clientDK := dirKey{srcIP: ck.aIP, dstIP: ck.bIP, srcPort: ck.aPort, dstPort: ck.bPort}
		if sd, ok := pr.synDir[ck]; ok {
			clientDK = sd
		}
		serverDK := dirKey{
			srcIP:   clientDK.dstIP,
			dstIP:   clientDK.srcIP,
			srcPort: clientDK.dstPort,
			dstPort: clientDK.srcPort,
		}

		clientSegs := pr.segs[clientDK]
		serverSegs := pr.segs[serverDK]

		clientData, clientTS := assembleDir(clientSegs)
		serverData, serverTS := assembleDir(serverSegs)

		if len(clientData) == 0 && len(serverData) == 0 {
			continue
		}

		sessionID := fmt.Sprintf("imported-%s:%d-%s:%d",
			clientDK.srcIP, clientDK.srcPort, clientDK.dstIP, clientDK.dstPort)

		// Try HTTP parsing
		httpPackets := parseHTTPPairs(clientData, serverData, sessionID, serviceID,
			clientDK.srcIP, clientDK.dstIP, clientDK.srcPort, clientDK.dstPort)

		if len(httpPackets) > 0 {
			// HTTP parsed successfully: use those packets
			// Set timestamps from segment timestamps
			for i, pkt := range httpPackets {
				if i < len(clientTS) && pkt.Direction == sniffer.DirectionRequest {
					pkt.Timestamp = clientTS[0]
				} else if len(serverTS) > 0 && pkt.Direction == sniffer.DirectionResponse {
					pkt.Timestamp = serverTS[0]
				}
			}
			allPackets = append(allPackets, httpPackets...)
		} else {
			// Fallback: emit raw TCP chunks per direction
			if len(clientData) > 0 {
				ts := time.Now()
				if len(clientTS) > 0 {
					ts = clientTS[0]
				}
				pkt := &sniffer.Packet{
					ServiceID:    serviceID,
					SessionID:    sessionID,
					Timestamp:    ts,
					SrcIP:        clientDK.srcIP,
					SrcPort:      int(clientDK.srcPort),
					DstIP:        clientDK.dstIP,
					DstPort:      int(clientDK.dstPort),
					Protocol:     "tcp",
					Direction:    sniffer.DirectionRequest,
					Body:         clientData,
					MatchedRules: []sniffer.MatchedRuleInfo{},
				}
				if len(clientData) <= 512*1024 {
					pkt.BodyString = string(clientData)
				}
				allPackets = append(allPackets, pkt)
			}
			if len(serverData) > 0 {
				ts := time.Now()
				if len(serverTS) > 0 {
					ts = serverTS[0]
				}
				pkt := &sniffer.Packet{
					ServiceID:    serviceID,
					SessionID:    sessionID,
					Timestamp:    ts,
					SrcIP:        clientDK.dstIP,
					SrcPort:      int(clientDK.dstPort),
					DstIP:        clientDK.srcIP,
					DstPort:      int(clientDK.srcPort),
					Protocol:     "tcp",
					Direction:    sniffer.DirectionResponse,
					Body:         serverData,
					MatchedRules: []sniffer.MatchedRuleInfo{},
				}
				if len(serverData) <= 512*1024 {
					pkt.BodyString = string(serverData)
				}
				allPackets = append(allPackets, pkt)
			}
		}
	}

	// Apply flag/flagID checks
	for _, pkt := range allPackets {
		pkt.Flagged = sniffer.CheckFlagged(flagRegex, nil, pkt.URL, "", pkt.Body)
		if flagChecker != nil {
			pkt.ContainsFlagID, pkt.MatchedFlagIDs, pkt.FlagIDRound =
				sniffer.CheckFlagID(flagChecker, pkt.URL, "", pkt.Body)
		}
		if pkt.MatchedFlagIDs == nil {
			pkt.MatchedFlagIDs = []string{}
		}
	}

	// Sort by timestamp
	sort.Slice(allPackets, func(i, j int) bool {
		return allPackets[i].Timestamp.Before(allPackets[j].Timestamp)
	})

	return allPackets, nil
}
