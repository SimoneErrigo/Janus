package storage

import "sort"

const ProtocolPresetRevision = 1

// ProtocolPresetInfo is the single source of truth used by validation, the
// runtime and the beginner-facing selector. Spec contains no addresses: those
// are copied from the service when the preset is selected.
type ProtocolPresetInfo struct {
	ID           Protocol    `json:"id"`
	Label        string      `json:"label"`
	Group        string      `json:"group"`
	Description  string      `json:"description"`
	Stability    string      `json:"stability"`
	Capabilities []string    `json:"capabilities"`
	Spec         ServiceSpec `json:"spec"`
}

func preset(id Protocol, label, group, description, stability string, transport Transport, app ApplicationProfile, tls ClientTLSMode, framing FramingMode, capabilities ...string) ProtocolPresetInfo {
	return ProtocolPresetInfo{
		ID: id, Label: label, Group: group, Description: description,
		Stability: stability, Capabilities: capabilities,
		Spec: ServiceSpec{
			Listener:    ListenerSpec{Transport: transport, TLS: tls},
			Application: ApplicationSpec{Profile: app},
			Framing:     FramingSpec{Mode: framing},
		},
	}
}

var protocolRegistry = map[Protocol]ProtocolPresetInfo{
	ProtocolHTTP:    preset(ProtocolHTTP, "HTTP", "Web", "HTTP/1.1 reverse proxy", "stable", TransportTCP, ApplicationHTTP, ClientTLSOff, FramingHTTP, "http", "stream", "rewrite"),
	ProtocolHTTPS:   preset(ProtocolHTTPS, "HTTPS", "Web", "HTTP with client-side TLS termination", "stable", TransportTCP, ApplicationHTTP, ClientTLSTerminate, FramingHTTP, "http", "stream", "tls-terminate", "rewrite"),
	ProtocolWS:      preset(ProtocolWS, "WebSocket", "Web", "WebSocket messages over HTTP", "stable", TransportTCP, ApplicationWebSocket, ClientTLSOff, FramingHTTP, "http", "websocket", "stream", "rewrite"),
	ProtocolWSS:     preset(ProtocolWSS, "WebSocket TLS", "Web", "WebSocket with client-side TLS termination", "stable", TransportTCP, ApplicationWebSocket, ClientTLSTerminate, FramingHTTP, "http", "websocket", "stream", "tls-terminate", "rewrite"),
	ProtocolHTTP2:   preset(ProtocolHTTP2, "HTTP/2 TLS", "Web", "HTTP/2 with TLS termination", "stable", TransportTCP, ApplicationHTTP2, ClientTLSTerminate, FramingHTTP, "http", "http2", "stream", "tls-terminate"),
	ProtocolH2C:     preset(ProtocolH2C, "HTTP/2 cleartext", "Web", "HTTP/2 without TLS (h2c)", "stable", TransportTCP, ApplicationHTTP2, ClientTLSOff, FramingHTTP, "http", "http2", "stream"),
	ProtocolGRPC:    preset(ProtocolGRPC, "gRPC TLS", "Web", "gRPC over HTTP/2 with TLS termination", "stable", TransportTCP, ApplicationGRPC, ClientTLSTerminate, FramingHTTP, "http", "http2", "grpc", "stream", "tls-terminate"),
	ProtocolGRPCH2C: preset(ProtocolGRPCH2C, "gRPC cleartext", "Web", "gRPC over cleartext HTTP/2", "experimental", TransportTCP, ApplicationGRPC, ClientTLSOff, FramingHTTP, "http", "http2", "grpc", "stream"),
	ProtocolTCP:     preset(ProtocolTCP, "TCP raw", "Generic", "Raw TCP chunks", "stable", TransportTCP, ApplicationRaw, ClientTLSOff, FramingRaw, "stream", "rewrite"),
	ProtocolTCPLine: preset(ProtocolTCPLine, "TCP line", "Generic", "TCP split on newline", "stable", TransportTCP, ApplicationRaw, ClientTLSOff, FramingLine, "stream", "framed", "rewrite"),
	ProtocolTLS:     preset(ProtocolTLS, "TLS raw", "Generic", "Raw TCP with client-side TLS termination", "stable", TransportTCP, ApplicationRaw, ClientTLSTerminate, FramingRaw, "stream", "tls-terminate", "rewrite"),
	ProtocolUDP:     preset(ProtocolUDP, "UDP raw", "Generic", "One message per UDP datagram", "stable", TransportUDP, ApplicationRaw, ClientTLSOff, FramingRaw, "datagram", "rewrite"),
	ProtocolDNS:     preset(ProtocolDNS, "DNS", "Decoded", "DNS over UDP with structured fields", "stable", TransportUDP, ApplicationDNS, ClientTLSOff, FramingRaw, "datagram", "decoded", "rewrite"),
	ProtocolDNSTCP:  preset(ProtocolDNSTCP, "DNS over TCP", "Decoded", "Length-prefixed DNS over TCP", "stable", TransportTCP, ApplicationDNS, ClientTLSOff, FramingLengthPrefix, "stream", "framed", "decoded", "rewrite"),
	ProtocolRESP:    preset(ProtocolRESP, "Redis / RESP2", "Decoded", "Redis RESP2 messages and commands", "stable", TransportTCP, ApplicationRESP, ClientTLSOff, FramingRESP, "stream", "framed", "decoded", "rewrite"),
	ProtocolMQTT:    preset(ProtocolMQTT, "MQTT 3.1.1", "Decoded", "MQTT control packets and topics", "experimental", TransportTCP, ApplicationMQTT, ClientTLSOff, FramingMQTT, "stream", "framed", "decoded", "rewrite"),
}

func init() {
	dnsTCP := protocolRegistry[ProtocolDNSTCP]
	dnsTCP.Spec.Framing.PrefixBytes = 2
	protocolRegistry[ProtocolDNSTCP] = dnsTCP
}

func ProtocolPresets() []ProtocolPresetInfo {
	out := make([]ProtocolPresetInfo, 0, len(protocolRegistry))
	for _, item := range protocolRegistry {
		item.Capabilities = append([]string(nil), item.Capabilities...)
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Group != out[j].Group {
			return out[i].Group < out[j].Group
		}
		return out[i].Label < out[j].Label
	})
	return out
}

func LookupProtocolPreset(id Protocol) (ProtocolPresetInfo, bool) {
	p, ok := protocolRegistry[id]
	return p, ok
}
