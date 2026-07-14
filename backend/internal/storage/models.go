package storage

// Protocol represents the proxy protocol type.
type Protocol string

const (
	ProtocolHTTP    Protocol = "http"
	ProtocolHTTPS   Protocol = "https"
	ProtocolWS      Protocol = "ws"
	ProtocolWSS     Protocol = "wss"
	ProtocolHTTP2   Protocol = "h2"
	ProtocolH2C     Protocol = "h2c"
	ProtocolGRPC    Protocol = "grpc"
	ProtocolGRPCH2C Protocol = "grpc-h2c"
	ProtocolTCP     Protocol = "tcp"
	ProtocolTCPLine Protocol = "tcp-line"
	ProtocolTLS     Protocol = "tls"
	ProtocolUDP     Protocol = "udp"
	ProtocolDNS     Protocol = "dns"
	ProtocolDNSTCP  Protocol = "dns-tcp"
	ProtocolRESP    Protocol = "resp"
	ProtocolMQTT    Protocol = "mqtt"
)

// ServiceModelVersion is the current persisted service schema. Protocol stays
// as the beginner-facing preset while Spec is the normalized runtime model.
const ServiceModelVersion = 3

// Transport identifies the network transport used by a service listener.
type Transport string

const (
	TransportTCP Transport = "tcp"
	TransportUDP Transport = "udp"
)

// ApplicationProfile selects the application-aware proxy behaviour.
type ApplicationProfile string

const (
	ApplicationRaw       ApplicationProfile = "raw"
	ApplicationHTTP      ApplicationProfile = "http"
	ApplicationWebSocket ApplicationProfile = "websocket"
	ApplicationHTTP2     ApplicationProfile = "http2"
	ApplicationGRPC      ApplicationProfile = "grpc"
	ApplicationDNS       ApplicationProfile = "dns"
	ApplicationRESP      ApplicationProfile = "resp"
	ApplicationMQTT      ApplicationProfile = "mqtt"
)

// ClientTLSMode describes TLS on the client-facing side. Passthrough is part
// of the normalized model even though no beginner preset currently selects it.
type ClientTLSMode string

const (
	ClientTLSOff         ClientTLSMode = "off"
	ClientTLSTerminate   ClientTLSMode = "terminate"
	ClientTLSPassthrough ClientTLSMode = "passthrough"
)

// FramingMode determines how a byte stream is split into application frames.
// HTTP-family profiles are framed by net/http; raw TCP currently defaults to
// raw chunks and can opt into the generic stream framers later.
type FramingMode string

const (
	FramingRaw          FramingMode = "raw"
	FramingHTTP         FramingMode = "http"
	FramingLine         FramingMode = "line"
	FramingDelimiter    FramingMode = "delimiter"
	FramingFixed        FramingMode = "fixed"
	FramingLengthPrefix FramingMode = "length-prefix"
	FramingRESP         FramingMode = "resp"
	FramingMQTT         FramingMode = "mqtt"
	FramingCustom       FramingMode = "custom"
)

type ListenerSpec struct {
	Address   string        `json:"address"`
	Port      int           `json:"port"`
	Transport Transport     `json:"transport"`
	TLS       ClientTLSMode `json:"tls"`
}

type ApplicationSpec struct {
	Profile ApplicationProfile `json:"profile"`
}

type UpstreamSpec struct {
	Address string `json:"address"`
	TLS     bool   `json:"tls"`
}

type FramingSpec struct {
	Mode         FramingMode `json:"mode"`
	Delimiter    string      `json:"delimiter,omitempty"`
	FixedLength  int         `json:"fixed_length,omitempty"`
	PrefixBytes  int         `json:"prefix_bytes,omitempty"`
	LittleEndian bool        `json:"little_endian,omitempty"`
}

// ServiceSpec is the normalized, composable model consumed by the data plane.
// It is generated from ProtocolPreset for the beginner flow, so users never
// have to understand transport/TLS/framing just to configure a service.
type ServiceSpec struct {
	Listener    ListenerSpec    `json:"listener"`
	Application ApplicationSpec `json:"application"`
	Upstream    UpstreamSpec    `json:"upstream"`
	Framing     FramingSpec     `json:"framing"`
}

// TLSMode represents how TLS is handled.
type TLSMode string

const (
	TLSModeNone       TLSMode = ""
	TLSModeSelfSigned TLSMode = "selfsigned"
	TLSModeChallenge  TLSMode = "challenge"
)

// Service represents a proxied CTF challenge service.
type Service struct {
	ID             string      `json:"id"`
	Name           string      `json:"name"`
	ModelVersion   int         `json:"model_version"`
	Protocol       Protocol    `json:"protocol"` // beginner-facing preset
	PresetRevision int         `json:"preset_revision,omitempty"`
	Spec           ServiceSpec `json:"spec"`        // normalized runtime model
	ListenAddr     string      `json:"listen_addr"` // legacy/API compatibility
	ListenPort     int         `json:"listen_port"`
	TargetAddr     string      `json:"target_addr"` // legacy/API compatibility
	TLSMode        TLSMode     `json:"tls_mode,omitempty"`
	CertFile       string      `json:"cert_file,omitempty"`   // path for challenge mode
	KeyFile        string      `json:"key_file,omitempty"`    // path for challenge mode
	TargetTLS      bool        `json:"target_tls,omitempty"`  // connect to backend with TLS
	ProtoPaths     []string    `json:"proto_paths,omitempty"` // gRPC: paths to .proto files for body decoding
	ProtocolID     string      `json:"protocol_id,omitempty"` // custom protocol decoder (Step 14)
	Enabled        bool        `json:"enabled"`
}

// FieldType enumerates the wire-level types supported by the custom protocol
// decoder. The values are string-encoded so they survive round-trips through
// the JSON config file and the REST API without ambiguity.
type FieldType string

const (
	FieldU8          FieldType = "u8"
	FieldU16         FieldType = "u16"
	FieldU32         FieldType = "u32"
	FieldU64         FieldType = "u64"
	FieldI8          FieldType = "i8"
	FieldI16         FieldType = "i16"
	FieldI32         FieldType = "i32"
	FieldI64         FieldType = "i64"
	FieldF32         FieldType = "f32"
	FieldF64         FieldType = "f64"
	FieldBytesFixed  FieldType = "bytes_fixed"
	FieldStringFixed FieldType = "string_fixed"
	FieldStringLPU8  FieldType = "string_lp_u8"
	FieldStringLPU16 FieldType = "string_lp_u16"
	FieldBytesLPU8   FieldType = "bytes_lp_u8"
	FieldBytesLPU16  FieldType = "bytes_lp_u16"
	FieldRemaining   FieldType = "remaining_bytes"
	FieldDispatch    FieldType = "dispatch"
	FieldBytesComp   FieldType = "bytes_computed"
)

// ProtocolField describes a single decoded field. `Length` is meaningful only
// for fixed-length variants; `EnumRef` ties a numeric field to an enum so the
// decoder substitutes the label; `DispatchOn` names a previous enum-typed
// field whose label selects the struct used to decode the payload.
type ProtocolField struct {
	Name       string    `json:"name"`
	Type       FieldType `json:"type"`
	Length     int       `json:"length,omitempty"`      // bytes_fixed / string_fixed
	EnumRef    string    `json:"enum_ref,omitempty"`    // u8/u16/u32/u64/i*
	DispatchOn string    `json:"dispatch_on,omitempty"` // dispatch type only
	// bytes_computed: length is computed from previous numeric fields as
	//   ceil(value(LengthFrom) * value(LengthMulFrom) / LengthDiv)
	// LengthMulFrom is optional (defaults to multiplier 1); LengthDiv is
	// optional (defaults to 1). The ceiling division matches the way most
	// protocols round up bit-packed payloads (e.g. dim*dim/8 cells).
	LengthFrom    string `json:"length_from,omitempty"`
	LengthMulFrom string `json:"length_mul_from,omitempty"`
	LengthDiv     int    `json:"length_div,omitempty"`
}

// Endian represents byte order. Empty string defaults to little-endian.
type Endian string

const (
	EndianLittle Endian = "little"
	EndianBig    Endian = "big"
)

// CustomProtocol is the persisted definition of a user-built binary
// protocol used by the custom decoder. The decoder walks `RequestFields`
// for inbound packets and `ResponseFields` for outbound ones; `Enums` and
// `Structs` are referenced by name from those field lists.
//
// (Named CustomProtocol rather than Protocol to avoid colliding with the
// existing string-typed `Protocol` used for proxy/wire protocols above.)
type CustomProtocol struct {
	ID             string                       `json:"id"`
	Name           string                       `json:"name"`
	Endian         Endian                       `json:"endian,omitempty"`
	Enums          map[string]map[string]string `json:"enums,omitempty"`   // enum name -> { "0": "SIGNUP", ... }
	Structs        map[string][]ProtocolField   `json:"structs,omitempty"` // struct name -> fields
	RequestFields  []ProtocolField              `json:"request_fields,omitempty"`
	ResponseFields []ProtocolField              `json:"response_fields,omitempty"`
	CreatedAt      int64                        `json:"created_at,omitempty"`
	UpdatedAt      int64                        `json:"updated_at,omitempty"`
}
