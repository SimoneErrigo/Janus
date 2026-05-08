package storage

// Protocol represents the proxy protocol type.
type Protocol string

const (
	ProtocolHTTP  Protocol = "http"
	ProtocolHTTPS Protocol = "https"
	ProtocolHTTP2 Protocol = "h2"
	ProtocolGRPC  Protocol = "grpc"
	ProtocolTCP   Protocol = "tcp"
)

// TLSMode represents how TLS is handled.
type TLSMode string

const (
	TLSModeNone       TLSMode = ""
	TLSModeSelfSigned TLSMode = "selfsigned"
	TLSModeChallenge  TLSMode = "challenge"
)

// Service represents a proxied CTF challenge service.
type Service struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	ListenAddr string   `json:"listen_addr"` // e.g. "10.10.0.1:8080"
	ListenPort int      `json:"listen_port"`
	TargetAddr string   `json:"target_addr"` // e.g. "127.0.0.1:9080"
	Protocol   Protocol `json:"protocol"`
	TLSMode    TLSMode  `json:"tls_mode,omitempty"`
	CertFile   string   `json:"cert_file,omitempty"`   // path for challenge mode
	KeyFile    string   `json:"key_file,omitempty"`    // path for challenge mode
	TargetTLS  bool     `json:"target_tls,omitempty"`  // connect to backend with TLS
	ProtoPaths []string `json:"proto_paths,omitempty"` // gRPC: paths to .proto files for body decoding
	Enabled    bool     `json:"enabled"`
}
