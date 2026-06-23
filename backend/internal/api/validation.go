package api

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/SimoneErrigo/Janus/backend/internal/storage"
)

// serviceIDPattern restricts service IDs to characters that survive URL paths
// and JSON round-trips without surprises. Whitespace, BOMs and zero-width
// characters slip through json.Unmarshal silently and break later map lookups
// (LIST returns the service but UPDATE/DELETE 404s on the URL-derived key).
var serviceIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// slugifyServiceID derives a URL/JSON-safe service id from a human name, e.g.
// "Buggy Web!" -> "buggy-web". Returns "" when the name has no usable chars.
func slugifyServiceID(name string) string {
	var b strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' {
			b.WriteRune(r)
			lastDash = false
		} else if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-._")
}

// uniqueServiceID builds a service id from name and bumps a numeric suffix
// until taken() reports the id is free.
func uniqueServiceID(name string, taken func(string) bool) string {
	base := slugifyServiceID(name)
	if base == "" {
		base = "svc"
	}
	id := base
	for i := 2; taken(id); i++ {
		id = fmt.Sprintf("%s-%d", base, i)
	}
	return id
}

func validateService(svc *storage.Service) error {
	svc.ID = strings.TrimSpace(svc.ID)
	if svc.ID == "" {
		return fmt.Errorf("id is required")
	}
	if !serviceIDPattern.MatchString(svc.ID) {
		return fmt.Errorf("id must match %s", serviceIDPattern.String())
	}
	if svc.Name == "" {
		return fmt.Errorf("name is required")
	}

	// Proxy fields are required only when the service is enabled (the proxy
	// actually tries to listen). Disabled services — including the virtual
	// ones auto-created by PCAP import — carry empty addresses because
	// they're just packet containers, not proxy targets. Re-enabling such a
	// service later forces the user to fill in the fields at that moment.
	if svc.Enabled {
		if svc.ListenAddr == "" {
			return fmt.Errorf("listen_addr is required when service is enabled")
		}
		if svc.ListenPort <= 0 || svc.ListenPort > 65535 {
			return fmt.Errorf("listen_port must be between 1 and 65535 when service is enabled")
		}
		if svc.TargetAddr == "" {
			return fmt.Errorf("target_addr is required when service is enabled")
		}
	} else if svc.ListenPort < 0 || svc.ListenPort > 65535 {
		// Partial config is fine on disabled services, but reject obviously
		// out-of-range port numbers so we don't store garbage.
		return fmt.Errorf("listen_port must be between 0 and 65535")
	}

	switch svc.Protocol {
	case storage.ProtocolHTTP, storage.ProtocolHTTPS, storage.ProtocolHTTP2, storage.ProtocolGRPC, storage.ProtocolTCP:
		// valid
	default:
		return fmt.Errorf("protocol must be one of: http, https, h2, grpc, tcp")
	}

	// TLS validation also only matters if the proxy will actually start.
	if svc.Enabled && (svc.Protocol == storage.ProtocolHTTPS || svc.Protocol == storage.ProtocolHTTP2 || svc.Protocol == storage.ProtocolGRPC) {
		switch svc.TLSMode {
		case storage.TLSModeSelfSigned, storage.TLSModeChallenge:
			// valid
		default:
			return fmt.Errorf("tls_mode must be 'selfsigned' or 'challenge' for protocol %s", svc.Protocol)
		}
		if svc.TLSMode == storage.TLSModeChallenge {
			if svc.CertFile == "" || svc.KeyFile == "" {
				return fmt.Errorf("cert_file and key_file are required for challenge TLS mode")
			}
		}
	}

	return nil
}
