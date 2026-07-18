package api

import (
	"crypto/tls"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/SimoneErrigo/Janus/backend/internal/config"
	"github.com/SimoneErrigo/Janus/backend/internal/storage"
)

// applyServiceDefaults fills in implicit values before validation. Today it
// defaults the listen host to the configured TEAM_IP so operators don't have to
// retype their team address for every service: leaving listen_addr empty (or
// giving just a ":port"/port form) binds the service to TEAM_IP.
func applyServiceDefaults(svc *storage.Service) {
	teamIP := strings.TrimSpace(config.Get().DataPlane.DefaultBind)
	addr := strings.TrimSpace(svc.ListenAddr)
	switch {
	case addr == "" && teamIP != "":
		svc.ListenAddr = teamIP
	case strings.HasPrefix(addr, ":") && teamIP != "":
		// ":8080" — a bare port; adopt TEAM_IP as the host and, when
		// listen_port wasn't set separately, take the port from here too.
		if svc.ListenPort == 0 {
			fmt.Sscanf(addr[1:], "%d", &svc.ListenPort)
		}
		svc.ListenAddr = teamIP
	}

	// TLS-terminating presets should work after selecting the protocol alone.
	// Self-signed is the safe CTF default; challenge certificates remain an
	// optional advanced override.
	if preset, ok := storage.LookupProtocolPreset(svc.Protocol); ok && preset.Spec.Listener.TLS == storage.ClientTLSTerminate && svc.TLSMode == storage.TLSModeNone {
		svc.TLSMode = storage.TLSModeSelfSigned
	}
}

// serviceIDPattern restricts service IDs to characters that survive URL paths
// and JSON round-trips without surprises. Whitespace, BOMs and zero-width
// characters slip through json.Unmarshal silently and break later map lookups
// (LIST returns the service but UPDATE/DELETE 404s on the URL-derived key).
var serviceIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

const maxStaticCaptureServices = 256

// normalizeCaptureServiceIDs gives the static-capture preset deterministic set
// semantics. An empty result is intentionally preserved as "capture nothing".
func normalizeCaptureServiceIDs(values []string) ([]string, error) {
	if len(values) > maxStaticCaptureServices {
		return nil, fmt.Errorf("static capture supports at most %d services", maxStaticCaptureServices)
	}
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		id := strings.TrimSpace(raw)
		if id == "" || len(id) > 128 || !serviceIDPattern.MatchString(id) {
			return nil, fmt.Errorf("static capture service IDs must match %s", serviceIDPattern.String())
		}
		seen[id] = struct{}{}
	}
	result := make([]string, 0, len(seen))
	for id := range seen {
		result = append(result, id)
	}
	sort.Strings(result)
	return result, nil
}

func (s *Server) validateCaptureServiceIDs(serviceIDs []string, requireEnabled bool) error {
	if s.store == nil {
		return fmt.Errorf("service store is unavailable")
	}
	for _, id := range serviceIDs {
		svc, ok := s.store.GetService(id)
		if !ok {
			return fmt.Errorf("static capture service %q does not exist", id)
		}
		if requireEnabled && !svc.Enabled {
			return fmt.Errorf("static capture service %q is disabled", id)
		}
	}
	return nil
}

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
	if len(svc.ID) > 128 || !serviceIDPattern.MatchString(svc.ID) {
		return fmt.Errorf("id must match %s", serviceIDPattern.String())
	}
	svc.Name = strings.TrimSpace(svc.Name)
	if svc.Name == "" {
		return fmt.Errorf("name is required")
	}
	if len(svc.Name) > 256 || len(svc.ListenAddr) > 512 || len(svc.TargetAddr) > 2048 {
		return fmt.Errorf("service name or address is too long")
	}
	if len(svc.CertFile) > 4096 || len(svc.KeyFile) > 4096 || len(svc.ProtocolID) > 128 {
		return fmt.Errorf("service path or protocol id is too long")
	}
	if len(svc.ProtoPaths) > 128 {
		return fmt.Errorf("at most 128 proto paths are supported")
	}
	for _, path := range svc.ProtoPaths {
		if len(path) > 4096 {
			return fmt.Errorf("proto path is too long")
		}
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
		host, portText, err := net.SplitHostPort(svc.TargetAddr)
		port, portErr := strconv.Atoi(portText)
		if err != nil || portErr != nil || strings.TrimSpace(host) == "" || port < 1 || port > 65535 {
			return fmt.Errorf("target_addr must be a host:port address")
		}
	} else if svc.ListenPort < 0 || svc.ListenPort > 65535 {
		// Partial config is fine on disabled services, but reject obviously
		// out-of-range port numbers so we don't store garbage.
		return fmt.Errorf("listen_port must be between 0 and 65535")
	}

	if _, ok := storage.LookupProtocolPreset(svc.Protocol); !ok {
		return fmt.Errorf("unknown protocol preset %q", svc.Protocol)
	}

	// TLS validation also only matters if the proxy will actually start.
	if svc.Enabled && svc.RuntimeSpec().Listener.TLS == storage.ClientTLSTerminate {
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
			if _, err := tls.LoadX509KeyPair(svc.CertFile, svc.KeyFile); err != nil {
				return fmt.Errorf("invalid challenge TLS certificate or key: %w", err)
			}
		}
	}

	return nil
}
