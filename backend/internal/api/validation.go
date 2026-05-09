package api

import (
	"fmt"

	"github.com/SimoneErrigo/Janus/backend/internal/storage"
)

func validateService(svc *storage.Service) error {
	if svc.ID == "" {
		return fmt.Errorf("id is required")
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
