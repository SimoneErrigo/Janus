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
	if svc.ListenAddr == "" {
		return fmt.Errorf("listen_addr is required")
	}
	if svc.ListenPort <= 0 || svc.ListenPort > 65535 {
		return fmt.Errorf("listen_port must be between 1 and 65535")
	}
	if svc.TargetAddr == "" {
		return fmt.Errorf("target_addr is required")
	}

	switch svc.Protocol {
	case storage.ProtocolHTTP, storage.ProtocolHTTPS, storage.ProtocolHTTP2, storage.ProtocolGRPC, storage.ProtocolTCP:
		// valid
	default:
		return fmt.Errorf("protocol must be one of: http, https, h2, grpc, tcp")
	}

	// TLS validation
	if svc.Protocol == storage.ProtocolHTTPS || svc.Protocol == storage.ProtocolHTTP2 || svc.Protocol == storage.ProtocolGRPC {
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
