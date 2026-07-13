package storage

// ProtocolPreset derives the normalized runtime model from the single
// protocol choice exposed by the beginner service setup.
func ProtocolPreset(protocol Protocol) ServiceSpec {
	spec := ServiceSpec{
		Listener: ListenerSpec{Transport: TransportTCP, TLS: ClientTLSOff},
		Upstream: UpstreamSpec{},
		Framing:  FramingSpec{Mode: FramingRaw},
	}
	switch protocol {
	case ProtocolHTTP:
		spec.Application.Profile = ApplicationHTTP
		spec.Framing.Mode = FramingHTTP
	case ProtocolHTTPS:
		spec.Application.Profile = ApplicationHTTP
		spec.Listener.TLS = ClientTLSTerminate
		spec.Framing.Mode = FramingHTTP
	case ProtocolWS:
		spec.Application.Profile = ApplicationWebSocket
		spec.Framing.Mode = FramingHTTP
	case ProtocolWSS:
		spec.Application.Profile = ApplicationWebSocket
		spec.Listener.TLS = ClientTLSTerminate
		spec.Framing.Mode = FramingHTTP
	case ProtocolHTTP2:
		spec.Application.Profile = ApplicationHTTP2
		spec.Listener.TLS = ClientTLSTerminate
		spec.Framing.Mode = FramingHTTP
	case ProtocolGRPC:
		spec.Application.Profile = ApplicationGRPC
		spec.Listener.TLS = ClientTLSTerminate
		spec.Framing.Mode = FramingHTTP
	case ProtocolTCP:
		spec.Application.Profile = ApplicationRaw
	}
	return spec
}

// ApplyProtocolPreset materializes the selected protocol into Spec. Existing
// API fields remain the easy editing surface and are mirrored into the spec.
func (s *Service) ApplyProtocolPreset() {
	spec := ProtocolPreset(s.Protocol)
	spec.Listener.Address = s.ListenAddr
	spec.Listener.Port = s.ListenPort
	spec.Upstream.Address = s.TargetAddr
	spec.Upstream.TLS = s.TargetTLS
	s.Spec = spec
	s.ModelVersion = ServiceModelVersion
}

// Migrate upgrades a legacy service record in memory. It returns true when
// the persisted representation needs to be rewritten.
func (s *Service) Migrate() bool {
	if s.ModelVersion >= ServiceModelVersion && s.Spec.Listener.Transport != "" {
		return false
	}
	s.ApplyProtocolPreset()
	return true
}

// RuntimeSpec returns a complete spec even for a Service constructed directly
// by older tests or integrations that have not passed through Store migration.
func (s *Service) RuntimeSpec() ServiceSpec {
	if s.ModelVersion >= ServiceModelVersion && s.Spec.Listener.Transport != "" {
		return s.Spec
	}
	clone := *s
	clone.ApplyProtocolPreset()
	return clone.Spec
}
