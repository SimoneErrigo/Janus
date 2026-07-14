package storage

// ProtocolPreset derives the normalized runtime model from the single
// protocol choice exposed by the beginner service setup.
func ProtocolPreset(protocol Protocol) ServiceSpec {
	if p, ok := LookupProtocolPreset(protocol); ok {
		return p.Spec
	}
	return ServiceSpec{Listener: ListenerSpec{Transport: TransportTCP, TLS: ClientTLSOff}, Application: ApplicationSpec{Profile: ApplicationRaw}, Framing: FramingSpec{Mode: FramingRaw}}
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
	s.PresetRevision = ProtocolPresetRevision
}

// NormalizeSpec preserves advanced framing/decoder choices while keeping the
// addresses mirrored from the beginner-facing fields. Selecting a different
// protocol explicitly calls ApplyProtocolPreset instead.
func (s *Service) NormalizeSpec() {
	if s.Spec.Listener.Transport == "" || s.Spec.Application.Profile == "" || s.Spec.Framing.Mode == "" {
		s.ApplyProtocolPreset()
		return
	}
	s.Spec.Listener.Address = s.ListenAddr
	s.Spec.Listener.Port = s.ListenPort
	s.Spec.Upstream.Address = s.TargetAddr
	s.Spec.Upstream.TLS = s.TargetTLS
	s.ModelVersion = ServiceModelVersion
	if s.PresetRevision == 0 {
		s.PresetRevision = ProtocolPresetRevision
	}
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
	if s.Spec.Listener.Transport != "" {
		return s.Spec
	}
	clone := *s
	clone.ApplyProtocolPreset()
	return clone.Spec
}
