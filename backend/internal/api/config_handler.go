package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/SimoneErrigo/Janus/backend/internal/cleanup"
	"github.com/SimoneErrigo/Janus/backend/internal/config"
	"github.com/SimoneErrigo/Janus/backend/internal/flagids"
	"github.com/SimoneErrigo/Janus/backend/internal/scoring"
	"github.com/SimoneErrigo/Janus/backend/internal/sniffer"
)

type configResponse struct {
	// Passwords are write-only: the dashboard only needs to know whether one is
	// configured, never its value.
	TeamPassword    string `json:"team_password"`
	TeamPasswordSet bool   `json:"team_password_set"`
	FlagRegex       string `json:"flag_regex"`

	FlagRegexCaseInsensitive bool   `json:"flag_regex_case_insensitive"`
	FlagDecodeURL            bool   `json:"flag_decode_url"`
	TeamIP                   string `json:"team_ip"`

	FlagIDEnabled      bool   `json:"flagid_enabled"`
	FlagIDActive       bool   `json:"flagid_active"`
	FlagIDAPIURL       string `json:"flagid_api_url"`
	FlagIDTeamID       string `json:"flagid_team_id"`
	FlagIDPollInterval int    `json:"flagid_poll_interval"`
	FlagIDFormat       string `json:"flagid_format"`

	RoundDurationSec         int                                  `json:"round_duration_seconds"`
	CompetitionStart         string                               `json:"competition_start,omitempty"`
	KeepRounds               int                                  `json:"keep_rounds"`
	BaselineStartRound       int                                  `json:"baseline_start_round"`
	BaselineEndRound         int                                  `json:"baseline_end_round"`
	BaselineServiceRounds    map[string]config.BaselineRoundRange `json:"baseline_service_rounds"`
	CurrentRound             int                                  `json:"current_round"`
	TrafficMode              string                               `json:"traffic_mode"`
	StaticCaptureServiceIDs  []string                             `json:"static_capture_service_ids"`
	ScoringEnabled           bool                                 `json:"scoring_enabled"`
	PyFilterEnabled          bool                                 `json:"pyfilter_enabled"`
	FlowCorrelationWindowSec int                                  `json:"flow_correlation_window_seconds"`
	PcapExportDir            string                               `json:"pcap_export_dir"`
	PcapAutoSave             bool                                 `json:"pcap_auto_save"`
}

type configUpdateRequest struct {
	TeamPassword *string `json:"team_password,omitempty"`
	FlagRegex    *string `json:"flag_regex,omitempty"`

	FlagIDEnabled      *bool   `json:"flagid_enabled,omitempty"`
	FlagIDAPIURL       *string `json:"flagid_api_url,omitempty"`
	FlagIDTeamID       *string `json:"flagid_team_id,omitempty"`
	FlagIDPollInterval *int    `json:"flagid_poll_interval,omitempty"`
	FlagIDFormat       *string `json:"flagid_format,omitempty"`

	RoundDurationSec         *int                                 `json:"round_duration_seconds,omitempty"`
	CompetitionStart         *string                              `json:"competition_start,omitempty"`
	KeepRounds               *int                                 `json:"keep_rounds,omitempty"`
	BaselineStartRound       *int                                 `json:"baseline_start_round,omitempty"`
	BaselineEndRound         *int                                 `json:"baseline_end_round,omitempty"`
	BaselineServiceRounds    map[string]config.BaselineRoundRange `json:"baseline_service_rounds,omitempty"`
	TrafficMode              *string                              `json:"traffic_mode,omitempty"`
	StaticCaptureServiceIDs  *[]string                            `json:"static_capture_service_ids,omitempty"`
	ScoringEnabled           *bool                                `json:"scoring_enabled,omitempty"`
	PyFilterEnabled          *bool                                `json:"pyfilter_enabled,omitempty"`
	FlowCorrelationWindowSec *int                                 `json:"flow_correlation_window_seconds,omitempty"`
	PcapExportDir            *string                              `json:"pcap_export_dir,omitempty"`
	PcapAutoSave             *bool                                `json:"pcap_auto_save,omitempty"`
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.getConfig(w, r)
	case http.MethodPut:
		s.updateConfig(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) getConfig(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.configResponse(config.Get()))
}

func (s *Server) updateConfig(w http.ResponseWriter, r *http.Request) {
	// Persisting and applying a configuration change is one transaction from
	// the operator's point of view. Serialize the whole sequence so concurrent
	// saves cannot publish settings in one order and apply side effects in the
	// opposite order.
	s.configMu.Lock()
	defer s.configMu.Unlock()

	var req configUpdateRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	previous := config.Get()
	candidate := *previous
	if err := applyConfigUpdate(&candidate, req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.StaticCaptureServiceIDs != nil {
		if err := s.validateCaptureServiceIDs(candidate.StaticCaptureServiceIDs, false); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	next, err := config.Update(func(next *config.Config) error {
		*next = candidate
		return nil
	})
	if err != nil {
		http.Error(w, "saving configuration: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Apply side effects only after the configuration has been durably saved.
	// Stop admission before doing any other potentially expensive reconfiguration.
	// Enabling is deferred until the selected baseline has been loaded below.
	scoringChanged := previous.ScoringEnabled != next.ScoringEnabled
	if s.scoring != nil && scoringChanged && !next.ScoringEnabled {
		s.scoring.SetEnabled(false)
	}
	if s.pyfilter != nil && previous.PyFilterEnabled != next.PyFilterEnabled {
		s.pyfilter.SetRuntimeEnabled(next.PyFilterEnabled)
	}

	flagMatcherChanged := previous.FlagRegex != next.FlagRegex || req.FlagRegex != nil
	if flagMatcherChanged {
		if err := s.proxy.SetFlagPattern(next.FlagRegex, next.FlagRegexCaseInsensitive, next.FlagDecodeURL); err != nil {
			rollbackErr := s.rollbackConfig(previous)
			http.Error(w, configApplyError("refresh flag scanner", err, rollbackErr), http.StatusInternalServerError)
			return
		}
	}
	if s.captureCtrl != nil && previous.TrafficMode != next.TrafficMode {
		s.captureCtrl.SetMode(next.TrafficMode)
	}
	if s.packetStore != nil && previous.FlowCorrelationWindowSec != next.FlowCorrelationWindowSec {
		s.packetStore.SetFlowCorrelationWindowSec(next.FlowCorrelationWindowSec)
	}

	pollerChanged := previous.FlagIDEnabled != next.FlagIDEnabled ||
		previous.FlagIDAPIURL != next.FlagIDAPIURL || previous.OurTeamID != next.OurTeamID ||
		previous.FlagIDPollInterval != next.FlagIDPollInterval || previous.FlagIDFormat != next.FlagIDFormat ||
		previous.RoundDurationSec != next.RoundDurationSec || previous.CompetitionStart != next.CompetitionStart ||
		previous.KeepRounds != next.KeepRounds || previous.TrafficMode != next.TrafficMode
	if s.flagIDPoller != nil && pollerChanged {
		s.flagIDPoller.Reconfigure(pollerConfig(next))
	}
	if s.cleanupMgr != nil && previous.TrafficMode != next.TrafficMode {
		s.cleanupMgr.UpdateSettings(effectiveCleanupSettings(next))
	}

	baselineChanged := previous.CompetitionStart != next.CompetitionStart || previous.RoundDurationSec != next.RoundDurationSec ||
		previous.BaselineStartRound != next.BaselineStartRound || previous.BaselineEndRound != next.BaselineEndRound ||
		!maps.Equal(previous.BaselineServiceRounds, next.BaselineServiceRounds)
	if s.scoring != nil && next.ScoringEnabled && (baselineChanged || scoringChanged) {
		if err := s.scoring.ConfigureBaseline(scoringBaselineConfig(next)); err != nil {
			rollbackErr := s.rollbackConfig(previous)
			http.Error(w, configApplyError("reset scoring baseline", err, rollbackErr), http.StatusInternalServerError)
			return
		}
	}
	if s.scoring != nil && scoringChanged && next.ScoringEnabled {
		s.scoring.SetEnabled(true)
	}

	writeJSON(w, http.StatusOK, s.configResponse(next))
}

// rollbackConfig restores both the durable dashboard settings and every
// runtime consumer. It is only used after an apply failure, so favoring a
// complete reconciliation over avoiding a listener restart is intentional.
func (s *Server) rollbackConfig(previous *config.Config) error {
	if previous == nil {
		return fmt.Errorf("previous configuration is unavailable")
	}
	if _, err := config.Update(func(current *config.Config) error {
		*current = *previous
		return nil
	}); err != nil {
		return fmt.Errorf("persisting previous configuration: %w", err)
	}

	var rollbackErrors []error
	if s.proxy != nil {
		if err := s.proxy.SetFlagPattern(previous.FlagRegex, previous.FlagRegexCaseInsensitive, previous.FlagDecodeURL); err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("flag scanner: %w", err))
		}
	}
	if s.captureCtrl != nil {
		s.captureCtrl.SetMode(previous.TrafficMode)
	}
	if s.packetStore != nil {
		s.packetStore.SetFlowCorrelationWindowSec(previous.FlowCorrelationWindowSec)
	}
	if s.flagIDPoller != nil {
		s.flagIDPoller.Reconfigure(pollerConfig(previous))
	}
	if s.cleanupMgr != nil {
		s.cleanupMgr.UpdateSettings(effectiveCleanupSettings(previous))
	}
	if s.pyfilter != nil {
		s.pyfilter.SetRuntimeEnabled(previous.PyFilterEnabled)
	}
	if s.scoring != nil {
		// Reconcile from a quiescent scorer. If restoring the baseline fails, keep
		// scoring off and report an incomplete rollback instead of running with a
		// configuration different from the one persisted on disk.
		s.scoring.SetEnabled(false)
		if previous.ScoringEnabled {
			if err := s.scoring.ConfigureBaseline(scoringBaselineConfig(previous)); err != nil {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("scoring baseline: %w", err))
			} else {
				s.scoring.SetEnabled(true)
			}
		}
	}
	return errors.Join(rollbackErrors...)
}

func configApplyError(step string, applyErr, rollbackErr error) string {
	message := fmt.Sprintf("configuration was not applied (%s): %v", step, applyErr)
	if rollbackErr != nil {
		message += "; rollback was incomplete: " + rollbackErr.Error()
	}
	return message
}

func applyConfigUpdate(cfg *config.Config, req configUpdateRequest) error {
	// Empty means “unchanged”, which lets the frontend keep passwords write-only.
	if req.TeamPassword != nil && *req.TeamPassword != "" {
		if len(*req.TeamPassword) > 4096 {
			return fmt.Errorf("team_password is too long")
		}
		cfg.TeamPassword = *req.TeamPassword
	}
	if req.FlagRegex != nil {
		cfg.FlagRegex = strings.TrimSpace(*req.FlagRegex)
	}
	if len(cfg.FlagRegex) > 4096 {
		return fmt.Errorf("flag_regex is too long")
	}
	effectivePattern := cfg.FlagRegex
	if cfg.FlagRegexCaseInsensitive && effectivePattern != "" && !strings.HasPrefix(effectivePattern, "(?i)") {
		effectivePattern = "(?i)" + effectivePattern
	}
	if effectivePattern != "" {
		if _, err := regexp.Compile(effectivePattern); err != nil {
			return fmt.Errorf("invalid flag_regex: %w", err)
		}
	}

	if req.FlagIDEnabled != nil {
		cfg.FlagIDEnabled = *req.FlagIDEnabled
	}
	if req.FlagIDAPIURL != nil {
		cfg.FlagIDAPIURL = strings.TrimSpace(*req.FlagIDAPIURL)
	}
	if len(cfg.FlagIDAPIURL) > 4096 {
		return fmt.Errorf("flagid_api_url is too long")
	}
	if cfg.FlagIDAPIURL != "" {
		u, err := url.Parse(cfg.FlagIDAPIURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("flagid_api_url must be a valid HTTP(S) URL")
		}
	}
	if cfg.FlagIDEnabled && cfg.FlagIDAPIURL == "" {
		return fmt.Errorf("flagid_api_url is required when Flag ID polling is enabled")
	}
	if req.FlagIDTeamID != nil {
		cfg.OurTeamID = strings.TrimSpace(*req.FlagIDTeamID)
	}
	if len(cfg.OurTeamID) > 256 {
		return fmt.Errorf("flagid_team_id is too long")
	}
	if req.FlagIDPollInterval != nil {
		cfg.FlagIDPollInterval = *req.FlagIDPollInterval
	}
	if cfg.FlagIDPollInterval < 1 || cfg.FlagIDPollInterval > 3600 {
		return fmt.Errorf("flagid_poll_interval must be between 1 and 3600 seconds")
	}
	if req.FlagIDFormat != nil {
		cfg.FlagIDFormat = strings.ToLower(strings.TrimSpace(*req.FlagIDFormat))
	}
	switch cfg.FlagIDFormat {
	case "cyberchallenge", "saarctf", "faustctf", "forcad", "enowars":
	default:
		return fmt.Errorf("unsupported flagid_format %q", cfg.FlagIDFormat)
	}

	if req.RoundDurationSec != nil {
		cfg.RoundDurationSec = *req.RoundDurationSec
	}
	if cfg.RoundDurationSec < 1 || cfg.RoundDurationSec > 86400 {
		return fmt.Errorf("round_duration_seconds must be between 1 and 86400")
	}
	if req.CompetitionStart != nil {
		cfg.CompetitionStart = strings.TrimSpace(*req.CompetitionStart)
	}
	if _, err := parseCompetitionStart(cfg.CompetitionStart); err != nil {
		return err
	}
	if req.KeepRounds != nil {
		cfg.KeepRounds = *req.KeepRounds
	}
	if cfg.KeepRounds < 1 || cfg.KeepRounds > 100 {
		return fmt.Errorf("keep_rounds must be between 1 and 100")
	}
	if req.BaselineStartRound != nil {
		cfg.BaselineStartRound = *req.BaselineStartRound
	}
	if req.BaselineEndRound != nil {
		cfg.BaselineEndRound = *req.BaselineEndRound
	}
	if cfg.BaselineStartRound < 1 || cfg.BaselineEndRound > 10000 {
		return fmt.Errorf("baseline rounds must be between 1 and 10000")
	}
	if cfg.BaselineEndRound < cfg.BaselineStartRound+1 {
		return fmt.Errorf("baseline_end_round must include at least two rounds")
	}
	if cfg.BaselineEndRound-cfg.BaselineStartRound+1 > 50 {
		return fmt.Errorf("baseline range cannot exceed 50 rounds")
	}
	if req.BaselineServiceRounds != nil {
		cfg.BaselineServiceRounds = make(map[string]config.BaselineRoundRange, len(req.BaselineServiceRounds))
		for rawServiceID, rounds := range req.BaselineServiceRounds {
			serviceID := strings.TrimSpace(rawServiceID)
			if serviceID == "" || len(serviceID) > 256 {
				return fmt.Errorf("baseline service IDs must contain between 1 and 256 characters")
			}
			if rounds.StartRound < 1 || rounds.EndRound > 10000 {
				return fmt.Errorf("baseline rounds for %q must be between 1 and 10000", serviceID)
			}
			span := rounds.EndRound - rounds.StartRound + 1
			if span < 2 || span > 50 {
				return fmt.Errorf("baseline range for %q must include between 2 and 50 rounds", serviceID)
			}
			cfg.BaselineServiceRounds[serviceID] = rounds
		}
	}

	if req.TrafficMode != nil {
		cfg.TrafficMode = strings.ToLower(strings.TrimSpace(*req.TrafficMode))
	}
	if cfg.TrafficMode != sniffer.TrafficModeLive && cfg.TrafficMode != sniffer.TrafficModeStatic {
		return fmt.Errorf("traffic_mode must be one of: live, static")
	}
	if req.StaticCaptureServiceIDs != nil {
		serviceIDs, err := normalizeCaptureServiceIDs(*req.StaticCaptureServiceIDs)
		if err != nil {
			return err
		}
		cfg.StaticCaptureServiceIDs = serviceIDs
	}
	if req.ScoringEnabled != nil {
		cfg.ScoringEnabled = *req.ScoringEnabled
	}
	if req.PyFilterEnabled != nil {
		cfg.PyFilterEnabled = *req.PyFilterEnabled
	}
	if req.FlowCorrelationWindowSec != nil {
		cfg.FlowCorrelationWindowSec = *req.FlowCorrelationWindowSec
	}
	if cfg.FlowCorrelationWindowSec < 5 || cfg.FlowCorrelationWindowSec > 86400 {
		return fmt.Errorf("flow_correlation_window_seconds must be between 5 and 86400")
	}
	if req.PcapExportDir != nil {
		cfg.PcapExportDir = strings.TrimSpace(*req.PcapExportDir)
	}
	if cfg.PcapExportDir == "" || len(cfg.PcapExportDir) > 4096 {
		return fmt.Errorf("pcap_export_dir must be a non-empty path")
	}
	if req.PcapAutoSave != nil {
		cfg.PcapAutoSave = *req.PcapAutoSave
	}
	return nil
}

func parseCompetitionStart(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("competition_start must be RFC3339: %w", err)
	}
	return t, nil
}

func pollerConfig(cfg *config.Config) flagids.PollerConfig {
	return flagids.PollerConfig{
		Enabled: cfg.FlagIDEnabled && cfg.TrafficMode == sniffer.TrafficModeLive,
		APIURL:  cfg.FlagIDAPIURL, TeamID: cfg.OurTeamID,
		IntervalSec: cfg.FlagIDPollInterval, Format: cfg.FlagIDFormat,
		RoundDurationSec: cfg.RoundDurationSec, CompetitionStart: cfg.CompetitionStart,
		KeepRounds: cfg.KeepRounds,
	}
}

func scoringBaselineConfig(cfg *config.Config) scoring.BaselineConfig {
	start, _ := parseCompetitionStart(cfg.CompetitionStart)
	ranges := make(map[string]scoring.BaselineRange, len(cfg.BaselineServiceRounds))
	for serviceID, rounds := range cfg.BaselineServiceRounds {
		ranges[serviceID] = scoring.BaselineRange{StartRound: rounds.StartRound, EndRound: rounds.EndRound}
	}
	return scoring.NewBaselineConfig(start, cfg.RoundDurationSec, cfg.BaselineStartRound, cfg.BaselineEndRound, ranges)
}

func effectiveCleanupSettings(cfg *config.Config) cleanup.Settings {
	if cfg.TrafficMode == sniffer.TrafficModeStatic {
		return cleanup.Settings{}
	}
	return cleanup.Settings{MaxAgeMinutes: cfg.CleanupMaxAgeMinutes, MaxDBSizeMB: cfg.CleanupMaxDBSizeMB}
}

func (s *Server) configResponse(cfg *config.Config) configResponse {
	currentRound := 0
	active := false
	if s.flagIDPoller != nil {
		currentRound = s.flagIDPoller.CurrentRound()
		active = s.flagIDPoller.GetConfig().Enabled
	}
	return configResponse{
		TeamPassword: "", TeamPasswordSet: cfg.TeamPassword != "",
		FlagRegex: cfg.FlagRegex, FlagRegexCaseInsensitive: cfg.FlagRegexCaseInsensitive,
		FlagDecodeURL: cfg.FlagDecodeURL, TeamIP: cfg.TeamIP,
		FlagIDEnabled: cfg.FlagIDEnabled, FlagIDActive: active,
		FlagIDAPIURL: cfg.FlagIDAPIURL, FlagIDTeamID: cfg.OurTeamID,
		FlagIDPollInterval: cfg.FlagIDPollInterval, FlagIDFormat: cfg.FlagIDFormat,
		RoundDurationSec: cfg.RoundDurationSec, CompetitionStart: cfg.CompetitionStart,
		KeepRounds: cfg.KeepRounds, CurrentRound: currentRound,
		BaselineStartRound: cfg.BaselineStartRound, BaselineEndRound: cfg.BaselineEndRound,
		BaselineServiceRounds:    cfg.BaselineServiceRounds,
		TrafficMode:              cfg.TrafficMode,
		StaticCaptureServiceIDs:  append([]string{}, cfg.StaticCaptureServiceIDs...),
		ScoringEnabled:           cfg.ScoringEnabled,
		PyFilterEnabled:          cfg.PyFilterEnabled,
		FlowCorrelationWindowSec: cfg.FlowCorrelationWindowSec,
		PcapExportDir:            cfg.PcapExportDir, PcapAutoSave: cfg.PcapAutoSave,
	}
}
