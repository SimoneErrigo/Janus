package api

import (
	"encoding/json"
	"net/http"

	"github.com/SimoneErrigo/Janus/backend/internal/cleanup"
	"github.com/SimoneErrigo/Janus/backend/internal/config"
	"github.com/SimoneErrigo/Janus/backend/internal/flagids"
	"github.com/SimoneErrigo/Janus/backend/internal/sniffer"
)

type configResponse struct {
	TeamPassword     string `json:"team_password"`
	FlagRegex        string `json:"flag_regex"`

	// Flag ID settings
	FlagIDEnabled      bool   `json:"flagid_enabled"`
	FlagIDAPIURL       string `json:"flagid_api_url"`
	FlagIDTeamID       string `json:"flagid_team_id"`
	FlagIDPollInterval int    `json:"flagid_poll_interval"`
	FlagIDFormat       string `json:"flagid_format"`

	// Competition timing
	RoundDurationSec         int    `json:"round_duration_seconds"`
	CompetitionStart         string `json:"competition_start,omitempty"`
	KeepRounds               int    `json:"keep_rounds"`
	CurrentRound             int    `json:"current_round"`
	TrafficMode              string `json:"traffic_mode"`
	FlowCorrelationWindowSec int    `json:"flow_correlation_window_seconds"`
}

type configUpdateRequest struct {
	TeamPassword     *string `json:"team_password,omitempty"`
	FlagRegex        *string `json:"flag_regex,omitempty"`

	// Flag ID settings
	FlagIDEnabled      *bool   `json:"flagid_enabled,omitempty"`
	FlagIDAPIURL       *string `json:"flagid_api_url,omitempty"`
	FlagIDTeamID       *string `json:"flagid_team_id,omitempty"`
	FlagIDPollInterval *int    `json:"flagid_poll_interval,omitempty"`
	FlagIDFormat       *string `json:"flagid_format,omitempty"`

	// Competition timing
	RoundDurationSec         *int    `json:"round_duration_seconds,omitempty"`
	CompetitionStart         *string `json:"competition_start,omitempty"`
	KeepRounds               *int    `json:"keep_rounds,omitempty"`
	TrafficMode              *string `json:"traffic_mode,omitempty"`
	FlowCorrelationWindowSec *int    `json:"flow_correlation_window_seconds,omitempty"`
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

func (s *Server) getConfig(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()

	// Read live poller config
	var pollerCfg flagids.PollerConfig
	if s.flagIDPoller != nil {
		pollerCfg = s.flagIDPoller.GetConfig()
	}

	writeJSON(w, http.StatusOK, configResponse{
		TeamPassword:             cfg.TeamPassword,
		FlagRegex:                cfg.FlagRegex,
		FlagIDEnabled:            pollerCfg.Enabled,
		FlagIDAPIURL:             pollerCfg.APIURL,
		FlagIDTeamID:             pollerCfg.TeamID,
		FlagIDPollInterval:       pollerCfg.IntervalSec,
		FlagIDFormat:             pollerCfg.Format,
		RoundDurationSec:         pollerCfg.RoundDurationSec,
		CompetitionStart:         pollerCfg.CompetitionStart,
		KeepRounds:               pollerCfg.KeepRounds,
		CurrentRound:             s.flagIDPoller.CurrentRound(),
		TrafficMode:              cfg.TrafficMode,
		FlowCorrelationWindowSec: cfg.FlowCorrelationWindowSec,
	})
}

func (s *Server) updateConfig(w http.ResponseWriter, r *http.Request) {
	var req configUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	cfg := config.Get()
	if req.TeamPassword != nil {
		if *req.TeamPassword == "" {
			http.Error(w, "team_password cannot be empty", http.StatusBadRequest)
			return
		}
		cfg.TeamPassword = *req.TeamPassword
	}
	if req.FlagRegex != nil {
		cfg.FlagRegex = *req.FlagRegex
	}
	if req.TrafficMode != nil {
		mode := *req.TrafficMode
		if mode != sniffer.TrafficModeLive && mode != sniffer.TrafficModeStatic {
			http.Error(w, "traffic_mode must be one of: live, static", http.StatusBadRequest)
			return
		}
		cfg.TrafficMode = mode
		if s.captureCtrl != nil {
			s.captureCtrl.SetMode(mode)
		}
		// Static mode: stop periodic fetch/backfill and disable auto-cleanup.
		// Live mode: restore periodic behavior from current settings.
		if s.flagIDPoller != nil {
			current := s.flagIDPoller.GetConfig()
			if mode == sniffer.TrafficModeStatic {
				current.Enabled = false
			} else {
				current.Enabled = cfg.FlagIDEnabled
			}
			s.flagIDPoller.Reconfigure(current)
		}
		if s.cleanupMgr != nil {
			if mode == sniffer.TrafficModeStatic {
				s.cleanupMgr.UpdateSettings(cleanup.Settings{MaxAgeMinutes: 0, MaxDBSizeMB: 0})
			} else {
				s.cleanupMgr.UpdateSettings(cleanup.Settings{MaxAgeMinutes: cfg.CleanupMaxAgeMinutes, MaxDBSizeMB: cfg.CleanupMaxDBSizeMB})
			}
		}
	}
	if req.FlowCorrelationWindowSec != nil {
		if *req.FlowCorrelationWindowSec < 5 {
			http.Error(w, "flow_correlation_window_seconds must be >= 5", http.StatusBadRequest)
			return
		}
		cfg.FlowCorrelationWindowSec = *req.FlowCorrelationWindowSec
		if s.packetStore != nil {
			s.packetStore.SetFlowCorrelationWindowSec(*req.FlowCorrelationWindowSec)
		}
	}

	// Reconfigure Flag ID poller if any flagID/timing field was provided
	if s.flagIDPoller != nil && (req.FlagIDEnabled != nil || req.FlagIDAPIURL != nil || req.FlagIDTeamID != nil || req.FlagIDPollInterval != nil || req.FlagIDFormat != nil || req.RoundDurationSec != nil || req.CompetitionStart != nil || req.KeepRounds != nil) {
		current := s.flagIDPoller.GetConfig()
		if req.FlagIDEnabled != nil {
			current.Enabled = *req.FlagIDEnabled
		}
		if req.FlagIDAPIURL != nil {
			current.APIURL = *req.FlagIDAPIURL
		}
		if req.FlagIDTeamID != nil {
			current.TeamID = *req.FlagIDTeamID
		}
		if req.FlagIDPollInterval != nil {
			current.IntervalSec = *req.FlagIDPollInterval
		}
		if req.FlagIDFormat != nil {
			current.Format = *req.FlagIDFormat
			cfg.FlagIDFormat = *req.FlagIDFormat
		}
		if req.RoundDurationSec != nil {
			current.RoundDurationSec = *req.RoundDurationSec
			cfg.RoundDurationSec = *req.RoundDurationSec
		}
		if req.CompetitionStart != nil {
			current.CompetitionStart = *req.CompetitionStart
			cfg.CompetitionStart = *req.CompetitionStart
		}
		if req.KeepRounds != nil {
			current.KeepRounds = *req.KeepRounds
			cfg.KeepRounds = *req.KeepRounds
		}

		// Also update global config
		cfg.FlagIDEnabled = current.Enabled
		cfg.FlagIDAPIURL = current.APIURL
		cfg.OurTeamID = current.TeamID
		cfg.FlagIDPollInterval = current.IntervalSec

		s.flagIDPoller.Reconfigure(current)
	}

	// Read back poller config for response
	var pollerCfg flagids.PollerConfig
	if s.flagIDPoller != nil {
		pollerCfg = s.flagIDPoller.GetConfig()
	}

	currentRound := 0
	if s.flagIDPoller != nil {
		currentRound = s.flagIDPoller.CurrentRound()
	}
	writeJSON(w, http.StatusOK, configResponse{
		TeamPassword:             cfg.TeamPassword,
		FlagRegex:                cfg.FlagRegex,
		FlagIDEnabled:            pollerCfg.Enabled,
		FlagIDAPIURL:             pollerCfg.APIURL,
		FlagIDTeamID:             pollerCfg.TeamID,
		FlagIDPollInterval:       pollerCfg.IntervalSec,
		FlagIDFormat:             pollerCfg.Format,
		RoundDurationSec:         pollerCfg.RoundDurationSec,
		CompetitionStart:         pollerCfg.CompetitionStart,
		KeepRounds:               pollerCfg.KeepRounds,
		CurrentRound:             currentRound,
		TrafficMode:              cfg.TrafficMode,
		FlowCorrelationWindowSec: cfg.FlowCorrelationWindowSec,
	})
}
