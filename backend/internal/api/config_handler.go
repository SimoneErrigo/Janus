package api

import (
	"encoding/json"
	"net/http"

	"github.com/SimoneErrigo/Janus/backend/internal/config"
	"github.com/SimoneErrigo/Janus/backend/internal/flagids"
)

type configResponse struct {
	VMIP             string `json:"vm_ip"`
	NetworkInterface string `json:"network_interface"`
	TeamPassword     string `json:"team_password"`
	FlagRegex        string `json:"flag_regex"`

	// Flag ID settings
	FlagIDEnabled      bool   `json:"flagid_enabled"`
	FlagIDAPIURL       string `json:"flagid_api_url"`
	FlagIDTeamID       string `json:"flagid_team_id"`
	FlagIDPollInterval int    `json:"flagid_poll_interval"`
	FlagIDFormat       string `json:"flagid_format"`
}

type configUpdateRequest struct {
	VMIP             *string `json:"vm_ip,omitempty"`
	NetworkInterface *string `json:"network_interface,omitempty"`
	TeamPassword     *string `json:"team_password,omitempty"`
	FlagRegex        *string `json:"flag_regex,omitempty"`

	// Flag ID settings
	FlagIDEnabled      *bool   `json:"flagid_enabled,omitempty"`
	FlagIDAPIURL       *string `json:"flagid_api_url,omitempty"`
	FlagIDTeamID       *string `json:"flagid_team_id,omitempty"`
	FlagIDPollInterval *int    `json:"flagid_poll_interval,omitempty"`
	FlagIDFormat       *string `json:"flagid_format,omitempty"`
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
		VMIP:               cfg.VMIP,
		NetworkInterface:   cfg.NetworkInterface,
		TeamPassword:       cfg.TeamPassword,
		FlagRegex:          cfg.FlagRegex,
		FlagIDEnabled:      pollerCfg.Enabled,
		FlagIDAPIURL:       pollerCfg.APIURL,
		FlagIDTeamID:       pollerCfg.TeamID,
		FlagIDPollInterval: pollerCfg.IntervalSec,
		FlagIDFormat:       pollerCfg.Format,
	})
}

func (s *Server) updateConfig(w http.ResponseWriter, r *http.Request) {
	var req configUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	cfg := config.Get()

	if req.VMIP != nil {
		cfg.VMIP = *req.VMIP
	}
	if req.NetworkInterface != nil {
		cfg.NetworkInterface = *req.NetworkInterface
	}
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

	// Reconfigure Flag ID poller if any flagID field was provided
	if s.flagIDPoller != nil && (req.FlagIDEnabled != nil || req.FlagIDAPIURL != nil || req.FlagIDTeamID != nil || req.FlagIDPollInterval != nil || req.FlagIDFormat != nil) {
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

	writeJSON(w, http.StatusOK, configResponse{
		VMIP:               cfg.VMIP,
		NetworkInterface:   cfg.NetworkInterface,
		TeamPassword:       cfg.TeamPassword,
		FlagRegex:          cfg.FlagRegex,
		FlagIDEnabled:      pollerCfg.Enabled,
		FlagIDAPIURL:       pollerCfg.APIURL,
		FlagIDTeamID:       pollerCfg.TeamID,
		FlagIDPollInterval: pollerCfg.IntervalSec,
		FlagIDFormat:       pollerCfg.Format,
	})
}
