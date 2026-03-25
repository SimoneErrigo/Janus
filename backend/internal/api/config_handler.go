package api

import (
	"encoding/json"
	"net/http"

	"github.com/SimoneErrigo/Janus/backend/internal/config"
)

type configResponse struct {
	VMIP             string `json:"vm_ip"`
	NetworkInterface string `json:"network_interface"`
	TeamPassword     string `json:"team_password"`
	FlagRegex        string `json:"flag_regex"`
}

type configUpdateRequest struct {
	VMIP             *string `json:"vm_ip,omitempty"`
	NetworkInterface *string `json:"network_interface,omitempty"`
	TeamPassword     *string `json:"team_password,omitempty"`
	FlagRegex        *string `json:"flag_regex,omitempty"`
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
	writeJSON(w, http.StatusOK, configResponse{
		VMIP:             cfg.VMIP,
		NetworkInterface: cfg.NetworkInterface,
		TeamPassword:     cfg.TeamPassword,
		FlagRegex:        cfg.FlagRegex,
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

	writeJSON(w, http.StatusOK, configResponse{
		VMIP:             cfg.VMIP,
		NetworkInterface: cfg.NetworkInterface,
		TeamPassword:     cfg.TeamPassword,
		FlagRegex:        cfg.FlagRegex,
	})
}
