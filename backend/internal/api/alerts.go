package api

import (
	"database/sql"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/SimoneErrigo/Janus/backend/internal/sniffer"
)

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listAlerts(w, r)
	case http.MethodDelete:
		s.clearAlerts(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAlertByID(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/alerts/")
	if idStr == "" {
		http.Error(w, "missing alert ID", http.StatusBadRequest)
		return
	}

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid alert ID", http.StatusBadRequest)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.getAlert(w, r, id)
}

func (s *Server) listAlerts(w http.ResponseWriter, r *http.Request) {
	q := sniffer.AlertQuery{
		ServiceID: r.URL.Query().Get("service_id"),
		RuleID:    r.URL.Query().Get("rule_id"),
		SrcIP:     r.URL.Query().Get("src_ip"),
	}

	if v := r.URL.Query().Get("time_from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			q.TimeFrom = &t
		}
	}
	if v := r.URL.Query().Get("time_to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			q.TimeTo = &t
		}
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		q.Limit, _ = strconv.Atoi(v)
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		q.Offset, _ = strconv.Atoi(v)
	}

	alerts, total, err := s.packetStore.QueryAlerts(q)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if alerts == nil {
		alerts = []*sniffer.Alert{}
	}

	// Enrich alerts with rule names and scopes from the rule store
	for _, a := range alerts {
		if rule, ok := s.ruleStore.GetRule(a.RuleID); ok {
			a.RuleName = rule.Name
			a.MatchedScope = string(rule.Scope)
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"alerts": alerts,
		"total":  total,
	})
}

func (s *Server) getAlert(w http.ResponseWriter, r *http.Request, id int64) {
	alert, err := s.packetStore.GetAlert(id)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "alert not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Enrich with rule name and scope
	if rule, ok := s.ruleStore.GetRule(alert.RuleID); ok {
		alert.RuleName = rule.Name
		alert.MatchedScope = string(rule.Scope)
	}

	// Get linked packet (flag IDs are now tagged at ingestion, no live enrichment needed)
	linkedPacket, _ := s.packetStore.GetPacketByID(alert.PacketID)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"alert":  alert,
		"packet": linkedPacket,
	})
}

func (s *Server) clearAlerts(w http.ResponseWriter, r *http.Request) {
	if err := s.packetStore.ClearAlerts(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
