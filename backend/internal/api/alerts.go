package api

import (
	"database/sql"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/SimoneErrigo/Janus/backend/internal/filter"
	"github.com/SimoneErrigo/Janus/backend/internal/sniffer"
)

// alertResidualCap is the maximum number of alerts the residual-filter path
// pulls into memory in one go. Past this point users must narrow the legacy
// alert filters (service / src / rule / time range) before applying `q`.
const alertResidualCap = 5000

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
	params := r.URL.Query()
	q := sniffer.AlertQuery{
		ServiceID:    params.Get("service_id"),
		RuleID:       params.Get("rule_id"),
		SrcIP:        params.Get("src_ip"),
		NotServiceID: params.Get("not_service_id"),
		NotRuleID:    params.Get("not_rule_id"),
		NotSrcIP:     params.Get("not_src_ip"),
	}

	if v := params.Get("time_from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			q.TimeFrom = &t
		}
	}
	if v := params.Get("time_to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			q.TimeTo = &t
		}
	}
	pageLimit := 50
	if v := params.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			pageLimit = n
		}
	}
	pageOffset := 0
	if v := params.Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			pageOffset = n
		}
	}

	// Optional unified expression filter — evaluated against the linked
	// packet of each alert (alert rows alone don't carry body/url/etc.).
	exprStr := strings.TrimSpace(params.Get("q"))
	var exprEval filter.EvalFunc
	if exprStr != "" {
		fn, err := filter.Compile(exprStr)
		if err != nil {
			http.Error(w, "invalid q expression: "+err.Error(), http.StatusBadRequest)
			return
		}
		exprEval = fn
	}

	if exprEval == nil {
		// Fast path: SQL pagination with COUNT.
		q.Limit = pageLimit
		q.Offset = pageOffset
		alerts, total, err := s.packetStore.QueryAlerts(q)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if alerts == nil {
			alerts = []*sniffer.Alert{}
		}
		s.enrichAlerts(alerts)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"alerts": alerts,
			"total":  total,
		})
		return
	}

	// Residual path: pull a bounded window, filter against linked packets,
	// then slice for the requested page.
	q.Limit = alertResidualCap
	q.Offset = 0
	allAlerts, _, err := s.packetStore.QueryAlerts(q)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	filtered := make([]*sniffer.Alert, 0, len(allAlerts))
	for _, a := range allAlerts {
		pkt, err := s.packetStore.GetPacketByID(a.PacketID)
		if err != nil || pkt == nil {
			continue // packet was deleted/cleaned; alert is dangling
		}
		if !exprEval(sniffer.AsView(pkt)) {
			continue
		}
		filtered = append(filtered, a)
	}

	total := len(filtered)
	end := pageOffset + pageLimit
	if pageOffset > total {
		pageOffset = total
	}
	if end > total {
		end = total
	}
	page := filtered[pageOffset:end]
	if page == nil {
		page = []*sniffer.Alert{}
	}
	s.enrichAlerts(page)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"alerts": page,
		"total":  total,
	})
}

func (s *Server) enrichAlerts(alerts []*sniffer.Alert) {
	for _, a := range alerts {
		if rule, ok := s.ruleStore.GetRule(a.RuleID); ok {
			a.RuleName = rule.Name
			a.MatchedScope = string(rule.Scope)
		}
	}
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
	log.Printf("[user=%s] action=clear-alerts", DisplayNameFromRequest(r))
	w.WriteHeader(http.StatusNoContent)
}
