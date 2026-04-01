package sniffer

import (
	"bytes"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/SimoneErrigo/Janus/backend/internal/dropper"
	"github.com/SimoneErrigo/Janus/backend/internal/flagids"
	"github.com/SimoneErrigo/Janus/backend/internal/storage"
)

const maxBodyCapture = 1 << 20 // 1 MB

// CheckFlagID checks whether any of the packet content contains a current flag ID value.
// Returns the boolean flag, the list of matched flag ID string values, and the current round number.
func CheckFlagID(checker FlagIDChecker, url, headers string, body []byte) (bool, []string, int) {
	if checker == nil {
		return false, nil, 0
	}
	text := url + " " + headers
	if len(body) > 0 {
		text += " " + string(body)
	}
	matches := checker.FindMatchingFlagIDs(text)
	if len(matches) == 0 {
		return false, nil, checker.CurrentRound()
	}
	vals := make([]string, len(matches))
	for i, m := range matches {
		vals[i] = m.FlagID
	}
	return true, vals, checker.CurrentRound()
}

// HTTPMiddleware returns an http.Handler that logs requests/responses and evaluates drop rules.
// getFlagIDChecker is called per request so updates from SetFlagIDChecker apply without restarting the proxy.
func HTTPMiddleware(next http.Handler, svc *storage.Service, store *PacketStore, dropEngine *dropper.Engine, flagRegex *regexp.Regexp, flagScanner *flagids.FlagScanner, getFlagIDChecker func() FlagIDChecker) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Parse client address
		srcIP, srcPortStr, _ := net.SplitHostPort(r.RemoteAddr)
		srcPort, _ := strconv.Atoi(srcPortStr)

		// Parse destination from the listener
		dstIP := svc.ListenAddr
		dstPort := svc.ListenPort

		// Capture request body (limited)
		var reqBody []byte
		if r.Body != nil {
			reqBody, _ = io.ReadAll(io.LimitReader(r.Body, maxBodyCapture))
			r.Body = io.NopCloser(bytes.NewReader(reqBody))
		}

		// Collect request headers
		reqHeaders := flattenHeaders(r.Header)
		headersStr := flattenHeadersString(r.Header)

		// Evaluate rules before inserting
		var matchedRules []MatchedRuleInfo
		shouldDrop := false
		var alertRules []dropper.Rule
		if dropEngine != nil {
			result := dropEngine.EvaluateActions(&dropper.HTTPRequest{
				ServiceID: svc.ID,
				Headers:   headersStr,
				Body:      reqBody,
				URL:       r.URL.String(),
			})
			for _, rule := range result.AllMatched {
				matchedRules = append(matchedRules, MatchedRuleInfo{
					ID:      rule.ID,
					Name:    rule.Name,
					Action:  string(rule.Action),
					Pattern: rule.Pattern,
					Scope:   string(rule.Scope),
				})
			}
			shouldDrop = result.ShouldDrop
			alertRules = result.AlertRules
		}

		// Check flagged status and flag ID containment
		flagged := CheckFlagged(flagRegex, flagScanner, r.URL.String(), headersStr, reqBody)
		containsFlagID, matchedFlagIDs, flagIDRound := CheckFlagID(getFlagIDChecker(), r.URL.String(), headersStr, reqBody)

		// Session ID: ties request + response from the same TCP connection.
		// Even with SNAT (all traffic from same IP), src_port is unique per connection.
		sessionID := MakeSessionID(svc.ID, srcIP, srcPort)

		// Build and insert request packet
		reqPacket := &Packet{
			ServiceID:      svc.ID,
			SessionID:      sessionID,
			Timestamp:      start,
			SrcIP:          srcIP,
			SrcPort:        srcPort,
			DstIP:          dstIP,
			DstPort:        dstPort,
			Protocol:       string(svc.Protocol),
			Direction:      DirectionRequest,
			Method:         r.Method,
			URL:            r.URL.String(),
			Headers:        reqHeaders,
			Body:           reqBody,
			MatchedRules:   matchedRules,
			Flagged:        flagged,
			ContainsFlagID: containsFlagID,
			MatchedFlagIDs: matchedFlagIDs,
			FlagIDRound:    flagIDRound,
		}
		if reqPacket.MatchedRules == nil {
			reqPacket.MatchedRules = []MatchedRuleInfo{}
		}
		if err := store.Insert(reqPacket); err != nil {
			log.Printf("[%s] sniffer: failed to log request: %v", svc.Name, err)
		}

		// Insert alerts for alert/both rules
		for _, rule := range alertRules {
			alert := &Alert{
				PacketID:       reqPacket.ID,
				RuleID:         rule.ID,
				ServiceID:      svc.ID,
				SrcIP:          srcIP,
				Timestamp:      start,
				PatternMatched: rule.Pattern,
			}
			if err := store.InsertAlert(alert); err != nil {
				log.Printf("[%s] sniffer: failed to log alert: %v", svc.Name, err)
			}
		}

		// Drop if rules matched
		if shouldDrop {
			log.Printf("[%s] DROP: %d rule(s) matched request %s %s", svc.Name, len(matchedRules), r.Method, r.URL.String())
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Wrap response writer to capture status and body
		rw := &responseCapture{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rw, r)

		// Log response packet
		respHeaders := flattenHeaders(rw.Header())
		respBody := rw.body.Bytes()
		respHeadersStr := flattenHeadersString(rw.Header())
		respFlagged := CheckFlagged(flagRegex, flagScanner, r.URL.String(), respHeadersStr, respBody)
		respContainsFlagID, respMatchedFlagIDs, respFlagIDRound := CheckFlagID(getFlagIDChecker(), r.URL.String(), respHeadersStr, respBody)

		// Evaluate rules against response (alert-only, never drop — response already sent)
		var respMatchedRules []MatchedRuleInfo
		var respAlertRules []dropper.Rule
		if dropEngine != nil {
			respResult := dropEngine.EvaluateActions(&dropper.HTTPRequest{
				ServiceID: svc.ID,
				Headers:   respHeadersStr,
				Body:      respBody,
				URL:       r.URL.String(),
			})
			for _, rule := range respResult.AllMatched {
				respMatchedRules = append(respMatchedRules, MatchedRuleInfo{
					ID:      rule.ID,
					Name:    rule.Name,
					Action:  string(rule.Action),
					Pattern: rule.Pattern,
					Scope:   string(rule.Scope),
				})
			}
			respAlertRules = respResult.AlertRules
		}
		if respMatchedRules == nil {
			respMatchedRules = []MatchedRuleInfo{}
		}

		respPacket := &Packet{
			ServiceID:      svc.ID,
			SessionID:      sessionID,
			Timestamp:      time.Now(),
			SrcIP:          dstIP,
			SrcPort:        dstPort,
			DstIP:          srcIP,
			DstPort:        srcPort,
			Protocol:       string(svc.Protocol),
			Direction:      DirectionResponse,
			Method:         r.Method,
			URL:            r.URL.String(),
			Status:         rw.statusCode,
			Headers:        respHeaders,
			Body:           respBody,
			MatchedRules:   respMatchedRules,
			Flagged:        respFlagged,
			ContainsFlagID: respContainsFlagID,
			MatchedFlagIDs: respMatchedFlagIDs,
			FlagIDRound:    respFlagIDRound,
		}
		if err := store.Insert(respPacket); err != nil {
			log.Printf("[%s] sniffer: failed to log response: %v", svc.Name, err)
		}

		// Insert alerts for response-matched rules
		for _, rule := range respAlertRules {
			alert := &Alert{
				PacketID:       respPacket.ID,
				RuleID:         rule.ID,
				ServiceID:      svc.ID,
				SrcIP:          srcIP,
				Timestamp:      time.Now(),
				PatternMatched: rule.Pattern,
			}
			if err := store.InsertAlert(alert); err != nil {
				log.Printf("[%s] sniffer: failed to log response alert: %v", svc.Name, err)
			}
		}
	})
}

// CheckFlagged checks whether any of the packet content matches a flag pattern.
// Uses the fast FlagScanner when available, falls back to regexp.
func CheckFlagged(flagRegex *regexp.Regexp, scanner *flagids.FlagScanner, url, headers string, body []byte) bool {
	// Fast path: use the optimized byte scanner
	if scanner != nil {
		if url != "" && scanner.MatchString(url) {
			return true
		}
		if headers != "" && scanner.MatchString(headers) {
			return true
		}
		if len(body) > 0 && scanner.MatchBytes(body) {
			return true
		}
		return false
	}
	// Fallback: regexp
	if flagRegex == nil {
		return false
	}
	if url != "" && flagRegex.MatchString(url) {
		return true
	}
	if headers != "" && flagRegex.MatchString(headers) {
		return true
	}
	if len(body) > 0 && flagRegex.Match(body) {
		return true
	}
	return false
}

// responseCapture wraps http.ResponseWriter to capture status code and body.
type responseCapture struct {
	http.ResponseWriter
	statusCode  int
	body        bytes.Buffer
	wroteHeader bool
}

func (rc *responseCapture) WriteHeader(code int) {
	if !rc.wroteHeader {
		rc.statusCode = code
		rc.wroteHeader = true
	}
	rc.ResponseWriter.WriteHeader(code)
}

func (rc *responseCapture) Write(b []byte) (int, error) {
	if rc.body.Len() < maxBodyCapture {
		remaining := maxBodyCapture - rc.body.Len()
		if len(b) > remaining {
			rc.body.Write(b[:remaining])
		} else {
			rc.body.Write(b)
		}
	}
	return rc.ResponseWriter.Write(b)
}

// Flush implements http.Flusher for streaming/SSE support.
func (rc *responseCapture) Flush() {
	if f, ok := rc.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func flattenHeadersString(h http.Header) string {
	var sb strings.Builder
	for k, vals := range h {
		for _, v := range vals {
			sb.WriteString(k)
			sb.WriteString(": ")
			sb.WriteString(v)
			sb.WriteString("\n")
		}
	}
	return sb.String()
}

func flattenHeaders(h http.Header) map[string]string {
	flat := make(map[string]string, len(h))
	for k, v := range h {
		flat[k] = v[0]
		if len(v) > 1 {
			flat[k] = v[0]
			for i := 1; i < len(v); i++ {
				flat[k] += ", " + v[i]
			}
		}
	}
	return flat
}
