package sniffer

import (
	"bufio"
	"bytes"
	"encoding/base64"
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
	flowmodel "github.com/SimoneErrigo/Janus/backend/internal/flow"
	"github.com/SimoneErrigo/Janus/backend/internal/storage"
)

const maxBodyCapture = 1 << 20 // 1 MB

// PyBlockMatch is a blocking Python-filter verdict on a request: a script asked
// to drop the current request inline (in real time).
type PyBlockMatch struct {
	Script string
	Reason string
}

// PyResult is the outcome of the inline (synchronous) Python filters on a
// request: the matches that asked to block, plus an optional rewritten body.
type PyResult struct {
	Blocks    []PyBlockMatch
	NewBody   []byte // rewritten body to forward (only when Rewritten)
	Rewritten bool
}

// PyBlockFunc synchronously evaluates the inline (blocking) Python filters
// against a request/message flow and returns their verdict (block and/or
// rewrite). It runs on the hot path, so implementations must be bounded and fail
// open. A nil func disables inline blocking/rewriting.
type PyBlockFunc func(flow map[string]any) PyResult

func roundFromFlagIDMatches(matches []flagids.FlagMatch, fallback int) int {
	round := 0
	for _, m := range matches {
		if m.Round > round {
			round = m.Round
		}
	}
	if round > 0 {
		return round
	}
	return fallback
}

// CheckFlagID checks whether any of the packet content contains a current flag ID value.
// Returns the boolean flag, the list of matched flag ID string values, and the matched round when available.
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
	return true, vals, roundFromFlagIDMatches(matches, checker.CurrentRound())
}

// HTTPMiddleware returns an http.Handler that logs requests/responses and evaluates drop rules.
// getFlagIDChecker is called per request so updates from SetFlagIDChecker apply without restarting the proxy.
func HTTPMiddleware(next http.Handler, svc *storage.Service, store PacketSink, dropEngine *dropper.Engine, flagRegex *regexp.Regexp, flagScanner *flagids.FlagScanner, getFlagIDChecker func() FlagIDChecker, shouldCapture func() bool, shouldApplyFlagIDsOnIngest func() bool, pyBlock PyBlockFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Parse client address
		srcIP, srcPortStr, _ := net.SplitHostPort(r.RemoteAddr)
		srcPort, _ := strconv.Atoi(srcPortStr)

		// Parse destination from the listener
		dstIP := svc.ListenAddr
		dstPort := svc.ListenPort

		// Capture a finite prefix without ever replacing the forwarded body by
		// that prefix. Unknown-length streams are captured as the backend reads.
		reqBody, reqBodyTruncated, streamingCapture, err := prepareRequestCapture(r)
		if err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		// Collect request headers
		reqHeaders := flattenHeaders(r.Header)
		headersStr := flattenHeadersString(r.Header)

		captureEnabled := shouldCapture == nil || shouldCapture()
		applyFlagIDsNow := shouldApplyFlagIDsOnIngest == nil || shouldApplyFlagIDsOnIngest()

		// Compute metadata before rule evaluation so live rules see the same
		// canonical fields as historical searches.
		flagged := CheckFlagged(flagRegex, flagScanner, r.URL.String(), headersStr, reqBody)
		containsFlagID, matchedFlagIDs, flagIDRound := false, []string(nil), 0
		if applyFlagIDsNow {
			containsFlagID, matchedFlagIDs, flagIDRound = CheckFlagID(getFlagIDChecker(), r.URL.String(), headersStr, reqBody)
		}
		sessionID := MakeSessionID(svc.ID, srcIP, srcPort)
		reqView := flowmodel.PacketView{
			Service: svc.ID, Session: sessionID, OccurredAt: start,
			Source:       flowmodel.Endpoint{IP: srcIP, Port: srcPort},
			Destination:  flowmodel.Endpoint{IP: dstIP, Port: dstPort},
			ProtocolName: string(svc.Protocol), DirectionName: string(DirectionRequest),
			MethodName: r.Method, URLValue: r.URL.String(), HeaderValues: reqHeaders,
			Payload: reqBody, BodyText: string(reqBody),
			FlaggedValue: flagged, ContainsFlagIDValue: containsFlagID,
		}

		// Evaluate rules before inserting/forwarding.
		var matchedRules []MatchedRuleInfo
		shouldDrop := false
		var alertRules []dropper.Rule
		if dropEngine != nil {
			result := dropEngine.EvaluateView(reqView)
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

		// Inline (synchronous) Python filters: evaluate the blocking scripts
		// against the request before forwarding, so a match ({"drop": True}) can
		// drop it in real time. Runs on the hot path but is bounded + fail-open
		// inside pyBlock, so a stuck/dead script never stalls traffic.
		var pyBlockAlerts []*Alert
		requestRewritten := false
		if pyBlock != nil {
			flow := map[string]any{
				"service":         svc.ID,
				"direction":       string(DirectionRequest),
				"method":          r.Method,
				"url":             r.URL.String(),
				"status":          0,
				"src":             srcIP,
				"dst":             dstIP,
				"sport":           srcPort,
				"dport":           dstPort,
				"headers":         reqHeaders,
				"body":            string(reqBody),
				"body_b64":        base64.StdEncoding.EncodeToString(reqBody),
				"flagged":         flagged,
				"contains_flagid": containsFlagID,
				"timestamp":       start.Unix(),
			}
			res := pyBlock(flow)
			for _, bm := range res.Blocks {
				matchedRules = append(matchedRules, MatchedRuleInfo{
					ID:      "pyfilter:" + bm.Script,
					Name:    "Python block (" + bm.Script + ")",
					Action:  "drop",
					Pattern: bm.Reason,
					Scope:   "python",
				})
				pyBlockAlerts = append(pyBlockAlerts, &Alert{
					RuleID:         "pyfilter:" + bm.Script,
					ServiceID:      svc.ID,
					SrcIP:          srcIP,
					Timestamp:      start,
					PatternMatched: bm.Reason,
				})
				shouldDrop = true
			}
			// Inline rewrite: swap the request body before forwarding + logging
			// (only when we're not about to drop it).
			if res.Rewritten && !shouldDrop && streamingCapture == nil {
				requestRewritten = true
				reqBody = res.NewBody
				r.Body = io.NopCloser(bytes.NewReader(reqBody))
				r.ContentLength = int64(len(reqBody))
				r.Header.Set("Content-Length", strconv.Itoa(len(reqBody)))
			}
		}

		// In static mode without capture, still persist drops and alert-triggering traffic so Alerts/Blocks stay useful.
		mustPersistReq := captureEnabled || shouldDrop || len(alertRules) > 0 || len(pyBlockAlerts) > 0

		// Build and insert request packet
		reqPacket := &Packet{
			ServiceID:        svc.ID,
			SessionID:        sessionID,
			Timestamp:        start,
			SrcIP:            srcIP,
			SrcPort:          srcPort,
			DstIP:            dstIP,
			DstPort:          dstPort,
			Protocol:         string(svc.Protocol),
			Direction:        DirectionRequest,
			Method:           r.Method,
			URL:              r.URL.String(),
			Headers:          reqHeaders,
			Body:             reqBody,
			CaptureTruncated: reqBodyTruncated,
			MatchedRules:     matchedRules,
			Flagged:          flagged,
			ContainsFlagID:   containsFlagID,
			MatchedFlagIDs:   matchedFlagIDs,
			FlagIDRound:      flagIDRound,
			Verdict:          VerdictFor(DirectionRequest, matchedRules, shouldDrop, requestRewritten, true),
		}
		if reqPacket.MatchedRules == nil {
			reqPacket.MatchedRules = []MatchedRuleInfo{}
		}
		persistRequest := func() {
			if !mustPersistReq {
				return
			}
			alertTemplates := make([]*Alert, 0, len(alertRules)+len(pyBlockAlerts))
			for _, rule := range alertRules {
				alertTemplates = append(alertTemplates, &Alert{
					RuleID:         rule.ID,
					ServiceID:      svc.ID,
					SrcIP:          srcIP,
					Timestamp:      start,
					PatternMatched: rule.Pattern,
				})
			}
			alertTemplates = append(alertTemplates, pyBlockAlerts...)
			if err := store.Enqueue(reqPacket, alertTemplates); err != nil {
				log.Printf("[%s] sniffer: failed to log request: %v", svc.Name, err)
			}
		}

		// Drop if rules matched
		if shouldDrop {
			persistRequest()
			log.Printf("[%s] DROP: %d rule(s) matched request %s %s", svc.Name, len(matchedRules), r.Method, r.URL.String())
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if streamingCapture == nil {
			persistRequest()
		}

		// Wrap response writer to capture status and body
		rw := &responseCapture{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rw, r)
		if streamingCapture != nil {
			reqPacket.Body = streamingCapture.Bytes()
			reqPacket.CaptureTruncated = streamingCapture.Truncated()
			reqPacket.Flagged = CheckFlagged(flagRegex, flagScanner, r.URL.String(), headersStr, reqPacket.Body)
			if applyFlagIDsNow {
				reqPacket.ContainsFlagID, reqPacket.MatchedFlagIDs, reqPacket.FlagIDRound = CheckFlagID(getFlagIDChecker(), r.URL.String(), headersStr, reqPacket.Body)
			}
			// Unknown-length streams cannot be safely buffered before forwarding.
			// Re-evaluate the captured prefix after forwarding so detections remain
			// visible, but record drop matches truthfully as would_drop.
			if dropEngine != nil {
				reqView.Payload = reqPacket.Body
				reqView.BodyText = string(reqPacket.Body)
				reqView.FlaggedValue = reqPacket.Flagged
				reqView.ContainsFlagIDValue = reqPacket.ContainsFlagID
				postResult := dropEngine.EvaluateView(reqView)
				matchedRules = matchedRules[:0]
				for _, rule := range postResult.AllMatched {
					matchedRules = append(matchedRules, MatchedRuleInfo{ID: rule.ID, Name: rule.Name, Action: string(rule.Action), Pattern: rule.Pattern, Scope: string(rule.Scope)})
				}
				alertRules = postResult.AlertRules
				reqPacket.MatchedRules = matchedRules
				reqPacket.Verdict = VerdictFor(DirectionRequest, matchedRules, false, false, false)
				mustPersistReq = captureEnabled || len(matchedRules) > 0
			}
			persistRequest()
		}

		// Log response packet
		respHeaders := flattenHeaders(rw.Header())
		respBody := rw.body.Bytes()
		respHeadersStr := flattenHeadersString(rw.Header())
		respFlagged := CheckFlagged(flagRegex, flagScanner, r.URL.String(), respHeadersStr, respBody)
		respContainsFlagID, respMatchedFlagIDs, respFlagIDRound := false, []string(nil), 0
		if applyFlagIDsNow {
			respContainsFlagID, respMatchedFlagIDs, respFlagIDRound = CheckFlagID(getFlagIDChecker(), r.URL.String(), respHeadersStr, respBody)
		}

		// Evaluate rules against response (alert-only, never drop — response already sent)
		var respMatchedRules []MatchedRuleInfo
		var respAlertRules []dropper.Rule
		if dropEngine != nil {
			respView := flowmodel.PacketView{
				Service: svc.ID, Session: sessionID, OccurredAt: time.Now(),
				Source:       flowmodel.Endpoint{IP: dstIP, Port: dstPort},
				Destination:  flowmodel.Endpoint{IP: srcIP, Port: srcPort},
				ProtocolName: string(svc.Protocol), DirectionName: string(DirectionResponse),
				MethodName: r.Method, URLValue: r.URL.String(), StatusCode: rw.statusCode,
				HeaderValues: respHeaders, Payload: respBody, BodyText: string(respBody),
				FlaggedValue: respFlagged, ContainsFlagIDValue: respContainsFlagID,
			}
			respResult := dropEngine.EvaluateView(respView)
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
		mustPersistResp := captureEnabled || len(respAlertRules) > 0

		respPacket := &Packet{
			ServiceID:        svc.ID,
			SessionID:        sessionID,
			Timestamp:        time.Now(),
			SrcIP:            dstIP,
			SrcPort:          dstPort,
			DstIP:            srcIP,
			DstPort:          srcPort,
			Protocol:         string(svc.Protocol),
			Direction:        DirectionResponse,
			Method:           r.Method,
			URL:              r.URL.String(),
			Status:           rw.statusCode,
			Headers:          respHeaders,
			Body:             respBody,
			CaptureTruncated: rw.truncated,
			MatchedRules:     respMatchedRules,
			Flagged:          respFlagged,
			ContainsFlagID:   respContainsFlagID,
			MatchedFlagIDs:   respMatchedFlagIDs,
			FlagIDRound:      respFlagIDRound,
			Verdict:          VerdictFor(DirectionResponse, respMatchedRules, false, false, false),
		}
		if mustPersistResp {
			alertTemplates := make([]*Alert, 0, len(respAlertRules))
			respTime := time.Now()
			for _, rule := range respAlertRules {
				alertTemplates = append(alertTemplates, &Alert{
					RuleID:         rule.ID,
					ServiceID:      svc.ID,
					SrcIP:          srcIP,
					Timestamp:      respTime,
					PatternMatched: rule.Pattern,
				})
			}
			if err := store.Enqueue(respPacket, alertTemplates); err != nil {
				log.Printf("[%s] sniffer: failed to log response: %v", svc.Name, err)
			}
		}
	})
}

// replayReadCloser replays a captured prefix and then continues with the
// original request body while preserving Close propagation.
type replayReadCloser struct {
	io.Reader
	closer io.Closer
}

func (r *replayReadCloser) Close() error { return r.closer.Close() }

// streamingBodyCapture observes bytes only when the upstream consumes them.
type streamingBodyCapture struct {
	source    io.ReadCloser
	body      bytes.Buffer
	truncated bool
}

func (c *streamingBodyCapture) Read(p []byte) (int, error) {
	n, err := c.source.Read(p)
	if n > 0 {
		remaining := maxBodyCapture - c.body.Len()
		if remaining > 0 {
			keep := n
			if keep > remaining {
				keep = remaining
			}
			_, _ = c.body.Write(p[:keep])
		}
		if n > remaining {
			c.truncated = true
		}
	}
	return n, err
}

func (c *streamingBodyCapture) Close() error    { return c.source.Close() }
func (c *streamingBodyCapture) Bytes() []byte   { return append([]byte(nil), c.body.Bytes()...) }
func (c *streamingBodyCapture) Truncated() bool { return c.truncated }

func prepareRequestCapture(r *http.Request) ([]byte, bool, *streamingBodyCapture, error) {
	if r.Body == nil {
		return nil, false, nil, nil
	}
	if r.ContentLength < 0 {
		capture := &streamingBodyCapture{source: r.Body}
		r.Body = capture
		return nil, false, capture, nil
	}
	prefix, err := io.ReadAll(io.LimitReader(r.Body, maxBodyCapture))
	if err != nil {
		return nil, false, nil, err
	}
	truncated := r.ContentLength > int64(len(prefix))
	r.Body = &replayReadCloser{Reader: io.MultiReader(bytes.NewReader(prefix), r.Body), closer: r.Body}
	return prefix, truncated, nil, nil
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
	truncated   bool
}

func (rc *responseCapture) WriteHeader(code int) {
	if !rc.wroteHeader {
		rc.statusCode = code
		rc.wroteHeader = true
	}
	rc.ResponseWriter.WriteHeader(code)
}

func (rc *responseCapture) Write(b []byte) (int, error) {
	before := rc.body.Len()
	if before < maxBodyCapture {
		remaining := maxBodyCapture - before
		if len(b) > remaining {
			rc.body.Write(b[:remaining])
			rc.truncated = true
		} else {
			rc.body.Write(b)
		}
	}
	if before >= maxBodyCapture && len(b) > 0 {
		rc.truncated = true
	}
	return rc.ResponseWriter.Write(b)
}

// Flush implements http.Flusher for streaming/SSE support.
func (rc *responseCapture) Flush() {
	if f, ok := rc.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack preserves protocol upgrades (notably WebSocket) through the capture
// middleware. httputil.ReverseProxy must take ownership of the client
// connection after the backend returns 101 Switching Protocols; hiding the
// underlying http.Hijacker makes the upgrade fail with a 502.
func (rc *responseCapture) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := rc.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	if !rc.wroteHeader {
		rc.statusCode = http.StatusSwitchingProtocols
		rc.wroteHeader = true
	}
	return h.Hijack()
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
		if len(v) == 1 {
			flat[k] = v[0]
		} else {
			flat[k] = strings.Join(v, ", ")
		}
	}
	return flat
}
