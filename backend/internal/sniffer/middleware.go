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
	Close  bool
}
type PyAlertMatch = PyBlockMatch

// PyResult is the outcome of the inline (synchronous) Python filters on a
// request: the matches that asked to block, plus an optional rewritten body.
type PyResult struct {
	Blocks    []PyBlockMatch
	Alerts    []PyAlertMatch
	NewBody   []byte // rewritten body to forward (only when Rewritten)
	Rewritten bool
	// Finalize reconciles connection counters with the payload actually
	// admitted by the caller. It never invokes Python.
	Finalize func(flow map[string]any)
}

// PyBlockFunc synchronously evaluates the inline (blocking) Python filters
// against a request/message flow and returns their verdict (block and/or
// rewrite). It runs on the hot path, so implementations must be bounded and fail
// open. A nil func disables inline blocking/rewriting.
type PyBlockFunc func(flow map[string]any) PyResult

// PyShouldEvaluateFunc is a cheap scope preflight. An empty direction asks
// whether any inline script needs the message for evaluation or connection
// tracking; an exact direction asks whether that direction can directly match.
// HTTP uses the exact response query before deciding to buffer a response.
type PyShouldEvaluateFunc func(service, direction, protocol string) bool

// ShouldCaptureFunc is the storage admission gate for one service. Proxy
// wiring binds the service ID in the callback closure, preserving the original
// no-argument middleware API. A nil callback captures everything.
type ShouldCaptureFunc func() bool

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
func HTTPMiddleware(next http.Handler, svc *storage.Service, store PacketSink, dropEngine *dropper.Engine, flagRegex *regexp.Regexp, flagScanner *flagids.FlagScanner, getFlagIDChecker func() FlagIDChecker, shouldCapture ShouldCaptureFunc, shouldApplyFlagIDsOnIngest func() bool, pyBlock PyBlockFunc, pyShouldEvaluate PyShouldEvaluateFunc) http.Handler {
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
		headersStr := FlattenHeadersString(r.Header)

		captureEnabled := shouldCapture == nil || shouldCapture()
		applyFlagIDsNow := shouldApplyFlagIDsOnIngest == nil || shouldApplyFlagIDsOnIngest()

		// Compute metadata before rule evaluation so live rules see the same
		// canonical fields as historical searches.
		flagged := CheckFlagged(flagRegex, flagScanner, r.URL.String(), headersStr, reqBody)
		flagURLCount, flagHeaderCount, flagBodyCount := CountFlags(flagRegex, flagScanner, r.URL.String(), headersStr, reqBody)
		containsFlagID, matchedFlagIDs, flagIDRound := false, []string(nil), 0
		if applyFlagIDsNow {
			containsFlagID, matchedFlagIDs, flagIDRound = CheckFlagID(getFlagIDChecker(), r.URL.String(), headersStr, reqBody)
		}
		sessionID, ok := ConnectionSessionFromContext(r.Context())
		if !ok {
			// Direct handler integrations may not use proxy.Manager's ConnContext;
			// retain the legacy, deterministic fallback for compatibility.
			sessionID = MakeSessionID(svc.ID, srcIP, srcPort)
		}
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
		var requestPyFlow map[string]any
		var requestPyResult PyResult
		var pyEventID string
		bodyComplete := streamingCapture == nil && !reqBodyTruncated
		requestRewritten := false
		forceClose := false
		if shouldProcessPythonMessage(svc, pyBlock, pyShouldEvaluate) {
			pyEventID = MakePyFilterEventID(sessionID, DirectionRequest, start)
			flow := map[string]any{
				"service":            svc.ID,
				"session":            sessionID,
				"event_id":           pyEventID,
				"direction":          string(DirectionRequest),
				"protocol":           string(svc.Protocol),
				"method":             r.Method,
				"url":                r.URL.String(),
				"status":             0,
				"src":                srcIP,
				"dst":                dstIP,
				"sport":              srcPort,
				"dport":              dstPort,
				"headers":            reqHeaders,
				"body":               string(reqBody),
				"body_b64":           base64.StdEncoding.EncodeToString(reqBody),
				"truncated":          !bodyComplete,
				"body_complete":      bodyComplete,
				"flagged":            flagged,
				"contains_flagid":    containsFlagID,
				"matched_flagids":    matchedFlagIDs,
				"flag_count_body":    flagBodyCount,
				"flag_count_headers": flagHeaderCount,
				"flag_count_url":     flagURLCount,
				"admitted":           !shouldDrop,
				"timestamp":          float64(start.UnixNano()) / float64(time.Second),
			}
			res := pyBlock(flow)
			requestPyFlow, requestPyResult = flow, res
			for _, alert := range res.Alerts {
				matchedRules = append(matchedRules, MatchedRuleInfo{ID: "pyfilter:" + alert.Script, Name: "Python alert (" + alert.Script + ")", Action: "alert", Pattern: alert.Reason, Scope: "python"})
				pyBlockAlerts = append(pyBlockAlerts, &Alert{RuleID: "pyfilter:" + alert.Script, ServiceID: svc.ID, SrcIP: srcIP, Timestamp: start, PatternMatched: alert.Reason})
			}
			for _, bm := range res.Blocks {
				forceClose = forceClose || bm.Close
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
			if res.Rewritten && !shouldDrop && bodyComplete {
				requestRewritten = true
				reqBody = res.NewBody
				r.Body = io.NopCloser(bytes.NewReader(reqBody))
				r.ContentLength = int64(len(reqBody))
				r.Header.Set("Content-Length", strconv.Itoa(len(reqBody)))
			}
		}
		if requestRewritten {
			flagged = CheckFlagged(flagRegex, flagScanner, r.URL.String(), headersStr, reqBody)
			flagURLCount, flagHeaderCount, flagBodyCount = CountFlags(flagRegex, flagScanner, r.URL.String(), headersStr, reqBody)
			if applyFlagIDsNow {
				containsFlagID, matchedFlagIDs, flagIDRound = CheckFlagID(getFlagIDChecker(), r.URL.String(), headersStr, reqBody)
			}
		}
		if streamingCapture == nil || shouldDrop {
			requestPyResult.Reconcile(requestPyFlow, reqBody, !shouldDrop, !bodyComplete,
				flagged, containsFlagID, matchedFlagIDs, flagBodyCount, flagHeaderCount, flagURLCount)
		}

		// In static mode without capture, still persist drops and alert-triggering traffic so Alerts/Blocks stay useful.
		mustPersistReq := captureEnabled || shouldDrop || len(alertRules) > 0 || len(pyBlockAlerts) > 0

		// Avoid allocating a retained packet object for ordinary excluded
		// traffic. Unknown-length bodies still need one because a rule can match
		// the captured prefix after the backend has consumed the stream.
		var reqPacket *Packet
		if mustPersistReq || streamingCapture != nil {
			reqPacket = &Packet{
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
				FlagCountBody:    flagBodyCount,
				FlagCountHeaders: flagHeaderCount,
				FlagCountURL:     flagURLCount,
				PyFilterEventID:  pyEventID,
				Verdict:          VerdictFor(DirectionRequest, matchedRules, shouldDrop, requestRewritten, true),
			}
			if reqPacket.MatchedRules == nil {
				reqPacket.MatchedRules = []MatchedRuleInfo{}
			}
		}
		persistRequest := func() {
			if !mustPersistReq || reqPacket == nil {
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
			if forceClose {
				w.Header().Set("Connection", "close")
				r.Close = true
			}
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if streamingCapture == nil {
			persistRequest()
		}

		// Buffer only ordinary HTTP/1 responses that an enabled response-side
		// inline filter can inspect. Streaming responses release the buffer on
		// their first Flush; oversized responses release it at the capture cap.
		// HTTP/2, gRPC and upgrades are never delayed here.
		evaluateResponse := shouldEvaluatePythonResponse(svc, pyBlock, pyShouldEvaluate)
		bufferResponse := shouldBufferHTTPResponse(r, svc, evaluateResponse)
		rw := newResponseCapture(w, bufferResponse)
		next.ServeHTTP(rw, r)
		if streamingCapture != nil {
			reqPacket.Body = streamingCapture.Bytes()
			reqPacket.CaptureTruncated = streamingCapture.Truncated()
			reqPacket.Flagged = CheckFlagged(flagRegex, flagScanner, r.URL.String(), headersStr, reqPacket.Body)
			reqPacket.FlagCountURL, reqPacket.FlagCountHeaders, reqPacket.FlagCountBody = CountFlags(flagRegex, flagScanner, r.URL.String(), headersStr, reqPacket.Body)
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
			requestPyResult.Reconcile(requestPyFlow, reqPacket.Body, true, reqPacket.CaptureTruncated,
				reqPacket.Flagged, reqPacket.ContainsFlagID, reqPacket.MatchedFlagIDs,
				reqPacket.FlagCountBody, reqPacket.FlagCountHeaders, reqPacket.FlagCountURL)
			persistRequest()
		}

		// Inspect the response. At this point it is still enforceable only when
		// responseCapture retained the complete ordinary HTTP/1 body.
		responseEnforceable := rw.canEnforce()
		respTime := time.Now()
		respStatus := rw.statusCode
		respHeaders := flattenHeaders(rw.Header())
		// Evaluate directly against the bounded response buffer. Copy it only if
		// the packet is admitted to the async store; excluded ordinary traffic
		// should not pay for a second body-sized allocation.
		respBody := rw.body.Bytes()
		respHeadersStr := FlattenHeadersString(rw.Header())
		respFlagged := CheckFlagged(flagRegex, flagScanner, "", respHeadersStr, respBody)
		_, respFlagHeaderCount, respFlagBodyCount := CountFlags(flagRegex, flagScanner, "", respHeadersStr, respBody)
		respContainsFlagID, respMatchedFlagIDs, respFlagIDRound := false, []string(nil), 0
		if applyFlagIDsNow {
			respContainsFlagID, respMatchedFlagIDs, respFlagIDRound = CheckFlagID(getFlagIDChecker(), "", respHeadersStr, respBody)
		}

		// Static response rules remain alert/would-drop policies. Python filters
		// can additionally enforce a decision while the bounded buffer is intact.
		var respMatchedRules []MatchedRuleInfo
		var respAlertRules []dropper.Rule
		if dropEngine != nil {
			respView := flowmodel.PacketView{
				Service: svc.ID, Session: sessionID, OccurredAt: time.Now(),
				Source:       flowmodel.Endpoint{IP: dstIP, Port: dstPort},
				Destination:  flowmodel.Endpoint{IP: srcIP, Port: srcPort},
				ProtocolName: string(svc.Protocol), DirectionName: string(DirectionResponse),
				MethodName: r.Method, URLValue: r.URL.String(), StatusCode: respStatus,
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

		var respPyAlerts []*Alert
		var responsePyFlow map[string]any
		var responsePyResult PyResult
		var respEventID string
		respDropped, respRewritten, respForceClose := false, false, false
		// While any applicable inline script is live, every response reaches the
		// Go-side connection tracker even when no response-scoped script can run.
		// This keeps flags/rates/fingerprints complete for a later request-side
		// filter. Runtime-disabled Python bypasses this allocation path entirely.
		if shouldProcessPythonMessage(svc, pyBlock, pyShouldEvaluate) {
			respEventID = MakePyFilterEventID(sessionID, DirectionResponse, respTime)
			responsePyFlow = map[string]any{
				"service":            svc.ID,
				"session":            sessionID,
				"event_id":           respEventID,
				"direction":          string(DirectionResponse),
				"protocol":           string(svc.Protocol),
				"method":             r.Method,
				"url":                r.URL.String(),
				"status":             respStatus,
				"src":                dstIP,
				"dst":                srcIP,
				"sport":              dstPort,
				"dport":              srcPort,
				"headers":            respHeaders,
				"body":               string(respBody),
				"body_b64":           base64.StdEncoding.EncodeToString(respBody),
				"truncated":          rw.truncated,
				"body_complete":      !rw.truncated,
				"flagged":            respFlagged,
				"contains_flagid":    respContainsFlagID,
				"matched_flagids":    respMatchedFlagIDs,
				"flag_count_body":    respFlagBodyCount,
				"flag_count_headers": respFlagHeaderCount,
				"flag_count_url":     0,
				"admitted":           true,
				"enforceable":        responseEnforceable,
				"timestamp":          float64(respTime.UnixNano()) / float64(time.Second),
			}
			res := pyBlock(responsePyFlow)
			responsePyResult = res
			for _, alert := range res.Alerts {
				respMatchedRules = append(respMatchedRules, MatchedRuleInfo{ID: "pyfilter:" + alert.Script, Name: "Python alert (" + alert.Script + ")", Action: "alert", Pattern: alert.Reason, Scope: "python"})
				respPyAlerts = append(respPyAlerts, &Alert{RuleID: "pyfilter:" + alert.Script, ServiceID: svc.ID, SrcIP: srcIP, Timestamp: respTime, PatternMatched: alert.Reason})
			}
			for _, match := range res.Blocks {
				respForceClose = respForceClose || match.Close
				respMatchedRules = append(respMatchedRules, MatchedRuleInfo{ID: "pyfilter:" + match.Script, Name: "Python block (" + match.Script + ")", Action: "drop", Pattern: match.Reason, Scope: "python"})
				respPyAlerts = append(respPyAlerts, &Alert{RuleID: "pyfilter:" + match.Script, ServiceID: svc.ID, SrcIP: srcIP, Timestamp: respTime, PatternMatched: match.Reason})
				if responseEnforceable {
					respDropped = true
				}
			}
			if res.Rewritten && responseEnforceable && !respDropped && responseAllowsBody(r.Method, respStatus) {
				respRewritten = true
				respBody = append([]byte(nil), res.NewBody...)
				prepareRewrittenResponseHeaders(rw.Header(), len(respBody))
				respHeaders = flattenHeaders(rw.Header())
				respHeadersStr = FlattenHeadersString(rw.Header())
				respFlagged = CheckFlagged(flagRegex, flagScanner, "", respHeadersStr, respBody)
				_, respFlagHeaderCount, respFlagBodyCount = CountFlags(flagRegex, flagScanner, "", respHeadersStr, respBody)
				if applyFlagIDsNow {
					respContainsFlagID, respMatchedFlagIDs, respFlagIDRound = CheckFlagID(getFlagIDChecker(), "", respHeadersStr, respBody)
				}
			}
		}
		responsePyResult.Reconcile(responsePyFlow, respBody, !respDropped, rw.truncated,
			respFlagged, respContainsFlagID, respMatchedFlagIDs, respFlagBodyCount, respFlagHeaderCount, 0)

		if responseEnforceable {
			switch {
			case respDropped:
				if respForceClose {
					r.Close = true
				}
				rw.replace(http.StatusForbidden, []byte("Forbidden\n"), respForceClose)
			case respRewritten:
				rw.commit(respBody)
			default:
				rw.commit(respBody)
			}
		}
		// A response-side native drop is reported as a would_drop match rather
		// than enforced, so key persistence off every matched rule (not only the
		// alert subset). This keeps security evidence outside the capture scope.
		mustPersistResp := captureEnabled || len(respMatchedRules) > 0 || respRewritten
		if mustPersistResp {
			if respMatchedRules == nil {
				respMatchedRules = []MatchedRuleInfo{}
			}
			respPacket := &Packet{
				ServiceID:        svc.ID,
				SessionID:        sessionID,
				Timestamp:        respTime,
				SrcIP:            dstIP,
				SrcPort:          dstPort,
				DstIP:            srcIP,
				DstPort:          srcPort,
				Protocol:         string(svc.Protocol),
				Direction:        DirectionResponse,
				Method:           r.Method,
				URL:              r.URL.String(),
				Status:           respStatus,
				Headers:          respHeaders,
				Body:             append([]byte(nil), respBody...),
				CaptureTruncated: rw.truncated,
				MatchedRules:     respMatchedRules,
				Flagged:          respFlagged,
				ContainsFlagID:   respContainsFlagID,
				MatchedFlagIDs:   respMatchedFlagIDs,
				FlagIDRound:      respFlagIDRound,
				FlagCountBody:    respFlagBodyCount,
				FlagCountHeaders: respFlagHeaderCount,
				PyFilterEventID:  respEventID,
				Verdict:          VerdictFor(DirectionResponse, respMatchedRules, respDropped, respRewritten, responseEnforceable),
			}
			alertTemplates := make([]*Alert, 0, len(respAlertRules)+len(respPyAlerts))
			for _, rule := range respAlertRules {
				alertTemplates = append(alertTemplates, &Alert{
					RuleID:         rule.ID,
					ServiceID:      svc.ID,
					SrcIP:          srcIP,
					Timestamp:      respTime,
					PatternMatched: rule.Pattern,
				})
			}
			alertTemplates = append(alertTemplates, respPyAlerts...)
			if err := store.Enqueue(respPacket, alertTemplates); err != nil {
				log.Printf("[%s] sniffer: failed to log response: %v", svc.Name, err)
			}
		}
	})
}

// Reconcile updates the connection tracker with the payload that the proxy
// actually admitted after any inline rewrite. It does not run a filter again.
func (result PyResult) Reconcile(flow map[string]any, body []byte, admitted, truncated, flagged, containsFlagID bool, matchedFlagIDs []string, bodyFlags, headerFlags, urlFlags int) {
	if result.Finalize == nil || flow == nil {
		return
	}
	flow["body"] = string(body)
	flow["body_b64"] = base64.StdEncoding.EncodeToString(body)
	flow["truncated"] = truncated
	flow["body_complete"] = !truncated
	flow["flagged"] = flagged
	flow["contains_flagid"] = containsFlagID
	flow["matched_flagids"] = matchedFlagIDs
	flow["flag_count_body"] = bodyFlags
	flow["flag_count_headers"] = headerFlags
	flow["flag_count_url"] = urlFlags
	flow["admitted"] = admitted
	result.Finalize(flow)
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
	complete  bool
}

func (c *streamingBodyCapture) Read(p []byte) (int, error) {
	n, err := c.source.Read(p)
	if err == io.EOF {
		c.complete = true
	}
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

func (c *streamingBodyCapture) Close() error { return c.source.Close() }

// Bytes remains valid after capture completes because the buffer is never
// mutated again; callers that enqueue it retain the backing slice directly.
func (c *streamingBodyCapture) Bytes() []byte   { return c.body.Bytes() }
func (c *streamingBodyCapture) Truncated() bool { return c.truncated || !c.complete }

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

// CountFlags returns exact, component-wise non-overlapping matches for newly
// captured traffic. FlagScanner also applies the configured percent-decoding;
// the regexp fallback keeps tests and legacy setups functional.
func CountFlags(flagRegex *regexp.Regexp, scanner *flagids.FlagScanner, url, headers string, body []byte) (urlCount, headerCount, bodyCount int) {
	countString := func(value string) int {
		if scanner != nil {
			return scanner.CountString(value)
		}
		if flagRegex != nil {
			return len(flagRegex.FindAllString(value, -1))
		}
		return 0
	}
	countBytes := func(value []byte) int {
		if scanner != nil {
			return scanner.CountBytes(value)
		}
		if flagRegex != nil {
			return len(flagRegex.FindAll(value, -1))
		}
		return 0
	}
	return countString(url), countString(headers), countBytes(body)
}

func shouldEvaluatePythonResponse(svc *storage.Service, pyBlock PyBlockFunc, shouldEvaluate PyShouldEvaluateFunc) bool {
	if pyBlock == nil || svc == nil || svc.RuntimeSpec().Application.Profile == storage.ApplicationWebSocket {
		return false
	}
	return shouldEvaluate == nil || shouldEvaluate(svc.ID, string(DirectionResponse), string(svc.Protocol))
}

// shouldProcessPythonMessage is the allocation gate for live Python work. The
// empty direction asks the manager whether any inline script for this
// service/protocol needs the connection message, including for state tracking.
// A nil preflight preserves compatibility with direct/custom PyBlock callers.
func shouldProcessPythonMessage(svc *storage.Service, pyBlock PyBlockFunc, shouldEvaluate PyShouldEvaluateFunc) bool {
	if pyBlock == nil || svc == nil {
		return false
	}
	return shouldEvaluate == nil || shouldEvaluate(svc.ID, "", string(svc.Protocol))
}

func shouldBufferHTTPResponse(r *http.Request, svc *storage.Service, evaluate bool) bool {
	if !evaluate || r == nil || svc == nil || r.ProtoMajor != 1 || r.Header.Get("Upgrade") != "" {
		return false
	}
	return svc.RuntimeSpec().Application.Profile == storage.ApplicationHTTP
}

var rewrittenEntityHeaders = []string{
	"Accept-Ranges", "Content-Encoding", "Content-MD5", "Content-Range",
	"Digest", "ETag", "Trailer", "Transfer-Encoding",
}

func prepareRewrittenResponseHeaders(headers http.Header, length int) {
	for _, name := range rewrittenEntityHeaders {
		headers.Del(name)
	}
	headers.Set("Content-Length", strconv.Itoa(length))
}

func responseAllowsBody(method string, status int) bool {
	return method != http.MethodHead && status >= 200 && status != http.StatusNoContent && status != http.StatusNotModified
}

// responseCapture normally mirrors writes while retaining a bounded prefix.
// In buffering mode it delays an ordinary HTTP/1 response until Python has
// evaluated the complete body. Flush or overflow atomically switches it back
// to transparent pass-through.
type responseCapture struct {
	http.ResponseWriter
	statusCode  int
	body        bytes.Buffer
	wroteHeader bool
	sentHeader  bool
	truncated   bool
	buffering   bool
	streamed    bool
	hijacked    bool
}

func newResponseCapture(w http.ResponseWriter, buffering bool) *responseCapture {
	return &responseCapture{ResponseWriter: w, statusCode: http.StatusOK, buffering: buffering}
}

func (rc *responseCapture) WriteHeader(code int) {
	if rc.wroteHeader {
		return
	}
	rc.statusCode = code
	rc.wroteHeader = true
	if !rc.buffering {
		rc.sendHeader()
	}
}

func (rc *responseCapture) Write(b []byte) (int, error) {
	if !rc.wroteHeader {
		rc.statusCode = http.StatusOK
		rc.wroteHeader = true
	}
	before := rc.body.Len()
	remaining := maxBodyCapture - before
	if before < maxBodyCapture {
		if len(b) > remaining {
			_, _ = rc.body.Write(b[:remaining])
			rc.truncated = true
		} else {
			_, _ = rc.body.Write(b)
		}
	}
	if before >= maxBodyCapture && len(b) > 0 {
		rc.truncated = true
	}
	if rc.buffering {
		if !rc.truncated {
			return len(b), nil
		}
		// Only bytes written before this call are pending. The current slice is
		// forwarded whole; rc.body merely retains its inspection prefix.
		pending := append([]byte(nil), rc.body.Bytes()[:before]...)
		rc.buffering = false
		rc.streamed = true
		rc.sendHeader()
		if len(pending) > 0 {
			if _, err := rc.ResponseWriter.Write(pending); err != nil {
				return 0, err
			}
		}
	}
	rc.sendHeader()
	return rc.ResponseWriter.Write(b)
}

// Flush implements http.Flusher for streaming/SSE support.
func (rc *responseCapture) Flush() {
	if !rc.wroteHeader {
		rc.statusCode = http.StatusOK
		rc.wroteHeader = true
	}
	if rc.buffering {
		rc.streamed = true
		_ = rc.release()
	} else {
		rc.sendHeader()
	}
	if f, ok := rc.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (rc *responseCapture) sendHeader() {
	if rc.sentHeader || rc.hijacked {
		return
	}
	rc.ResponseWriter.WriteHeader(rc.statusCode)
	rc.sentHeader = true
}

func (rc *responseCapture) canEnforce() bool {
	return rc.buffering && !rc.sentHeader && !rc.hijacked
}

func (rc *responseCapture) release() error {
	if !rc.buffering {
		return nil
	}
	rc.buffering = false
	rc.sendHeader()
	if rc.body.Len() == 0 {
		return nil
	}
	_, err := rc.ResponseWriter.Write(rc.body.Bytes())
	return err
}

func (rc *responseCapture) commit(body []byte) error {
	if !rc.canEnforce() {
		return nil
	}
	rc.buffering = false
	rc.sendHeader()
	if len(body) == 0 {
		return nil
	}
	_, err := rc.ResponseWriter.Write(body)
	return err
}

func (rc *responseCapture) replace(status int, body []byte, forceClose bool) {
	if !rc.canEnforce() {
		return
	}
	for name := range rc.Header() {
		rc.Header().Del(name)
	}
	rc.Header().Set("Content-Type", "text/plain; charset=utf-8")
	rc.Header().Set("Content-Length", strconv.Itoa(len(body)))
	if forceClose {
		rc.Header().Set("Connection", "close")
	}
	rc.statusCode = status
	rc.wroteHeader = true
	_ = rc.commit(body)
}

// Unwrap lets http.ResponseController discover optional capabilities exposed
// by the underlying writer on newer Go versions.
func (rc *responseCapture) Unwrap() http.ResponseWriter { return rc.ResponseWriter }

// Hijack preserves protocol upgrades (notably WebSocket) through the capture
// middleware. httputil.ReverseProxy must take ownership of the client
// connection after the backend returns 101 Switching Protocols; hiding the
// underlying http.Hijacker makes the upgrade fail with a 502.
func (rc *responseCapture) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := rc.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	rc.buffering = false
	rc.streamed = true
	rc.hijacked = true
	if !rc.wroteHeader {
		rc.statusCode = http.StatusSwitchingProtocols
		rc.wroteHeader = true
	}
	return h.Hijack()
}

// FlattenHeadersString returns the exact header representation used by live
// flag matching and synthetic PyFilter tests.
func FlattenHeadersString(h http.Header) string {
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
