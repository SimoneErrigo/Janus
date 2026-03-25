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
	"github.com/SimoneErrigo/Janus/backend/internal/storage"
)

const maxBodyCapture = 1 << 20 // 1 MB

// HTTPMiddleware returns an http.Handler that logs requests/responses and evaluates drop rules.
func HTTPMiddleware(next http.Handler, svc *storage.Service, store *PacketStore, dropEngine *dropper.Engine, flagRegex *regexp.Regexp) http.Handler {
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

		// Evaluate drop rules before inserting
		var matchedRules []MatchedRuleInfo
		shouldDrop := false
		if dropEngine != nil {
			matched := dropEngine.EvaluateAll(&dropper.HTTPRequest{
				ServiceID: svc.ID,
				Headers:   headersStr,
				Body:      reqBody,
				URL:       r.URL.String(),
			})
			for _, rule := range matched {
				matchedRules = append(matchedRules, MatchedRuleInfo{ID: rule.ID, Name: rule.Name})
			}
			if len(matched) > 0 {
				shouldDrop = true
			}
		}

		// Check flagged status
		flagged := CheckFlagged(flagRegex, r.URL.String(), headersStr, reqBody)

		// Build and insert request packet
		reqPacket := &Packet{
			ServiceID:    svc.ID,
			Timestamp:    start,
			SrcIP:        srcIP,
			SrcPort:      srcPort,
			DstIP:        dstIP,
			DstPort:      dstPort,
			Protocol:     string(svc.Protocol),
			Direction:    DirectionRequest,
			Method:       r.Method,
			URL:          r.URL.String(),
			Headers:      reqHeaders,
			Body:         reqBody,
			MatchedRules: matchedRules,
			Flagged:      flagged,
		}
		if reqPacket.MatchedRules == nil {
			reqPacket.MatchedRules = []MatchedRuleInfo{}
		}
		if err := store.Insert(reqPacket); err != nil {
			log.Printf("[%s] sniffer: failed to log request: %v", svc.Name, err)
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
		respFlagged := CheckFlagged(flagRegex, r.URL.String(), respHeadersStr, respBody)

		respPacket := &Packet{
			ServiceID:    svc.ID,
			Timestamp:    time.Now(),
			SrcIP:        dstIP,
			SrcPort:      dstPort,
			DstIP:        srcIP,
			DstPort:      srcPort,
			Protocol:     string(svc.Protocol),
			Direction:    DirectionResponse,
			Method:       r.Method,
			URL:          r.URL.String(),
			Status:       rw.statusCode,
			Headers:      respHeaders,
			Body:         respBody,
			MatchedRules: []MatchedRuleInfo{},
			Flagged:      respFlagged,
		}
		if err := store.Insert(respPacket); err != nil {
			log.Printf("[%s] sniffer: failed to log response: %v", svc.Name, err)
		}
	})
}

// CheckFlagged checks whether any of the packet content matches the flag regex.
func CheckFlagged(flagRegex *regexp.Regexp, url, headers string, body []byte) bool {
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
	statusCode int
	body       bytes.Buffer
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
