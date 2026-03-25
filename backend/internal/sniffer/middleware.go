package sniffer

import (
	"bytes"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/SimoneErrigo/Janus/backend/internal/dropper"
	"github.com/SimoneErrigo/Janus/backend/internal/storage"
)

const maxBodyCapture = 1 << 20 // 1 MB

// HTTPMiddleware returns an http.Handler that logs requests/responses and evaluates drop rules.
func HTTPMiddleware(next http.Handler, svc *storage.Service, store *PacketStore, dropEngine *dropper.Engine) http.Handler {
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

		// Log request packet
		reqPacket := &Packet{
			ServiceID: svc.ID,
			Timestamp: start,
			SrcIP:     srcIP,
			SrcPort:   srcPort,
			DstIP:     dstIP,
			DstPort:   dstPort,
			Protocol:  string(svc.Protocol),
			Direction: DirectionRequest,
			Method:    r.Method,
			URL:       r.URL.String(),
			Headers:   reqHeaders,
			Body:      reqBody,
		}
		if err := store.Insert(reqPacket); err != nil {
			log.Printf("[%s] sniffer: failed to log request: %v", svc.Name, err)
		}

		// Evaluate drop rules
		if dropEngine != nil {
			headersStr := flattenHeadersString(r.Header)
			result := dropEngine.Evaluate(&dropper.HTTPRequest{
				ServiceID: svc.ID,
				Headers:   headersStr,
				Body:      reqBody,
				URL:       r.URL.String(),
			})
			if result.Matched {
				log.Printf("[%s] DROP: rule %q matched request %s %s", svc.Name, result.Rule.Name, r.Method, r.URL.String())
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}

		// Wrap response writer to capture status and body
		rw := &responseCapture{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rw, r)

		// Log response packet
		respHeaders := flattenHeaders(rw.Header())
		respPacket := &Packet{
			ServiceID: svc.ID,
			Timestamp: time.Now(),
			SrcIP:     dstIP,
			SrcPort:   dstPort,
			DstIP:     srcIP,
			DstPort:   srcPort,
			Protocol:  string(svc.Protocol),
			Direction: DirectionResponse,
			Method:    r.Method,
			URL:       r.URL.String(),
			Status:    rw.statusCode,
			Headers:   respHeaders,
			Body:      rw.body.Bytes(),
		}
		if err := store.Insert(respPacket); err != nil {
			log.Printf("[%s] sniffer: failed to log response: %v", svc.Name, err)
		}
	})
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
