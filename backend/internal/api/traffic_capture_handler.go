package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/SimoneErrigo/Janus/backend/internal/config"
	"github.com/SimoneErrigo/Janus/backend/internal/sniffer"
)

type captureStatusResponse struct {
	Mode                 string   `json:"mode"`
	Capturing            bool     `json:"capturing"`
	CanCapture           bool     `json:"can_capture"`
	ConfiguredServiceIDs []string `json:"configured_service_ids"`
	ServiceIDs           []string `json:"service_ids"`
	CaptureStart         string   `json:"capture_start,omitempty"`
	CaptureStop          string   `json:"capture_stop,omitempty"`
}

func (s *Server) currentCaptureStatus() captureStatusResponse {
	mode := sniffer.TrafficModeLive
	capturing := true
	canCapture := false
	var start, stop string
	configuredServiceIDs := append([]string{}, config.Get().StaticCaptureServiceIDs...)
	captureServiceIDs := []string{}
	if s.captureCtrl != nil {
		snapshot := s.captureCtrl.Snapshot()
		mode = snapshot.Mode
		capturing = snapshot.Capturing
		canCapture = mode == sniffer.TrafficModeStatic && len(configuredServiceIDs) > 0
		if canCapture && s.validateCaptureServiceIDs(configuredServiceIDs, true) != nil {
			canCapture = false
		}
		captureServiceIDs = snapshot.ServiceIDs
		if !snapshot.CaptureStart.IsZero() {
			to := snapshot.CaptureStop
			if snapshot.Capturing {
				to = time.Now()
			}
			start = snapshot.CaptureStart.UTC().Format(time.RFC3339Nano)
			stop = to.UTC().Format(time.RFC3339Nano)
		}
	}
	return captureStatusResponse{
		Mode:                 mode,
		Capturing:            capturing,
		CanCapture:           canCapture,
		ConfiguredServiceIDs: configuredServiceIDs,
		ServiceIDs:           captureServiceIDs,
		CaptureStart:         start,
		CaptureStop:          stop,
	}
}

type captureStartRequest struct {
	ServiceIDs []string `json:"service_ids"`
}

func (s *Server) handleTrafficCaptureStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.currentCaptureStatus())
}

func (s *Server) handleTrafficCaptureStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req captureStartRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	decodeErr := decoder.Decode(&req)
	requestedServiceIDs := req.ServiceIDs
	useConfiguredPreset := errors.Is(decodeErr, io.EOF)
	if useConfiguredPreset {
		// Preserve compatibility with the original body-less Start endpoint:
		// it now uses the explicit persisted preset, never an all-services
		// wildcard. Sending an explicit empty array still means "capture none".
	} else if decodeErr != nil {
		http.Error(w, "invalid JSON: "+decodeErr.Error(), http.StatusBadRequest)
		return
	} else if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("multiple JSON values are not allowed")
		}
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	s.serviceMu.Lock()
	defer s.serviceMu.Unlock()
	// Persist the operator's preset and snapshot the same sorted IDs atomically
	// with respect to Config saves and competing Start requests.
	s.configMu.Lock()
	defer s.configMu.Unlock()
	if useConfiguredPreset {
		requestedServiceIDs = config.Get().StaticCaptureServiceIDs
	}
	serviceIDs, err := normalizeCaptureServiceIDs(requestedServiceIDs)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(serviceIDs) == 0 {
		http.Error(w, "select at least one enabled service before starting static capture", http.StatusBadRequest)
		return
	}
	if err := s.validateCaptureServiceIDs(serviceIDs, true); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if s.captureCtrl == nil {
		http.Error(w, "capture controller is unavailable", http.StatusServiceUnavailable)
		return
	}
	previous := config.Get()
	if s.captureCtrl.Mode() != sniffer.TrafficModeStatic {
		http.Error(w, sniffer.ErrCaptureNotStatic.Error(), http.StatusBadRequest)
		return
	}
	if s.captureCtrl.IsCapturing() {
		http.Error(w, sniffer.ErrCaptureAlreadyActive.Error(), http.StatusConflict)
		return
	}
	if _, err := config.Update(func(next *config.Config) error {
		next.StaticCaptureServiceIDs = append([]string{}, serviceIDs...)
		return nil
	}); err != nil {
		http.Error(w, "saving static capture scope: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.captureCtrl.StartCapture(serviceIDs); err != nil {
		_, rollbackErr := config.Update(func(next *config.Config) error {
			*next = *previous
			return nil
		})
		status := http.StatusBadRequest
		if errors.Is(err, sniffer.ErrCaptureAlreadyActive) {
			status = http.StatusConflict
		}
		message := err.Error()
		if rollbackErr != nil {
			message += "; restoring capture preset: " + rollbackErr.Error()
		}
		http.Error(w, message, status)
		return
	}
	writeJSON(w, http.StatusOK, s.currentCaptureStatus())
}

func (s *Server) handleTrafficCaptureStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.captureCtrl == nil {
		http.Error(w, "capture stop is only available while static capture is active", http.StatusBadRequest)
		return
	}
	session, stopped := s.captureCtrl.StopCaptureWithSnapshot()
	if !stopped {
		http.Error(w, "capture stop is only available while static capture is active", http.StatusBadRequest)
		return
	}

	// Auto-save PCAP if configured
	cfg := config.Get()
	if cfg.PcapAutoSave && s.packetStore != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		flushErr := s.packetStore.Flush(ctx)
		cancel()
		q := sniffer.PacketQuery{
			TimeFrom:   &session.CaptureStart,
			TimeTo:     &session.CaptureStop,
			ServiceIDs: session.ServiceIDs,
		}
		if flushErr != nil {
			log.Printf("auto-save pcap failed while flushing capture queue: %v", flushErr)
		} else if filename, count, _, err := s.ExportPcap(q); err == nil {
			log.Printf("auto-save pcap: %s (%d packets, window %s-%s)", filename, count, session.CaptureStart.Format(time.RFC3339), session.CaptureStop.Format(time.RFC3339))
		} else {
			log.Printf("auto-save pcap failed: %v", err)
		}
	}

	writeJSON(w, http.StatusOK, s.currentCaptureStatus())
}

func (s *Server) handleTrafficCaptureApplyFlagIDs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.captureCtrl == nil {
		http.Error(w, "apply flagIds is only available in static mode", http.StatusBadRequest)
		return
	}
	// Start and traffic-mode changes take this lock too. Keep capture stopped
	// for the whole backfill so the SQLite writer is not reactivated midway.
	s.configMu.Lock()
	defer s.configMu.Unlock()
	// Read mode, completion state, window and scope in one immutable snapshot.
	// The snapshot also prevents any later controller change from retargeting it.
	session := s.captureCtrl.Snapshot()
	if session.Mode != sniffer.TrafficModeStatic {
		http.Error(w, "apply flagIds is only available in static mode", http.StatusBadRequest)
		return
	}
	if session.Capturing {
		http.Error(w, "stop capture before applying flagIds", http.StatusConflict)
		return
	}
	if session.CaptureStart.IsZero() || session.CaptureStop.IsZero() || len(session.ServiceIDs) == 0 {
		http.Error(w, "no static capture window available; start and stop capture first", http.StatusBadRequest)
		return
	}

	if s.flagIDPoller != nil {
		s.flagIDPoller.FetchNow()
	}
	currentRound := 0
	if s.flagIDPoller != nil {
		currentRound = s.flagIDPoller.CurrentRound()
	}
	updated, err := s.packetStore.BackfillFlagIDsWindowForServices(
		s.flagIDPoller,
		currentRound,
		session.CaptureStart,
		session.CaptureStop,
		session.ServiceIDs,
	)
	if err != nil {
		http.Error(w, "backfill error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if s.packetHub != nil {
		s.packetHub.Notify()
	}
	log.Printf("static apply-flagids: updated %d packets for window %s - %s (round=%d)", updated, session.CaptureStart.UTC().Format(time.RFC3339), session.CaptureStop.UTC().Format(time.RFC3339), currentRound)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"updated":       updated,
		"current_round": currentRound,
		"from":          session.CaptureStart.UTC().Format(time.RFC3339Nano),
		"to":            session.CaptureStop.UTC().Format(time.RFC3339Nano),
		"service_ids":   session.ServiceIDs,
	})
}
