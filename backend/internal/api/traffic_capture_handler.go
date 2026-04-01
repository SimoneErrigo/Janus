package api

import (
	"log"
	"net/http"
	"time"

	"github.com/SimoneErrigo/Janus/backend/internal/sniffer"
)

type captureStatusResponse struct {
	Mode         string `json:"mode"`
	Capturing    bool   `json:"capturing"`
	CanCapture   bool   `json:"can_capture"`
	CaptureStart string `json:"capture_start,omitempty"`
	CaptureStop  string `json:"capture_stop,omitempty"`
}

func (s *Server) currentCaptureStatus() captureStatusResponse {
	mode := sniffer.TrafficModeLive
	capturing := true
	canCapture := false
	var start, stop string
	if s.captureCtrl != nil {
		mode = s.captureCtrl.Mode()
		capturing = s.captureCtrl.IsCapturing()
		canCapture = mode == sniffer.TrafficModeStatic
		if from, to, ok := s.captureCtrl.CaptureWindow(); ok {
			start = from.UTC().Format(time.RFC3339Nano)
			stop = to.UTC().Format(time.RFC3339Nano)
		}
	}
	return captureStatusResponse{
		Mode:         mode,
		Capturing:    capturing,
		CanCapture:   canCapture,
		CaptureStart: start,
		CaptureStop:  stop,
	}
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
	if s.captureCtrl == nil || !s.captureCtrl.StartCapture() {
		http.Error(w, "capture start is only available in static mode", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, s.currentCaptureStatus())
}

func (s *Server) handleTrafficCaptureStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.captureCtrl == nil || !s.captureCtrl.StopCapture() {
		http.Error(w, "capture stop is only available while static capture is active", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, s.currentCaptureStatus())
}

func (s *Server) handleTrafficCaptureApplyFlagIDs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.captureCtrl == nil || s.captureCtrl.Mode() != sniffer.TrafficModeStatic {
		http.Error(w, "apply flagIds is only available in static mode", http.StatusBadRequest)
		return
	}
	from, to, ok := s.captureCtrl.CaptureWindow()
	if !ok {
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
	updated, err := s.packetStore.BackfillFlagIDsWindow(s.flagIDPoller, currentRound, from, to)
	if err != nil {
		http.Error(w, "backfill error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if s.packetHub != nil {
		s.packetHub.Notify()
	}
	log.Printf("static apply-flagids: updated %d packets for window %s - %s (round=%d)", updated, from.UTC().Format(time.RFC3339), to.UTC().Format(time.RFC3339), currentRound)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"updated":       updated,
		"current_round": currentRound,
		"from":          from.UTC().Format(time.RFC3339Nano),
		"to":            to.UTC().Format(time.RFC3339Nano),
	})
}
