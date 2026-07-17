package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/SimoneErrigo/Janus/backend/internal/config"
	januspcap "github.com/SimoneErrigo/Janus/backend/internal/pcap"
	"github.com/SimoneErrigo/Janus/backend/internal/sniffer"
	"github.com/SimoneErrigo/Janus/backend/internal/storage"
)

const (
	maxPCAPUploadSize   int64 = 256 << 20
	maxPCAPRequestSize        = maxPCAPUploadSize + (1 << 20)
	pcapFormMemory            = 8 << 20
	pcapImportJobTTL          = time.Hour
	maxPcapSelectionIDs       = 10_000
)

// ---- Import progress hub ----

type importState struct {
	State           string `json:"state"` // "running" | "done" | "error"
	PacketsImported int    `json:"packets_imported"`
	ServiceID       string `json:"service_id,omitempty"`
	Error           string `json:"error,omitempty"`
	updatedAt       time.Time
	cancel          context.CancelFunc
}

type importHub struct {
	mu     sync.RWMutex
	jobs   map[string]*importState
	active int
	idle   chan struct{}
}

var globalImportHub = &importHub{jobs: make(map[string]*importState)}

func (h *importHub) create(id string) context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	h.mu.Lock()
	h.pruneLocked(time.Now())
	if h.active == 0 {
		h.idle = make(chan struct{})
	}
	h.active++
	h.jobs[id] = &importState{State: "running", updatedAt: time.Now(), cancel: cancel}
	h.mu.Unlock()
	return ctx
}

func (h *importHub) get(id string) (importState, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pruneLocked(time.Now())
	s, ok := h.jobs[id]
	if !ok {
		return importState{}, false
	}
	return *s, true
}

func (h *importHub) update(id string, fn func(*importState)) {
	h.mu.Lock()
	if s, ok := h.jobs[id]; ok {
		fn(s)
		s.updatedAt = time.Now()
	}
	h.mu.Unlock()
}

func (h *importHub) finish(id, state, serviceID, message string, imported int) {
	h.mu.Lock()
	s, ok := h.jobs[id]
	var cancel context.CancelFunc
	if ok && s.State == "running" {
		s.State, s.ServiceID, s.Error = state, serviceID, message
		s.PacketsImported, s.updatedAt = imported, time.Now()
		cancel, s.cancel = s.cancel, nil
		h.active--
		if h.active == 0 && h.idle != nil {
			close(h.idle)
		}
	}
	h.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (h *importHub) cancelAll() {
	h.mu.RLock()
	cancels := make([]context.CancelFunc, 0, h.active)
	for _, job := range h.jobs {
		if job.State == "running" && job.cancel != nil {
			cancels = append(cancels, job.cancel)
		}
	}
	h.mu.RUnlock()
	for _, cancel := range cancels {
		cancel()
	}
}

func (h *importHub) pruneLocked(now time.Time) {
	for id, job := range h.jobs {
		if job.State != "running" && now.Sub(job.updatedAt) > pcapImportJobTTL {
			delete(h.jobs, id)
		}
	}
}

func (h *importHub) wait(ctx context.Context) error {
	h.mu.RLock()
	if h.active == 0 {
		h.mu.RUnlock()
		return nil
	}
	done := h.idle
	h.mu.RUnlock()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// WaitForPcapImports lets the process shutdown drain imports before closing
// the packet store. Call it after the HTTP server has stopped accepting work.
func (s *Server) WaitForPcapImports(ctx context.Context) error {
	err := globalImportHub.wait(ctx)
	if err == nil {
		return nil
	}
	// A very large import must never outlive the SQLite store. Once the normal
	// grace period expires, cancel every parser and wait for acknowledgement
	// before shutdown is allowed to close the database.
	globalImportHub.cancelAll()
	_ = globalImportHub.wait(context.Background())
	return err
}

// pcapDir returns the configured export directory and ensures it exists.
func pcapDir() (string, error) {
	dir := config.Get().PcapExportDir
	if dir == "" {
		dir = config.Get().DataDir + "/pcap"
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("creating pcap dir %s: %w", dir, err)
	}
	return dir, nil
}

// safeName validates and resolves a file name inside the export directory.
// Returns an error if the name would escape the directory.
func safeName(dir, name string) (string, error) {
	base := filepath.Base(name)
	if base == "." || base == ".." || base == "" || base != name || !strings.EqualFold(filepath.Ext(base), ".pcap") {
		return "", fmt.Errorf("invalid filename")
	}
	root, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("resolving export directory: %w", err)
	}
	full := filepath.Join(root, base)
	rel, err := filepath.Rel(root, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid filename")
	}
	return full, nil
}

func createPcapFile(dir, prefix string) (*os.File, string, error) {
	stamp := time.Now().UTC().Format("20060102-150405.000")
	f, err := os.CreateTemp(dir, prefix+"-"+stamp+"-*.pcap")
	if err != nil {
		return nil, "", err
	}
	return f, filepath.Base(f.Name()), nil
}

// ExportPcap queries packets with the given filter, writes a .pcap file and
// returns the file name, packet count and file size. Called from both the
// HTTP handler and the auto-save path in handleTrafficCaptureStop.
func (s *Server) ExportPcap(q sniffer.PacketQuery) (filename string, count int, sizeBytes int64, err error) {
	filename, count, sizeBytes, _, err = s.exportPcap(q)
	return
}

func (s *Server) exportPcap(q sniffer.PacketQuery) (filename string, count int, sizeBytes int64, truncated bool, err error) {
	q.SortOrder = "asc"
	if q.Limit <= 0 {
		q.Limit = 100_000
	}

	packets, total, queryErr := s.packetStore.Query(q)
	if queryErr != nil {
		return "", 0, 0, false, fmt.Errorf("querying packets: %w", queryErr)
	}

	dir, dirErr := pcapDir()
	if dirErr != nil {
		return "", 0, 0, false, dirErr
	}

	f, filename, createErr := createPcapFile(dir, "janus")
	if createErr != nil {
		return "", 0, 0, false, fmt.Errorf("creating file: %w", createErr)
	}
	fullPath := f.Name()
	keep := false
	defer func() {
		_ = f.Close()
		if !keep {
			_ = os.Remove(fullPath)
		}
	}()

	if writeErr := januspcap.WritePcap(f, packets); writeErr != nil {
		return "", 0, 0, false, fmt.Errorf("writing pcap: %w", writeErr)
	}
	if closeErr := f.Close(); closeErr != nil {
		return "", 0, 0, false, fmt.Errorf("closing pcap: %w", closeErr)
	}

	info, statErr := os.Stat(fullPath)
	if statErr != nil {
		return "", 0, 0, false, fmt.Errorf("stating pcap: %w", statErr)
	}
	keep = true
	return filename, len(packets), info.Size(), total > len(packets), nil
}

// GET /api/packets/flow/pcap?packet_id=X
// Resolves the flow for the given anchor packet and streams it as a .pcap file
// (Content-Disposition: attachment). Browser links authenticate with the
// same-origin HttpOnly session cookie; credentials are never put in the URL.
func (s *Server) handleFlowPcap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	packetIDStr := r.URL.Query().Get("packet_id")
	if packetIDStr == "" {
		http.Error(w, "packet_id is required", http.StatusBadRequest)
		return
	}

	packetID, err := strconv.ParseInt(packetIDStr, 10, 64)
	if err != nil || packetID <= 0 {
		http.Error(w, "invalid packet_id", http.StatusBadRequest)
		return
	}

	packets, err := s.packetStore.QueryFlow(packetID)
	if err != nil {
		http.Error(w, "flow query error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if len(packets) == 0 {
		http.Error(w, "no packets found for this flow", http.StatusNotFound)
		return
	}

	filename := fmt.Sprintf("flow-%d.pcap", packetID)
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))

	if err := januspcap.WritePcap(w, packets); err != nil {
		// Headers already sent — can't change status code, just log
		log.Printf("flow PCAP download failed for packet %d: %v", packetID, err)
	}
}

// POST /api/pcap/export
func (s *Server) handlePcapExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var req struct {
		ServiceID string `json:"service_id"`
		SessionID string `json:"session_id"`
		TimeFrom  string `json:"time_from"`
		TimeTo    string `json:"time_to"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	q := sniffer.PacketQuery{
		ServiceID: req.ServiceID,
		SessionID: req.SessionID,
	}
	if req.TimeFrom != "" {
		t, err := time.Parse(time.RFC3339, req.TimeFrom)
		if err != nil {
			http.Error(w, "time_from must be RFC3339", http.StatusBadRequest)
			return
		}
		q.TimeFrom = &t
	}
	if req.TimeTo != "" {
		t, err := time.Parse(time.RFC3339, req.TimeTo)
		if err != nil {
			http.Error(w, "time_to must be RFC3339", http.StatusBadRequest)
			return
		}
		q.TimeTo = &t
	}

	filename, count, size, truncated, err := s.exportPcap(q)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"filename":     filename,
		"packet_count": count,
		"size_bytes":   size,
		"truncated":    truncated,
	})
}

// POST /api/pcap/export-selection
// Body: {"ids": [int64, ...]} — exports a .pcap file containing exactly the
// listed packets (sorted by timestamp asc). The file is written to the pcap
// dir like /api/pcap/export so it shows up in the files list.
func (s *Server) handlePcapExportSelection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var body struct {
		IDs []int64 `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(body.IDs) == 0 {
		http.Error(w, "ids is required", http.StatusBadRequest)
		return
	}
	if len(body.IDs) > maxPcapSelectionIDs {
		http.Error(w, fmt.Sprintf("at most %d packet ids can be exported", maxPcapSelectionIDs), http.StatusRequestEntityTooLarge)
		return
	}

	packets := make([]*sniffer.Packet, 0, len(body.IDs))
	seen := make(map[int64]struct{}, len(body.IDs))
	for _, id := range body.IDs {
		if _, duplicate := seen[id]; duplicate {
			continue
		}
		seen[id] = struct{}{}
		pkt, err := s.packetStore.GetPacketByID(id)
		if err != nil {
			continue
		}
		packets = append(packets, pkt)
	}
	if len(packets) == 0 {
		http.Error(w, "no packets found for the given ids", http.StatusNotFound)
		return
	}
	sort.SliceStable(packets, func(i, j int) bool {
		return packets[i].Timestamp.Before(packets[j].Timestamp)
	})

	dir, err := pcapDir()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	f, filename, err := createPcapFile(dir, "janus-selection")
	if err != nil {
		http.Error(w, "creating file: "+err.Error(), http.StatusInternalServerError)
		return
	}
	fullPath := f.Name()
	keep := false
	defer func() {
		_ = f.Close()
		if !keep {
			_ = os.Remove(fullPath)
		}
	}()
	if err := januspcap.WritePcap(f, packets); err != nil {
		http.Error(w, "writing pcap: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := f.Close(); err != nil {
		http.Error(w, "closing pcap: "+err.Error(), http.StatusInternalServerError)
		return
	}
	info, err := os.Stat(fullPath)
	if err != nil {
		http.Error(w, "stating pcap: "+err.Error(), http.StatusInternalServerError)
		return
	}
	keep = true
	log.Printf("[user=%s] action=pcap-export-selection count=%d file=%s",
		DisplayNameFromRequest(r), len(packets), filename)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"filename":     filename,
		"packet_count": len(packets),
		"size_bytes":   info.Size(),
	})
}

// GET /api/pcap/files
func (s *Server) handlePcapListFiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	dir, err := pcapDir()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		http.Error(w, "listing pcap files: "+err.Error(), http.StatusInternalServerError)
		return
	}
	type fileInfo struct {
		Name      string `json:"name"`
		SizeBytes int64  `json:"size_bytes"`
		ModTime   string `json:"mod_time"`
	}
	var files []fileInfo
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pcap") {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		fi := fileInfo{Name: e.Name(), SizeBytes: info.Size(), ModTime: info.ModTime().UTC().Format(time.RFC3339)}
		files = append(files, fi)
	}
	if files == nil {
		files = []fileInfo{}
	}
	sort.Slice(files, func(i, j int) bool {
		if files[i].ModTime != files[j].ModTime {
			return files[i].ModTime > files[j].ModTime
		}
		return files[i].Name < files[j].Name
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{"files": files})
}

// GET /api/pcap/files/{name}  — download
// DELETE /api/pcap/files/{name} — delete
func (s *Server) handlePcapFile(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/pcap/files/")
	if name == "" {
		http.Error(w, "missing filename", http.StatusBadRequest)
		return
	}
	dir, err := pcapDir()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fullPath, err := safeName(dir, name)
	if err != nil {
		http.Error(w, "invalid filename", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		fileInfo, err := os.Lstat(fullPath)
		if err != nil || !fileInfo.Mode().IsRegular() {
			http.Error(w, "file not found", http.StatusNotFound)
			return
		}
		f, err := os.Open(fullPath)
		if err != nil {
			http.Error(w, "file not found", http.StatusNotFound)
			return
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() {
			http.Error(w, "file not found", http.StatusNotFound)
			return
		}
		base := filepath.Base(fullPath)
		w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, base))
		w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))
		buf := make([]byte, 32*1024)
		for {
			n, readErr := f.Read(buf)
			if n > 0 {
				if _, writeErr := w.Write(buf[:n]); writeErr != nil {
					return
				}
			}
			if errors.Is(readErr, io.EOF) {
				return
			}
			if readErr != nil {
				log.Printf("PCAP download failed for %s: %v", base, readErr)
				return
			}
		}

	case http.MethodDelete:
		if err := os.Remove(fullPath); err != nil {
			http.Error(w, "file not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// POST /api/pcap/import — multipart upload of a .pcap file.
// Form fields: file (required), service_id (optional — creates a virtual service if empty).
// Returns { import_id, service_id } immediately; parsing runs in background.
func (s *Server) handlePcapImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// MaxBytesReader enforces a real request limit; ParseMultipartForm's
	// argument only controls how much of the multipart body stays in memory.
	r.Body = http.MaxBytesReader(w, r.Body, maxPCAPRequestSize)
	if err := r.ParseMultipartForm(pcapFormMemory); err != nil {
		status := http.StatusBadRequest
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		http.Error(w, "failed to parse upload: "+err.Error(), status)
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "missing 'file' field", http.StatusBadRequest)
		return
	}
	defer file.Close()
	if header.Size > maxPCAPUploadSize {
		http.Error(w, fmt.Sprintf("pcap exceeds %d MiB upload limit", maxPCAPUploadSize>>20), http.StatusRequestEntityTooLarge)
		return
	}

	serviceID := strings.TrimSpace(r.FormValue("service_id"))
	// protocol_id is optional. When supplied, it's bound to the (existing
	// or auto-created) service so imported packets are auto-decoded with
	// the chosen custom protocol — same behavior as the live capture path.
	protocolID := strings.TrimSpace(r.FormValue("protocol_id"))
	if serviceID != "" && (len(serviceID) > 128 || !serviceIDPattern.MatchString(serviceID)) {
		http.Error(w, "invalid service_id", http.StatusBadRequest)
		return
	}
	if len(protocolID) > 128 || (protocolID != "" && !serviceIDPattern.MatchString(protocolID)) {
		http.Error(w, "invalid protocol_id", http.StatusBadRequest)
		return
	}
	if protocolID != "" {
		if _, ok := s.store.GetProtocol(protocolID); !ok {
			http.Error(w, "protocol_id not found", http.StatusBadRequest)
			return
		}
	}

	// The multipart file belongs to the request and may be removed when this
	// handler returns. Copy it to an owned temporary file before launching the
	// background import, with a second byte-count guard for unknown sizes.
	tmp, err := os.CreateTemp("", "janus-pcap-import-*")
	if err != nil {
		http.Error(w, "failed to stage upload: "+err.Error(), http.StatusInternalServerError)
		return
	}
	tmpPath := tmp.Name()
	removeTemp := true
	defer func() {
		_ = tmp.Close()
		if removeTemp {
			_ = os.Remove(tmpPath)
		}
	}()
	written, copyErr := io.Copy(tmp, io.LimitReader(file, maxPCAPUploadSize+1))
	closeErr := tmp.Close()
	if written > maxPCAPUploadSize {
		http.Error(w, fmt.Sprintf("pcap exceeds %d MiB upload limit", maxPCAPUploadSize>>20), http.StatusRequestEntityTooLarge)
		return
	}
	if copyErr != nil || closeErr != nil {
		if copyErr == nil {
			copyErr = closeErr
		}
		http.Error(w, "failed to stage upload: "+copyErr.Error(), http.StatusInternalServerError)
		return
	}
	importRaw := make([]byte, 8)
	if _, err := rand.Read(importRaw); err != nil {
		http.Error(w, "failed to generate import id", http.StatusInternalServerError)
		return
	}
	importID := hex.EncodeToString(importRaw)
	generatedServiceID := ""
	if serviceID == "" {
		serviceRaw := make([]byte, 6)
		if _, err := rand.Read(serviceRaw); err != nil {
			http.Error(w, "failed to generate service id", http.StatusInternalServerError)
			return
		}
		generatedServiceID = "pcap-" + hex.EncodeToString(serviceRaw)
	}

	s.protocolMu.Lock()
	if protocolID != "" {
		if _, ok := s.store.GetProtocol(protocolID); !ok {
			s.protocolMu.Unlock()
			http.Error(w, "protocol_id was deleted while the upload was staged", http.StatusConflict)
			return
		}
	}
	s.serviceMu.Lock()
	if serviceID == "" {
		// Create a virtual service named pcap:<filename>
		uploadName := filepath.Base(header.Filename)
		if uploadName == "." || uploadName == "" {
			uploadName = "upload.pcap"
		}
		if runes := []rune(uploadName); len(runes) > 128 {
			uploadName = string(runes[:128])
		}
		svc := &storage.Service{
			ID:         generatedServiceID,
			Name:       "pcap:" + uploadName,
			ListenAddr: "",
			ListenPort: 0,
			TargetAddr: "",
			Protocol:   storage.ProtocolTCP,
			ProtocolID: protocolID,
			Enabled:    false,
		}
		if err := s.store.CreateService(svc); err != nil {
			s.serviceMu.Unlock()
			s.protocolMu.Unlock()
			http.Error(w, "failed to create virtual service: "+err.Error(), http.StatusInternalServerError)
			return
		}
		serviceID = generatedServiceID
		log.Printf("PCAP import: created virtual service %s for %s (protocol=%q)", generatedServiceID, header.Filename, protocolID)
	} else {
		svc, ok := s.store.GetService(serviceID)
		if !ok {
			s.serviceMu.Unlock()
			s.protocolMu.Unlock()
			http.Error(w, "service_id not found", http.StatusBadRequest)
			return
		}
		// Only update the binding when the import explicitly carries one;
		// an empty form field leaves the existing binding untouched so we
		// don't accidentally clear protocols set up earlier.
		if protocolID != "" && svc.ProtocolID != protocolID {
			svc.ProtocolID = protocolID
			if err := s.store.UpdateService(svc); err != nil {
				s.serviceMu.Unlock()
				s.protocolMu.Unlock()
				http.Error(w, "failed to bind protocol: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}
	}
	s.serviceMu.Unlock()
	s.protocolMu.Unlock()

	importCtx := globalImportHub.create(importID)

	// Capture request body into memory before returning (file will be removed after handler exits)
	user := DisplayNameFromRequest(r)
	log.Printf("PCAP import: user=%s file=%s size=%d import_id=%s service=%s",
		user, header.Filename, header.Size, importID, serviceID)

	go s.runPcapImport(importCtx, importID, serviceID, tmpPath, header.Filename)
	removeTemp = false

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"import_id":  importID,
		"service_id": serviceID,
	})
}

// runPcapImport parses the uploaded pcap and inserts packets. Called from a goroutine.
func (s *Server) runPcapImport(ctx context.Context, importID, serviceID, tempPath, filename string) {
	defer os.Remove(tempPath)
	defer func() {
		if rec := recover(); rec != nil {
			globalImportHub.finish(importID, "error", serviceID, fmt.Sprintf("panic: %v", rec), 0)
		}
	}()
	file, err := os.Open(tempPath)
	if err != nil {
		globalImportHub.finish(importID, "error", serviceID, err.Error(), 0)
		return
	}
	defer file.Close()

	var flagRE *regexp.Regexp
	cfg := config.Get()
	pat := cfg.FlagRegex
	if cfg.FlagRegexCaseInsensitive && pat != "" && !strings.HasPrefix(pat, "(?i)") {
		pat = "(?i)" + pat
	}
	if pat != "" {
		if re, err := regexp.Compile(pat); err == nil {
			flagRE = re
		}
	}

	packets, err := januspcap.ParsePCAPAsPackets(contextReader{ctx: ctx, reader: file}, serviceID, flagRE, s.flagIDPoller)
	if err != nil {
		globalImportHub.finish(importID, "error", serviceID, err.Error(), 0)
		log.Printf("PCAP import %s failed: %v", importID, err)
		return
	}

	inserted := 0
	for _, pkt := range packets {
		if err := ctx.Err(); err != nil {
			globalImportHub.finish(importID, "error", serviceID, "import cancelled during shutdown", inserted)
			return
		}
		if err := s.packetStore.Insert(pkt); err != nil {
			log.Printf("PCAP import %s: insert error: %v", importID, err)
			continue
		}
		inserted++
		if inserted%100 == 0 {
			globalImportHub.update(importID, func(st *importState) { st.PacketsImported = inserted })
		}
	}

	globalImportHub.finish(importID, "done", serviceID, "", inserted)
	log.Printf("PCAP import %s done: %d packets from %s", importID, inserted, filename)
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	select {
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	default:
		return r.reader.Read(p)
	}
}

// GET /api/pcap/import/{id}/status — check progress of a running import.
func (s *Server) handlePcapImportStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/pcap/import/")
	path = strings.TrimSuffix(path, "/status")
	path = strings.Trim(path, "/")
	if path == "" {
		http.Error(w, "missing import id", http.StatusBadRequest)
		return
	}
	st, ok := globalImportHub.get(path)
	if !ok {
		http.Error(w, "import not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, st)
}
