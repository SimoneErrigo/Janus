package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/SimoneErrigo/Janus/backend/internal/config"
	januspcap "github.com/SimoneErrigo/Janus/backend/internal/pcap"
	"github.com/SimoneErrigo/Janus/backend/internal/sniffer"
	"github.com/SimoneErrigo/Janus/backend/internal/storage"
)

// ---- Import progress hub ----

type importState struct {
	State           string `json:"state"`            // "running" | "done" | "error"
	PacketsImported int    `json:"packets_imported"`
	ServiceID       string `json:"service_id,omitempty"`
	Error           string `json:"error,omitempty"`
}

type importHub struct {
	mu    sync.RWMutex
	jobs  map[string]*importState
}

var globalImportHub = &importHub{jobs: make(map[string]*importState)}

func (h *importHub) create(id string) {
	h.mu.Lock()
	h.jobs[id] = &importState{State: "running"}
	h.mu.Unlock()
}

func (h *importHub) get(id string) (importState, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
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
	}
	h.mu.Unlock()
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
	if base == "." || base == ".." || base == "" {
		return "", fmt.Errorf("invalid filename")
	}
	full := filepath.Join(dir, base)
	if !strings.HasPrefix(full, filepath.Clean(dir)+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid filename")
	}
	return full, nil
}

// ExportPcap queries packets with the given filter, writes a .pcap file and
// returns the file name, packet count and file size. Called from both the
// HTTP handler and the auto-save path in handleTrafficCaptureStop.
func (s *Server) ExportPcap(q sniffer.PacketQuery) (filename string, count int, sizeBytes int64, err error) {
	q.SortOrder = "asc"
	if q.Limit <= 0 {
		q.Limit = 100_000
	}

	packets, total, queryErr := s.packetStore.Query(q)
	if queryErr != nil {
		return "", 0, 0, fmt.Errorf("querying packets: %w", queryErr)
	}

	dir, dirErr := pcapDir()
	if dirErr != nil {
		return "", 0, 0, dirErr
	}

	ts := time.Now().UTC().Format("20060102-150405")
	filename = fmt.Sprintf("janus-%s.pcap", ts)
	fullPath := filepath.Join(dir, filename)

	f, createErr := os.Create(fullPath)
	if createErr != nil {
		return "", 0, 0, fmt.Errorf("creating file: %w", createErr)
	}
	defer f.Close()

	if writeErr := januspcap.WritePcap(f, packets); writeErr != nil {
		os.Remove(fullPath)
		return "", 0, 0, fmt.Errorf("writing pcap: %w", writeErr)
	}

	info, _ := f.Stat()
	size := int64(0)
	if info != nil {
		size = info.Size()
	}
	return filename, total, size, nil
}

// GET /api/packets/flow/pcap?packet_id=X
// Resolves the flow for the given anchor packet and streams it as a .pcap file
// (Content-Disposition: attachment). Auth via ?token= query param so a plain
// browser link / window.open() works without a custom Authorization header.
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

	var packetID int64
	if _, err := fmt.Sscanf(packetIDStr, "%d", &packetID); err != nil {
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
		_ = err
	}
}

// POST /api/pcap/export
func (s *Server) handlePcapExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ServiceID string `json:"service_id"`
		SessionID string `json:"session_id"`
		TimeFrom  string `json:"time_from"`
		TimeTo    string `json:"time_to"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Body is optional — ignore decode errors
		req = struct {
			ServiceID string `json:"service_id"`
			SessionID string `json:"session_id"`
			TimeFrom  string `json:"time_from"`
			TimeTo    string `json:"time_to"`
		}{}
	}

	q := sniffer.PacketQuery{
		ServiceID: req.ServiceID,
		SessionID: req.SessionID,
	}
	if req.TimeFrom != "" {
		if t, err := time.Parse(time.RFC3339, req.TimeFrom); err == nil {
			q.TimeFrom = &t
		}
	}
	if req.TimeTo != "" {
		if t, err := time.Parse(time.RFC3339, req.TimeTo); err == nil {
			q.TimeTo = &t
		}
	}

	filename, count, size, err := s.ExportPcap(q)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"filename":      filename,
		"packet_count":  count,
		"size_bytes":    size,
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
		writeJSON(w, http.StatusOK, map[string]interface{}{"files": []interface{}{}})
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
		info, _ := e.Info()
		fi := fileInfo{Name: e.Name()}
		if info != nil {
			fi.SizeBytes = info.Size()
			fi.ModTime = info.ModTime().UTC().Format(time.RFC3339)
		}
		files = append(files, fi)
	}
	if files == nil {
		files = []fileInfo{}
	}
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
		f, err := os.Open(fullPath)
		if err != nil {
			http.Error(w, "file not found", http.StatusNotFound)
			return
		}
		defer f.Close()
		info, _ := f.Stat()
		base := filepath.Base(fullPath)
		w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, base))
		if info != nil {
			w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))
		}
		buf := make([]byte, 32*1024)
		for {
			n, err := f.Read(buf)
			if n > 0 {
				w.Write(buf[:n])
			}
			if err != nil {
				break
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

	// 256 MB max upload
	if err := r.ParseMultipartForm(256 << 20); err != nil {
		http.Error(w, "failed to parse upload: "+err.Error(), http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "missing 'file' field", http.StatusBadRequest)
		return
	}
	defer file.Close()

	serviceID := strings.TrimSpace(r.FormValue("service_id"))
	// protocol_id is optional. When supplied, it's bound to the (existing
	// or auto-created) service so imported packets are auto-decoded with
	// the chosen custom protocol — same behavior as the live capture path.
	protocolID := strings.TrimSpace(r.FormValue("protocol_id"))
	if protocolID != "" {
		if _, ok := s.store.GetProtocol(protocolID); !ok {
			http.Error(w, "protocol_id not found", http.StatusBadRequest)
			return
		}
	}
	if serviceID == "" {
		// Create a virtual service named pcap:<filename>
		raw := make([]byte, 6)
		_, _ = rand.Read(raw)
		newID := "pcap-" + hex.EncodeToString(raw)
		svc := &storage.Service{
			ID:         newID,
			Name:       "pcap:" + header.Filename,
			ListenAddr: "",
			ListenPort: 0,
			TargetAddr: "",
			Protocol:   storage.ProtocolTCP,
			ProtocolID: protocolID,
			Enabled:    false,
		}
		if err := s.store.CreateService(svc); err != nil {
			http.Error(w, "failed to create virtual service: "+err.Error(), http.StatusInternalServerError)
			return
		}
		serviceID = newID
		log.Printf("PCAP import: created virtual service %s for %s (protocol=%q)", newID, header.Filename, protocolID)
	} else {
		svc, ok := s.store.GetService(serviceID)
		if !ok {
			http.Error(w, "service_id not found", http.StatusBadRequest)
			return
		}
		// Only update the binding when the import explicitly carries one;
		// an empty form field leaves the existing binding untouched so we
		// don't accidentally clear protocols set up earlier.
		if protocolID != "" && svc.ProtocolID != protocolID {
			svc.ProtocolID = protocolID
			if err := s.store.UpdateService(svc); err != nil {
				http.Error(w, "failed to bind protocol: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}
	}

	raw := make([]byte, 8)
	_, _ = rand.Read(raw)
	importID := hex.EncodeToString(raw)
	globalImportHub.create(importID)

	// Capture request body into memory before returning (file will be removed after handler exits)
	user := DisplayNameFromRequest(r)
	log.Printf("PCAP import: user=%s file=%s size=%d import_id=%s service=%s",
		user, header.Filename, header.Size, importID, serviceID)

	go s.runPcapImport(importID, serviceID, file, header.Filename)

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"import_id":  importID,
		"service_id": serviceID,
	})
}

// runPcapImport parses the uploaded pcap and inserts packets. Called from a goroutine.
func (s *Server) runPcapImport(importID, serviceID string, file io.Reader, filename string) {
	defer func() {
		if rec := recover(); rec != nil {
			globalImportHub.update(importID, func(st *importState) {
				st.State = "error"
				st.Error = fmt.Sprintf("panic: %v", rec)
			})
		}
	}()

	var flagRE *regexp.Regexp
	if pat := config.Get().FlagRegex; pat != "" {
		if re, err := regexp.Compile(pat); err == nil {
			flagRE = re
		}
	}

	packets, err := januspcap.ParsePCAPAsPackets(file, serviceID, flagRE, s.flagIDPoller)
	if err != nil {
		globalImportHub.update(importID, func(st *importState) {
			st.State = "error"
			st.Error = err.Error()
		})
		log.Printf("PCAP import %s failed: %v", importID, err)
		return
	}

	inserted := 0
	for _, pkt := range packets {
		if err := s.packetStore.Insert(pkt); err != nil {
			log.Printf("PCAP import %s: insert error: %v", importID, err)
			continue
		}
		inserted++
		if s.packetHub != nil {
			s.packetHub.PushPacket(pkt)
		}
	}

	globalImportHub.update(importID, func(st *importState) {
		st.State = "done"
		st.PacketsImported = inserted
		st.ServiceID = serviceID
	})
	log.Printf("PCAP import %s done: %d packets from %s", importID, inserted, filename)
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
