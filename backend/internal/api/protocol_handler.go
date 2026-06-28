package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/SimoneErrigo/Janus/backend/internal/customdecode"
	"github.com/SimoneErrigo/Janus/backend/internal/protoimport"
	"github.com/SimoneErrigo/Janus/backend/internal/storage"
	"github.com/google/uuid"
)

// handleProtocols dispatches list/create on /api/protocols.
func (s *Server) handleProtocols(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.store.ListProtocols())
	case http.MethodPost:
		s.createProtocol(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleProtocolImport parses pasted Python source (the standard struct +
// enum.Enum idiom used by CTF challenge clients) into a draft CustomProtocol
// that the editor can load. Nothing is persisted: the response carries the
// draft plus any warnings about parts that couldn't be mapped cleanly. The
// user reviews/wires it in the editor and saves through the normal create
// endpoint.
func (s *Server) handleProtocolImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	proto, warnings, err := protoimport.Parse(req.Code)
	if err != nil {
		// 422: the request was well-formed but we found nothing to import.
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"protocol": proto,
		"warnings": warnings,
	})
}

// handleProtocolByID dispatches get/update/delete on /api/protocols/:id.
func (s *Server) handleProtocolByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/protocols/")
	if id == "" {
		http.Error(w, "missing protocol ID", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet:
		p, ok := s.store.GetProtocol(id)
		if !ok {
			http.Error(w, "protocol not found", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, p)
	case http.MethodPut:
		s.updateProtocol(w, r, id)
	case http.MethodDelete:
		if err := s.store.DeleteProtocol(id); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) createProtocol(w http.ResponseWriter, r *http.Request) {
	var p storage.CustomProtocol
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateProtocol(&p); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if p.ID == "" {
		p.ID = uuid.NewString()
	}
	now := time.Now().Unix()
	p.CreatedAt = now
	p.UpdatedAt = now
	if err := s.store.CreateProtocol(&p); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

func (s *Server) updateProtocol(w http.ResponseWriter, r *http.Request, id string) {
	var p storage.CustomProtocol
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	p.ID = id
	if err := validateProtocol(&p); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Preserve CreatedAt across updates so the user can sort by it.
	if existing, ok := s.store.GetProtocol(id); ok {
		p.CreatedAt = existing.CreatedAt
	}
	p.UpdatedAt = time.Now().Unix()
	if err := s.store.UpdateProtocol(&p); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// validateProtocol does the cheap structural checks that prevent garbage
// from getting persisted. The decoder itself is permissive at runtime
// (returns partial trees on bad bodies), so we don't need to reject every
// possible mistake here — just the ones that would corrupt the editor.
func validateProtocol(p *storage.CustomProtocol) error {
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if p.Endian != "" && p.Endian != storage.EndianLittle && p.Endian != storage.EndianBig {
		return fmt.Errorf("endian must be 'little' or 'big'")
	}
	for _, scope := range [][2]any{{"request", p.RequestFields}, {"response", p.ResponseFields}} {
		name := scope[0].(string)
		fields := scope[1].([]storage.ProtocolField)
		if err := validateFieldList(name, fields, p); err != nil {
			return err
		}
	}
	for sname, sfields := range p.Structs {
		if err := validateFieldList("struct "+sname, sfields, p); err != nil {
			return err
		}
	}
	for ename, table := range p.Enums {
		if strings.TrimSpace(ename) == "" {
			return fmt.Errorf("enum name cannot be empty")
		}
		for k := range table {
			if _, err := strconv.ParseInt(k, 10, 64); err != nil {
				return fmt.Errorf("enum %q: key %q must be a number", ename, k)
			}
		}
	}
	return nil
}

func validateFieldList(scope string, fields []storage.ProtocolField, p *storage.CustomProtocol) error {
	seen := make(map[string]bool, len(fields))
	for i, f := range fields {
		if strings.TrimSpace(f.Name) == "" {
			return fmt.Errorf("%s: field #%d has no name", scope, i+1)
		}
		if seen[f.Name] {
			return fmt.Errorf("%s: duplicate field name %q", scope, f.Name)
		}
		seen[f.Name] = true
		if !isValidFieldType(f.Type) {
			return fmt.Errorf("%s: field %q has unknown type %q", scope, f.Name, f.Type)
		}
		switch f.Type {
		case storage.FieldBytesFixed, storage.FieldStringFixed:
			if f.Length <= 0 {
				return fmt.Errorf("%s: field %q requires length > 0", scope, f.Name)
			}
		case storage.FieldDispatch:
			if f.DispatchOn == "" {
				return fmt.Errorf("%s: dispatch field %q must specify dispatch_on", scope, f.Name)
			}
			if !seen[f.DispatchOn] {
				return fmt.Errorf("%s: dispatch field %q references unknown previous field %q", scope, f.Name, f.DispatchOn)
			}
		case storage.FieldBytesComp:
			if f.LengthFrom == "" {
				return fmt.Errorf("%s: bytes_computed field %q must specify length_from", scope, f.Name)
			}
			if !seen[f.LengthFrom] {
				return fmt.Errorf("%s: bytes_computed field %q references unknown previous field %q", scope, f.Name, f.LengthFrom)
			}
			if f.LengthMulFrom != "" && !seen[f.LengthMulFrom] {
				return fmt.Errorf("%s: bytes_computed field %q references unknown previous field %q in length_mul_from", scope, f.Name, f.LengthMulFrom)
			}
			if f.LengthDiv < 0 {
				return fmt.Errorf("%s: bytes_computed field %q has negative length_div", scope, f.Name)
			}
		}
		if f.EnumRef != "" {
			if _, ok := p.Enums[f.EnumRef]; !ok {
				return fmt.Errorf("%s: field %q references unknown enum %q", scope, f.Name, f.EnumRef)
			}
		}
	}
	return nil
}

func isValidFieldType(t storage.FieldType) bool {
	switch t {
	case storage.FieldU8, storage.FieldU16, storage.FieldU32, storage.FieldU64,
		storage.FieldI8, storage.FieldI16, storage.FieldI32, storage.FieldI64,
		storage.FieldF32, storage.FieldF64,
		storage.FieldBytesFixed, storage.FieldStringFixed,
		storage.FieldStringLPU8, storage.FieldStringLPU16,
		storage.FieldBytesLPU8, storage.FieldBytesLPU16,
		storage.FieldRemaining, storage.FieldDispatch,
		storage.FieldBytesComp:
		return true
	}
	return false
}

// handlePacketDecodedCustom decodes a captured packet using a user-defined
// protocol. URL: /api/packets/decoded-custom?packet_id=N[&protocol_id=P]
//
// If protocol_id is omitted, the protocol bound to the packet's service is
// used. If neither is set, returns 400 — the frontend should not call this
// endpoint without a usable source.
func (s *Server) handlePacketDecodedCustom(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	pidStr := r.URL.Query().Get("packet_id")
	if pidStr == "" {
		http.Error(w, "missing packet_id", http.StatusBadRequest)
		return
	}
	pid, err := strconv.ParseInt(pidStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid packet_id", http.StatusBadRequest)
		return
	}
	pkt, err := s.packetStore.GetPacketByID(pid)
	if err != nil {
		// Saved-flow snapshot fallback (see proto_decode_handler.go).
		if snap, snapErr := s.packetStore.GetPacketByIDFromSnapshots(pid); snapErr == nil {
			pkt = snap
		} else {
			http.Error(w, "packet not found", http.StatusNotFound)
			return
		}
	}

	protoID := r.URL.Query().Get("protocol_id")
	if protoID == "" {
		svc, ok := s.store.GetService(pkt.ServiceID)
		if !ok {
			http.Error(w, "service for packet not found", http.StatusNotFound)
			return
		}
		protoID = svc.ProtocolID
	}
	if protoID == "" {
		http.Error(w, "no protocol bound to this service and none specified", http.StatusBadRequest)
		return
	}
	proto, ok := s.store.GetProtocol(protoID)
	if !ok {
		http.Error(w, "protocol not found", http.StatusNotFound)
		return
	}
	result := customdecode.Decode(proto, string(pkt.Direction), pkt.Body)
	writeJSON(w, http.StatusOK, result)
}
