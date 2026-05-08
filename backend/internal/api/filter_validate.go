package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/SimoneErrigo/Janus/backend/internal/filter"
)

// validateFilterRequest is the JSON body shape for POST /api/filter/validate.
type validateFilterRequest struct {
	Expression string `json:"expression"`
}

// validateFilterResponse is the JSON response shape.
// On success: { ok: true }
// On parse error: { ok: false, error: "...", position: N }
type validateFilterResponse struct {
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	Position int    `json:"position,omitempty"`
}

// handleFilterValidate parses the supplied expression and reports any syntax
// error with a byte position so the frontend can underline the offending token.
// Compilation (field/op/value validation) is also run so semantic errors are
// surfaced — same code path that the rules engine and packet query will use.
func (s *Server) handleFilterValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req validateFilterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := filter.Compile(req.Expression); err != nil {
		resp := validateFilterResponse{OK: false, Error: err.Error()}
		var se *filter.SyntaxError
		if errors.As(err, &se) {
			resp.Position = se.Pos
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}
	writeJSON(w, http.StatusOK, validateFilterResponse{OK: true})
}
