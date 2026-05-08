package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleFilterValidate_OK(t *testing.T) {
	s := &Server{}
	body := strings.NewReader(`{"expression":"body contains \"pippo\" AND status == 200"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/filter/validate", body)
	rec := httptest.NewRecorder()
	s.handleFilterValidate(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp validateFilterResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.OK {
		t.Fatalf("expected OK, got %+v", resp)
	}
}

func TestHandleFilterValidate_SyntaxError(t *testing.T) {
	s := &Server{}
	body := strings.NewReader(`{"expression":"body contains"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/filter/validate", body)
	rec := httptest.NewRecorder()
	s.handleFilterValidate(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp validateFilterResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.OK {
		t.Fatalf("expected !OK, got %+v", resp)
	}
	if resp.Error == "" {
		t.Fatalf("expected error message, got empty")
	}
}

func TestHandleFilterValidate_SemanticError(t *testing.T) {
	s := &Server{}
	body := strings.NewReader(`{"expression":"unknown_field == 1"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/filter/validate", body)
	rec := httptest.NewRecorder()
	s.handleFilterValidate(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp validateFilterResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.OK {
		t.Fatalf("expected !OK for unknown field")
	}
}

func TestHandleFilterValidate_Empty(t *testing.T) {
	s := &Server{}
	body := strings.NewReader(`{"expression":""}`)
	req := httptest.NewRequest(http.MethodPost, "/api/filter/validate", body)
	rec := httptest.NewRecorder()
	s.handleFilterValidate(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	var resp validateFilterResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.OK {
		t.Fatalf("empty expression should be valid (match-all)")
	}
}
