package handler

import (
	"net/http/httptest"
	"testing"
)

func TestSetJsonHeader(t *testing.T) {
	rec := httptest.NewRecorder()
	setJsonHeader(rec)

	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json; charset=utf-8" {
		t.Errorf("expected 'application/json; charset=utf-8', got %q", contentType)
	}
}

func TestSendResponse(t *testing.T) {
	rec := httptest.NewRecorder()

	data := map[string]string{"key": "value"}
	sendResponse(rec, data)

	if rec.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Error("Content-Type not set")
	}

	body := rec.Body.String()
	if body == "" {
		t.Error("response body is empty")
	}
}
