package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/log"
)

type FieldError struct {
	Path    string         `json:"path"`
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Params  map[string]any `json:"params,omitempty"`
}

type APIError struct {
	Status  int          `json:"-"`
	Code    string       `json:"code"`
	Message string       `json:"error"`
	Fields  []FieldError `json:"fields,omitempty"`
}

func (e *APIError) Error() string { return e.Message }

func ErrInvalidJSON() *APIError {
	return &APIError{Status: http.StatusBadRequest, Code: "invalid_json", Message: "Invalid JSON"}
}

func ErrBadRequest(msg string) *APIError {
	return &APIError{Status: http.StatusBadRequest, Code: "bad_request", Message: msg}
}

func ErrNotFound(msg string) *APIError {
	return &APIError{Status: http.StatusNotFound, Code: "not_found", Message: msg}
}

func ErrValidation(msg string, fields ...FieldError) *APIError {
	return &APIError{Status: http.StatusBadRequest, Code: "validation_failed", Message: msg, Fields: fields}
}

func ErrInternal(msg string) *APIError {
	return &APIError{Status: http.StatusInternalServerError, Code: "internal", Message: msg}
}

func writeAPIError(w http.ResponseWriter, err error) {
	var ae *APIError
	if errors.As(err, &ae) {
		setJsonHeader(w)
		w.WriteHeader(ae.Status)
		_ = json.NewEncoder(w).Encode(ae)
		return
	}
	var ve *config.ValidationError
	if errors.As(err, &ve) {
		writeAPIError(w, fromValidationError(ve))
		return
	}
	log.Errorf("internal API error: %v", err)
	writeAPIError(w, ErrInternal("Internal server error"))
}

func fromValidationError(ve *config.ValidationError) *APIError {
	fields := make([]FieldError, len(ve.Fields))
	for i, f := range ve.Fields {
		fields[i] = FieldError{Path: f.Path, Code: f.Code, Message: f.Message, Params: f.Params}
	}
	return ErrValidation("Configuration is invalid", fields...)
}
