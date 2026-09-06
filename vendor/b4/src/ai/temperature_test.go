package ai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/daniellavrushin/b4/config"
)

func TestTemperatureRejectedDetector(t *testing.T) {
	yes := []string{
		`{"error":{"message":"` + "`temperature`" + ` is deprecated for this model."}}`,
		`{"error":{"message":"Unsupported value: 'temperature' does not support 0.2 with this model."}}`,
		`temperature is not supported`,
	}
	no := []string{
		`{"error":{"message":"invalid model"}}`,
		`{"error":{"message":"deprecated endpoint"}}`,
		`{"error":{"message":"unsupported region"}}`,
	}
	for _, b := range yes {
		if !temperatureRejected(b) {
			t.Errorf("expected match: %s", b)
		}
	}
	for _, b := range no {
		if temperatureRejected(b) {
			t.Errorf("expected no match: %s", b)
		}
	}
}

func TestAnthropicTemperatureRetry(t *testing.T) {
	var attempt atomic.Int32
	captured := make([]anthropicRequest, 0, 2)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var req anthropicRequest
		_ = json.Unmarshal(raw, &req)
		captured = append(captured, req)

		if attempt.Add(1) == 1 {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"type":"error","error":{"type":"invalid_request_error","message":"`+"`temperature`"+` is deprecated for this model."}}`)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, strings.Join([]string{
			`event: message_start`,
			`data: {"type":"message_start","message":{"usage":{"input_tokens":5,"output_tokens":0}}}`,
			``,
			`event: content_block_delta`,
			`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"ok"}}`,
			``,
			`event: message_stop`,
			`data: {"type":"message_stop"}`,
			``,
			``,
		}, "\n"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	m := NewManager(config.AIConfig{
		Enabled: true, Provider: ProviderAnthropic, Model: "claude-opus-4-7", Endpoint: srv.URL,
	}, filepath.Join(dir, "config.json"))
	m.Secrets().Set("anthropic", "ant-x")

	p, err := m.Provider()
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	ch, err := p.Stream(context.Background(), Request{
		System:      "you are b4",
		Messages:    []Message{{Role: RoleUser, Content: "hi"}},
		Temperature: 0.2,
	})
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	var text strings.Builder
	for c := range ch {
		if c.Err != nil {
			t.Fatalf("chunk err: %v", c.Err)
		}
		text.WriteString(c.Delta)
	}
	if got := text.String(); got != "ok" {
		t.Fatalf("text = %q", got)
	}
	if attempt.Load() != 2 {
		t.Fatalf("expected 2 attempts, got %d", attempt.Load())
	}
	if len(captured) != 2 {
		t.Fatalf("captured %d", len(captured))
	}
	if captured[0].Temperature == nil {
		t.Fatal("first attempt should have included temperature")
	}
	if captured[1].Temperature != nil {
		t.Fatalf("retry should omit temperature, got %v", *captured[1].Temperature)
	}
}

func TestOpenAITemperatureRetry(t *testing.T) {
	var attempt atomic.Int32
	captured := make([]openAIRequest, 0, 2)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var req openAIRequest
		_ = json.Unmarshal(raw, &req)
		captured = append(captured, req)

		if attempt.Add(1) == 1 {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":{"message":"Unsupported value: 'temperature' does not support 0.2 with this model. Only the default (1) value is supported."}}`)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, strings.Join([]string{
			`data: {"choices":[{"delta":{"content":"ok"}}]}`,
			``,
			`data: {"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":1}}`,
			``,
			`data: [DONE]`,
			``,
			``,
		}, "\n"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	m := NewManager(config.AIConfig{
		Enabled: true, Provider: ProviderOpenAI, Model: "o3-mini", Endpoint: srv.URL,
	}, filepath.Join(dir, "config.json"))
	m.Secrets().Set("openai", "sk-x")

	p, err := m.Provider()
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	ch, err := p.Stream(context.Background(), Request{
		Messages:    []Message{{Role: RoleUser, Content: "hi"}},
		Temperature: 0.2,
	})
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	var text strings.Builder
	for c := range ch {
		if c.Err != nil {
			t.Fatalf("chunk err: %v", c.Err)
		}
		text.WriteString(c.Delta)
	}
	if got := text.String(); got != "ok" {
		t.Fatalf("text = %q", got)
	}
	if attempt.Load() != 2 {
		t.Fatalf("expected 2 attempts, got %d", attempt.Load())
	}
	if captured[0].Temperature == nil {
		t.Fatal("first attempt should have included temperature")
	}
	if captured[1].Temperature != nil {
		t.Fatalf("retry should omit temperature, got %v", *captured[1].Temperature)
	}
}

func TestNonTemperatureErrorDoesNotRetry(t *testing.T) {
	var attempt atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":{"message":"invalid model"}}`)
	}))
	defer srv.Close()

	dir := t.TempDir()
	m := NewManager(config.AIConfig{
		Enabled: true, Provider: ProviderAnthropic, Model: "bogus", Endpoint: srv.URL,
	}, filepath.Join(dir, "config.json"))
	m.Secrets().Set("anthropic", "ant-x")

	p, _ := m.Provider()
	_, err := p.Stream(context.Background(), Request{
		Messages: []Message{{Role: RoleUser, Content: "hi"}},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if attempt.Load() != 1 {
		t.Fatalf("expected 1 attempt, got %d", attempt.Load())
	}
}
