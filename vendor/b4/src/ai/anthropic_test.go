package ai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daniellavrushin/b4/config"
)

func TestAnthropicStreamHappyPath(t *testing.T) {
	stream := strings.Join([]string{
		`event: message_start`,
		`data: {"type":"message_start","message":{"usage":{"input_tokens":15,"output_tokens":0}}}`,
		``,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hi"}}`,
		``,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"!"}}`,
		``,
		`event: message_delta`,
		`data: {"type":"message_delta","usage":{"output_tokens":2}}`,
		``,
		`event: message_stop`,
		`data: {"type":"message_stop"}`,
		``,
		``,
	}, "\n")

	var captured anthropicRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/messages" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.Header.Get("x-api-key") != "ant-test" {
			t.Errorf("missing x-api-key")
		}
		if r.Header.Get("anthropic-version") != anthropicAPIVersion {
			t.Errorf("missing version header")
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &captured)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, stream)
	}))
	defer srv.Close()

	dir := t.TempDir()
	m := NewManager(config.AIConfig{
		Enabled:  true,
		Provider: ProviderAnthropic,
		Model:    "claude-haiku-4-5",
		Endpoint: srv.URL,
	}, filepath.Join(dir, "config.json"))
	m.Secrets().Set("anthropic", "ant-test")

	p, err := m.Provider()
	if err != nil {
		t.Fatalf("provider: %v", err)
	}

	ch, err := p.Stream(context.Background(), Request{
		System:   "be terse",
		Messages: []Message{{Role: RoleUser, Content: "hi"}},
	})
	if err != nil {
		t.Fatalf("stream: %v", err)
	}

	var text strings.Builder
	var usage *Usage
	for c := range ch {
		if c.Err != nil {
			t.Fatalf("chunk err: %v", c.Err)
		}
		text.WriteString(c.Delta)
		if c.Usage != nil {
			usage = c.Usage
		}
	}

	if got := text.String(); got != "Hi!" {
		t.Fatalf("text = %q", got)
	}
	if usage == nil || usage.InputTokens != 15 || usage.OutputTokens != 2 {
		t.Fatalf("usage = %+v", usage)
	}
	if captured.System != "be terse" {
		t.Fatalf("system = %q", captured.System)
	}
	if len(captured.Messages) != 1 || captured.Messages[0].Role != "user" {
		t.Fatalf("messages = %+v", captured.Messages)
	}
	if captured.MaxTokens == 0 {
		t.Fatal("max_tokens must be set for anthropic")
	}
}
