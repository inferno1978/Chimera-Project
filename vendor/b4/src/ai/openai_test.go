package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daniellavrushin/b4/config"
)

func newOpenAITestServer(t *testing.T, body string, status int, captured *openAIRequest) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer sk-test" {
			t.Errorf("auth header: %q", got)
		}
		if captured != nil {
			raw, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(raw, captured); err != nil {
				t.Errorf("decode req: %v", err)
			}
		}
		w.Header().Set("Content-Type", "text/event-stream")
		if status != 0 {
			w.WriteHeader(status)
		}
		_, _ = io.WriteString(w, body)
	}))
}

func TestOpenAIStreamHappyPath(t *testing.T) {
	stream := strings.Join([]string{
		`data: {"choices":[{"delta":{"content":"Hel"}}]}`,
		``,
		`data: {"choices":[{"delta":{"content":"lo"}}]}`,
		``,
		`data: {"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":12,"completion_tokens":3}}`,
		``,
		`data: [DONE]`,
		``,
		``,
	}, "\n")

	var captured openAIRequest
	srv := newOpenAITestServer(t, stream, 0, &captured)
	defer srv.Close()

	dir := t.TempDir()
	m := NewManager(config.AIConfig{
		Enabled:  true,
		Provider: ProviderOpenAI,
		Model:    "gpt-4o-mini",
		Endpoint: srv.URL,
	}, filepath.Join(dir, "config.json"))
	if err := m.Secrets().Set("openai", "sk-test"); err != nil {
		t.Fatalf("set secret: %v", err)
	}

	p, err := m.Provider()
	if err != nil {
		t.Fatalf("provider: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch, err := p.Stream(ctx, Request{
		System: "you are b4",
		Messages: []Message{
			{Role: RoleUser, Content: "hi"},
		},
	})
	if err != nil {
		t.Fatalf("stream: %v", err)
	}

	var text strings.Builder
	var usage *Usage
	var done bool
	for c := range ch {
		if c.Err != nil {
			t.Fatalf("chunk err: %v", c.Err)
		}
		text.WriteString(c.Delta)
		if c.Usage != nil {
			usage = c.Usage
		}
		if c.Done {
			done = true
		}
	}

	if got := text.String(); got != "Hello" {
		t.Fatalf("text = %q, want Hello", got)
	}
	if !done {
		t.Fatal("expected done chunk")
	}
	if usage == nil || usage.InputTokens != 12 || usage.OutputTokens != 3 {
		t.Fatalf("usage = %+v", usage)
	}
	if captured.Model != "gpt-4o-mini" {
		t.Fatalf("model = %q", captured.Model)
	}
	if !captured.Stream {
		t.Fatal("stream not set")
	}
	if len(captured.Messages) != 2 || captured.Messages[0].Role != "system" || captured.Messages[0].Content != "you are b4" {
		t.Fatalf("messages = %+v", captured.Messages)
	}
	if captured.Messages[1].Role != "user" || captured.Messages[1].Content != "hi" {
		t.Fatalf("user message = %+v", captured.Messages[1])
	}
}

func TestOpenAIErrorResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":{"message":"bad key"}}`)
	}))
	defer srv.Close()

	dir := t.TempDir()
	m := NewManager(config.AIConfig{
		Enabled:  true,
		Provider: ProviderOpenAI,
		Model:    "gpt-4o-mini",
		Endpoint: srv.URL,
	}, filepath.Join(dir, "config.json"))
	m.Secrets().Set("openai", "sk-test")

	p, _ := m.Provider()
	_, err := p.Stream(context.Background(), Request{Messages: []Message{{Role: RoleUser, Content: "x"}}})
	if err == nil {
		t.Fatal("expected error on 401")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Fatalf("error should mention 401: %v", err)
	}
}
