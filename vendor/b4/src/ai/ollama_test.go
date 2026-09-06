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

func TestOllamaStreamHappyPath(t *testing.T) {
	stream := strings.Join([]string{
		`{"message":{"role":"assistant","content":"He"},"done":false}`,
		`{"message":{"role":"assistant","content":"y"},"done":false}`,
		`{"message":{"role":"assistant","content":""},"done":true,"prompt_eval_count":7,"eval_count":2}`,
		``,
	}, "\n")

	var captured ollamaRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" {
			t.Errorf("path = %s", r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &captured)
		_, _ = io.WriteString(w, stream)
	}))
	defer srv.Close()

	dir := t.TempDir()
	m := NewManager(config.AIConfig{
		Enabled:  true,
		Provider: ProviderOllama,
		Model:    "llama3",
		Endpoint: srv.URL,
	}, filepath.Join(dir, "config.json"))

	p, err := m.Provider()
	if err != nil {
		t.Fatalf("provider: %v", err)
	}

	ch, err := p.Stream(context.Background(), Request{
		System:   "system",
		Messages: []Message{{Role: RoleUser, Content: "hi"}},
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

	if got := text.String(); got != "Hey" {
		t.Fatalf("text = %q", got)
	}
	if !done {
		t.Fatal("expected done")
	}
	if usage == nil || usage.InputTokens != 7 || usage.OutputTokens != 2 {
		t.Fatalf("usage = %+v", usage)
	}
	if !captured.Stream {
		t.Fatal("stream not set")
	}
	if len(captured.Messages) != 2 || captured.Messages[0].Role != "system" {
		t.Fatalf("messages = %+v", captured.Messages)
	}
}

func TestOllamaContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, _ := w.(http.Flusher)
		_, _ = io.WriteString(w, `{"message":{"role":"assistant","content":"x"},"done":false}`+"\n")
		if flusher != nil {
			flusher.Flush()
		}
		<-r.Context().Done()
	}))
	defer srv.Close()

	dir := t.TempDir()
	m := NewManager(config.AIConfig{
		Enabled:  true,
		Provider: ProviderOllama,
		Model:    "llama3",
		Endpoint: srv.URL,
	}, filepath.Join(dir, "config.json"))

	p, _ := m.Provider()
	ctx, cancel := context.WithCancel(context.Background())
	ch, err := p.Stream(ctx, Request{Messages: []Message{{Role: RoleUser, Content: "hi"}}})
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	first := <-ch
	if first.Delta != "x" {
		t.Fatalf("first delta = %q", first.Delta)
	}
	cancel()
	gotErr := false
	for c := range ch {
		if c.Err != nil {
			gotErr = true
		}
	}
	if !gotErr {
		t.Fatal("expected err on cancel")
	}
}
