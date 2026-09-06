package ai

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/daniellavrushin/b4/config"
)

func TestOpenAIListModelsFiltersAndDecodes(t *testing.T) {
	body := `{"object":"list","data":[
		{"id":"gpt-4o-mini","created":1700000000,"object":"model"},
		{"id":"gpt-4o","created":1700000001,"object":"model"},
		{"id":"o3-mini","created":1700000002,"object":"model"},
		{"id":"text-embedding-3-large","created":1700000003,"object":"model"},
		{"id":"whisper-1","created":1700000004,"object":"model"},
		{"id":"dall-e-3","created":1700000005,"object":"model"}
	]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/models" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer sk-x" {
			t.Errorf("auth header missing")
		}
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()

	dir := t.TempDir()
	m := NewManager(config.AIConfig{
		Enabled: true, Provider: ProviderOpenAI, Model: "gpt-4o-mini", Endpoint: srv.URL,
	}, filepath.Join(dir, "config.json"))
	m.Secrets().Set("openai", "sk-x")

	p, err := m.Provider()
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	models, err := p.ListModels(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	want := map[string]bool{"gpt-4o-mini": true, "gpt-4o": true, "o3-mini": true}
	if len(models) != len(want) {
		t.Fatalf("got %d models, want %d: %+v", len(models), len(want), models)
	}
	for _, m := range models {
		if !want[m.ID] {
			t.Errorf("unexpected model %q", m.ID)
		}
	}
}

func TestAnthropicListModels(t *testing.T) {
	body := `{"data":[
		{"id":"claude-haiku-4-5","display_name":"Claude Haiku 4.5","created_at":"2026-02-04T00:00:00Z"},
		{"id":"claude-sonnet-4-6","display_name":"Claude Sonnet 4.6","created_at":"2026-02-10T00:00:00Z"}
	],"has_more":false}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/models" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.URL.Query().Get("limit") != "100" {
			t.Errorf("limit = %s", r.URL.Query().Get("limit"))
		}
		if r.Header.Get("x-api-key") != "ant-x" {
			t.Errorf("missing x-api-key")
		}
		if r.Header.Get("anthropic-version") != anthropicAPIVersion {
			t.Errorf("missing version")
		}
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()

	dir := t.TempDir()
	m := NewManager(config.AIConfig{
		Enabled: true, Provider: ProviderAnthropic, Model: "claude-haiku-4-5", Endpoint: srv.URL,
	}, filepath.Join(dir, "config.json"))
	m.Secrets().Set("anthropic", "ant-x")

	p, err := m.Provider()
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	models, err := p.ListModels(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(models) != 2 {
		t.Fatalf("got %d models", len(models))
	}
	if models[0].DisplayName != "Claude Haiku 4.5" || models[0].Created == 0 {
		t.Fatalf("model[0] = %+v", models[0])
	}
}

func TestOllamaListModels(t *testing.T) {
	body := `{"models":[
		{"name":"llama3:latest","model":"llama3:latest","modified_at":"2026-01-01T00:00:00Z"},
		{"name":"mistral:7b","model":"mistral:7b","modified_at":"2026-01-02T00:00:00Z"}
	]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/tags" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()

	dir := t.TempDir()
	m := NewManager(config.AIConfig{
		Enabled: true, Provider: ProviderOllama, Model: "llama3", Endpoint: srv.URL,
	}, filepath.Join(dir, "config.json"))

	p, err := m.Provider()
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	models, err := p.ListModels(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(models) != 2 || models[0].ID != "llama3:latest" {
		t.Fatalf("got %+v", models)
	}
}

func TestProviderForOverride(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(config.AIConfig{
		Enabled: true, Provider: ProviderOllama, Model: "llama3", Endpoint: "http://saved",
	}, filepath.Join(dir, "config.json"))
	m.Secrets().Set("openai", "sk-y")

	p, err := m.ProviderFor(ProviderOpenAI, "https://custom-openai.example/v1", "")
	if err != nil {
		t.Fatalf("ProviderFor: %v", err)
	}
	if p.Name() != ProviderOpenAI {
		t.Fatalf("name = %s", p.Name())
	}
}

func TestIsOpenAIChatModel(t *testing.T) {
	yes := []string{"gpt-4o", "gpt-4o-mini", "gpt-3.5-turbo", "chatgpt-4o-latest", "o1-preview", "o3-mini", "o4-mini"}
	no := []string{"", "text-embedding-3-large", "whisper-1", "dall-e-3", "tts-1", "babbage-002"}
	for _, id := range yes {
		if !isOpenAIChatModel(id) {
			t.Errorf("expected chat model: %s", id)
		}
	}
	for _, id := range no {
		if isOpenAIChatModel(id) {
			t.Errorf("expected non-chat model: %s", id)
		}
	}
}
