package ai

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/daniellavrushin/b4/config"
)

func TestManagerProviderSelection(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")

	cases := []struct {
		name      string
		cfg       config.AIConfig
		secretRef string
		secretKey string
		wantErr   error
		wantName  string
	}{
		{
			name:    "disabled",
			cfg:     config.AIConfig{Enabled: false},
			wantErr: ErrDisabled,
		},
		{
			name:    "no provider",
			cfg:     config.AIConfig{Enabled: true},
			wantErr: ErrNoProvider,
		},
		{
			name:    "no model",
			cfg:     config.AIConfig{Enabled: true, Provider: ProviderOpenAI},
			wantErr: ErrNoModel,
		},
		{
			name:    "openai missing key",
			cfg:     config.AIConfig{Enabled: true, Provider: ProviderOpenAI, Model: "gpt-4o-mini"},
			wantErr: ErrMissingAPIKey,
		},
		{
			name:      "openai ok",
			cfg:       config.AIConfig{Enabled: true, Provider: ProviderOpenAI, Model: "gpt-4o-mini"},
			secretRef: "openai",
			secretKey: "sk-x",
			wantName:  ProviderOpenAI,
		},
		{
			name:      "anthropic ok",
			cfg:       config.AIConfig{Enabled: true, Provider: ProviderAnthropic, Model: "claude-haiku-4-5"},
			secretRef: "anthropic",
			secretKey: "ant-x",
			wantName:  ProviderAnthropic,
		},
		{
			name:     "ollama no key required",
			cfg:      config.AIConfig{Enabled: true, Provider: ProviderOllama, Model: "llama3"},
			wantName: ProviderOllama,
		},
		{
			name:    "unknown provider",
			cfg:     config.AIConfig{Enabled: true, Provider: "wat", Model: "x"},
			wantErr: ErrUnknownProvider,
		},
		{
			name:      "custom apikeyref",
			cfg:       config.AIConfig{Enabled: true, Provider: ProviderOpenAI, Model: "gpt-4o-mini", APIKeyRef: "openai-work"},
			secretRef: "openai-work",
			secretKey: "sk-y",
			wantName:  ProviderOpenAI,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewManager(tc.cfg, cfgPath)
			if tc.secretRef != "" {
				if err := m.Secrets().Set(tc.secretRef, tc.secretKey); err != nil {
					t.Fatalf("seed secret: %v", err)
				}
				defer m.Secrets().Delete(tc.secretRef)
			}

			p, err := m.Provider()
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("want err %v, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if p.Name() != tc.wantName {
				t.Fatalf("want provider %q, got %q", tc.wantName, p.Name())
			}
		})
	}
}

func TestManagerUpdate(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	m := NewManager(config.AIConfig{Enabled: false, TimeoutSec: 30}, cfgPath)

	if _, err := m.Provider(); !errors.Is(err, ErrDisabled) {
		t.Fatalf("want ErrDisabled, got %v", err)
	}

	m.Update(config.AIConfig{Enabled: true, Provider: ProviderOllama, Model: "llama3", TimeoutSec: 60})
	p, err := m.Provider()
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if p.Name() != ProviderOllama {
		t.Fatalf("want ollama, got %s", p.Name())
	}
}
