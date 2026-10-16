package ai

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSecretStoreRoundtrip(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")

	s := NewSecretStore(cfgPath)
	if got := s.Get("openai"); got != "" {
		t.Fatalf("expected empty key, got %q", got)
	}
	if err := s.Set("openai", "sk-test-123"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := s.Set("anthropic", "ant-key"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	st, err := os.Stat(s.Path())
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("expected mode 0600, got %v", st.Mode().Perm())
	}

	s2 := NewSecretStore(cfgPath)
	if got := s2.Get("openai"); got != "sk-test-123" {
		t.Fatalf("openai key not loaded: %q", got)
	}
	if got := s2.Get("anthropic"); got != "ant-key" {
		t.Fatalf("anthropic key not loaded: %q", got)
	}
	if !s2.Has("openai") {
		t.Fatal("Has should report true")
	}
	if got := len(s2.Refs()); got != 2 {
		t.Fatalf("expected 2 refs, got %d", got)
	}

	if err := s2.Delete("openai"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if s2.Has("openai") {
		t.Fatal("Delete failed")
	}
}

func TestSecretStoreEmptyRefIsNoop(t *testing.T) {
	dir := t.TempDir()
	s := NewSecretStore(filepath.Join(dir, "config.json"))
	if err := s.Set("", "ignored"); err != nil {
		t.Fatalf("Set empty: %v", err)
	}
	if len(s.Refs()) != 0 {
		t.Fatal("empty ref should not be stored")
	}
}
