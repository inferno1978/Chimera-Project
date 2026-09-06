package config

import (
	"os"
	"path/filepath"
	"testing"
)

func newTestAsnStore(t *testing.T) *AsnStore {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	return NewAsnStore(configPath)
}

func TestAsnStore_SetAndGetAll(t *testing.T) {
	s := newTestAsnStore(t)

	info := &AsnInfo{
		ID:       "13335",
		Name:     "AS13335 Cloudflare",
		Prefixes: []string{"1.1.1.0/24", "1.0.0.0/24"},
	}
	if err := s.Set(info); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	all := s.GetAll()
	if len(all) != 1 {
		t.Fatalf("expected 1 ASN, got %d", len(all))
	}
	got := all["13335"]
	if got == nil {
		t.Fatal("expected ASN 13335 in results")
	}
	if got.Name != "AS13335 Cloudflare" {
		t.Errorf("expected name 'AS13335 Cloudflare', got '%s'", got.Name)
	}
	if len(got.Prefixes) != 2 {
		t.Errorf("expected 2 prefixes, got %d", len(got.Prefixes))
	}
}

func TestAsnStore_FindByIP(t *testing.T) {
	s := newTestAsnStore(t)

	s.Set(&AsnInfo{
		ID:       "13335",
		Name:     "Cloudflare",
		Prefixes: []string{"1.1.1.0/24", "104.16.0.0/12"},
	})
	s.Set(&AsnInfo{
		ID:       "15169",
		Name:     "Google",
		Prefixes: []string{"8.8.8.0/24"},
	})

	tests := []struct {
		ip       string
		wantName string
		wantNil  bool
	}{
		{"1.1.1.1", "Cloudflare", false},
		{"104.16.5.100", "Cloudflare", false},
		{"8.8.8.8", "Google", false},
		{"192.168.1.1", "", true},
		{"1.1.1.1:443", "Cloudflare", false},
		{"[1.1.1.1]", "Cloudflare", false},
		{"invalid", "", true},
	}

	for _, tt := range tests {
		result := s.FindByIP(tt.ip)
		if tt.wantNil {
			if result != nil {
				t.Errorf("FindByIP(%q) = %v, want nil", tt.ip, result)
			}
			continue
		}
		if result == nil {
			t.Errorf("FindByIP(%q) = nil, want %q", tt.ip, tt.wantName)
			continue
		}
		if result.Name != tt.wantName {
			t.Errorf("FindByIP(%q).Name = %q, want %q", tt.ip, result.Name, tt.wantName)
		}
	}
}

func TestAsnStore_Delete(t *testing.T) {
	s := newTestAsnStore(t)

	s.Set(&AsnInfo{ID: "13335", Name: "Cloudflare", Prefixes: []string{"1.1.1.0/24"}})
	s.Set(&AsnInfo{ID: "15169", Name: "Google", Prefixes: []string{"8.8.8.0/24"}})

	if err := s.Delete("13335"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	all := s.GetAll()
	if len(all) != 1 {
		t.Fatalf("expected 1 ASN after delete, got %d", len(all))
	}
	if all["15169"] == nil {
		t.Error("expected Google ASN to remain")
	}
	if s.FindByIP("1.1.1.1") != nil {
		t.Error("expected nil for deleted ASN IP")
	}
}

func TestAsnStore_Persistence(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")

	s1 := NewAsnStore(configPath)
	s1.Set(&AsnInfo{ID: "13335", Name: "Cloudflare", Prefixes: []string{"1.1.1.0/24"}})

	s2 := NewAsnStore(configPath)
	all := s2.GetAll()
	if len(all) != 1 {
		t.Fatalf("expected 1 ASN after reload, got %d", len(all))
	}
	if all["13335"] == nil || all["13335"].Name != "Cloudflare" {
		t.Error("expected Cloudflare ASN after reload")
	}
}

func TestAsnStore_GetAllReturnsCopy(t *testing.T) {
	s := newTestAsnStore(t)
	s.Set(&AsnInfo{ID: "1", Name: "Test", Prefixes: []string{"10.0.0.0/8"}})

	all := s.GetAll()
	all["1"].Name = "Modified"

	fresh := s.GetAll()
	if fresh["1"].Name != "Test" {
		t.Error("GetAll should return a copy, not a reference")
	}
}

func TestAsnStore_FindByIPReturnsCopy(t *testing.T) {
	s := newTestAsnStore(t)
	s.Set(&AsnInfo{ID: "1", Name: "Test", Prefixes: []string{"10.0.0.0/8"}})

	result := s.FindByIP("10.0.0.1")
	result.Name = "Modified"

	result2 := s.FindByIP("10.0.0.1")
	if result2.Name != "Test" {
		t.Error("FindByIP should return a copy, not a reference")
	}
}

func TestAsnStore_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")

	s := NewAsnStore(configPath)
	all := s.GetAll()
	if len(all) != 0 {
		t.Errorf("expected empty store, got %d entries", len(all))
	}

	if result := s.FindByIP("1.1.1.1"); result != nil {
		t.Error("expected nil for empty store")
	}
}

func TestAsnStore_CorruptFile(t *testing.T) {
	dir := t.TempDir()
	asnPath := filepath.Join(dir, "asn_cache.json")
	os.WriteFile(asnPath, []byte("{invalid json"), 0644)

	configPath := filepath.Join(dir, "config.json")
	s := NewAsnStore(configPath)

	all := s.GetAll()
	if len(all) != 0 {
		t.Errorf("expected empty store after corrupt file, got %d entries", len(all))
	}
}
