package handler

import (
	"testing"
)

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "example.com"},
		{"EXAMPLE.COM", "example.com"},
		{"  example.com  ", "example.com"},
		{"http://example.com", "example.com"},
		{"https://example.com", "example.com"},
		{"https://example.com/path/to/page", "example.com"},
		{"example.com:8080", "example.com"},
		{"https://example.com:443/path", "example.com"},
		{"HTTP://EXAMPLE.COM/PATH", "example.com"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeDomain(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeDomain(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
