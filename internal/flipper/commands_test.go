package flipper

import (
	"testing"
)

func TestParseKiBLine(t *testing.T) {
	tests := []struct {
		line      string
		wantBytes string
		wantKind  string
		wantOk    bool
	}{
		// Happy paths
		{"1024KiB total", "1048576", "total", true},
		{"512KiB free", "524288", "free", true},
		{"60194KiB total", "61638656", "total", true},
		{"42KiB free", "43008", "free", true},
		// Whitespace between number and KiB
		{"1024 KiB total", "1048576", "total", true},
		{"  512  KiB  free", "524288", "free", true},
		// Zero is valid
		{"0KiB total", "0", "total", true},
		// No "KiB" present
		{"60194MB total", "", "", false},
		{"1024 total", "", "", false},
		{"", "", "", false},
		// "KiB" at position 0 (i == 0 → i <= 0 → false)
		{"KiB total", "", "", false},
		// Trailing word is not "total" or "free"
		{"1024KiB used", "", "", false},
		{"1024KiB", "", "", false},
		{"1024KiB  ", "", "", false},
		// Non-numeric before KiB
		{"abcKiB total", "", "", false},
		// Negative numbers are rejected by ParseUint
		{"-1KiB total", "", "", false},
		// Whitespace-only before KiB → empty numStr after trim → false
		{" KiB total", "", "", false},
		{"  KiB free", "", "", false},
		// Overflow: exceeds uint64 max → ParseUint error → false
		{"99999999999999999999KiB total", "", "", false},
	}

	for _, tt := range tests {
		bytes, kind, ok := parseKiBLine(tt.line)
		if ok != tt.wantOk {
			t.Errorf("parseKiBLine(%q): ok=%v, want %v", tt.line, ok, tt.wantOk)
			continue
		}
		if !ok {
			continue
		}
		if bytes != tt.wantBytes {
			t.Errorf("parseKiBLine(%q): bytes=%q, want %q", tt.line, bytes, tt.wantBytes)
		}
		if kind != tt.wantKind {
			t.Errorf("parseKiBLine(%q): kind=%q, want %q", tt.line, kind, tt.wantKind)
		}
	}
}
