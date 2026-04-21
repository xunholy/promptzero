package main

import "testing"

func TestIsSafeReportID(t *testing.T) {
	safe := []string{
		"abc123",
		"2026-04-22T10-00",
		"my_session",
		"deadbeefdeadbeef",
		"CamelCaseName",
	}
	for _, s := range safe {
		if !isSafeReportID(s) {
			t.Errorf("isSafeReportID(%q) = false, want true", s)
		}
	}

	unsafe := []string{
		"",              // empty
		"..",            // dot-segment
		".",             // single dot
		"../etc/passwd", // path traversal
		"abc/def",       // slash
		"abc\\def",      // backslash (Windows)
		"session\x00id", // NUL byte
		"sess name",     // space
		"a..b",          // embedded dot-dot
		"/absolute",     // absolute-path attempt
		"with.dot",      // filename extension shouldn't be in the id
	}
	for _, s := range unsafe {
		if isSafeReportID(s) {
			t.Errorf("isSafeReportID(%q) = true, want false", s)
		}
	}
}
