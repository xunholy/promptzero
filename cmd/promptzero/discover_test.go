package main

import (
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/flipper/transport"
)

// TestPickFlipperCandidate_PrefersExactUnholyName confirms the
// repo-pet-name shortcut: a device literally named "Unholy" wins
// over anything else, even higher RSSI.
func TestPickFlipperCandidate_PrefersExactUnholyName(t *testing.T) {
	devices := []transport.DiscoveredDevice{
		{Name: "Some Random BLE Speaker", Address: "AA:BB", RSSI: -40},
		{Name: "Unholy", Address: "CC:DD", RSSI: -80},
		{Name: "Flipper Bob", Address: "EE:FF", RSSI: -50},
	}
	got := pickFlipperCandidate(devices)
	if got.Name != "Unholy" {
		t.Errorf("got %q, want exact Unholy match", got.Name)
	}
}

// TestPickFlipperCandidate_FallsBackToFlipperSubstring ensures the
// case-insensitive "Flipper" substring is honoured when no exact
// Unholy peer is present. Flipper-named devices typically have the
// "Flipper Foo" pattern; we shouldn't require an exact match.
func TestPickFlipperCandidate_FallsBackToFlipperSubstring(t *testing.T) {
	devices := []transport.DiscoveredDevice{
		{Name: "AirPods", Address: "AA:BB", RSSI: -40},
		{Name: "flipper bob", Address: "CC:DD", RSSI: -55}, // lowercase
		{Name: "Other", Address: "EE:FF", RSSI: -30},
	}
	got := pickFlipperCandidate(devices)
	if got.Address != "CC:DD" {
		t.Errorf("got %q (name=%q), want lowercase 'flipper bob' to match", got.Address, got.Name)
	}
}

// TestPickFlipperCandidate_FallsBackToFirstWhenNoMatch confirms the
// strongest-RSSI fallback. The caller pre-sorts by RSSI; this
// function only steps in when nothing's named like a Flipper.
func TestPickFlipperCandidate_FallsBackToFirstWhenNoMatch(t *testing.T) {
	devices := []transport.DiscoveredDevice{
		{Name: "Strongest", Address: "AA:BB", RSSI: -30},
		{Name: "Weaker", Address: "CC:DD", RSSI: -70},
	}
	got := pickFlipperCandidate(devices)
	if got.Name != "Strongest" {
		t.Errorf("got %q, want Strongest (first when no name match)", got.Name)
	}
}

// TestContainsFold covers the case-insensitive substring helper. The
// hand-rolled implementation in discover.go avoids importing strings;
// we still pin its semantics so a future swap to strings.Contains
// (lowercased) doesn't change behaviour.
func TestContainsFold(t *testing.T) {
	cases := []struct {
		s, sub string
		want   bool
	}{
		{"Flipper Bob", "flipper", true},
		{"flipper", "FLIPPER", true},
		{"foo", "bar", false},
		{"", "anything", false}, // sub longer than s returns false
		{"anything", "", true},  // empty sub matches anything (stdlib parity)
		{"abc", "abc", true},    // exact match
		{"abc", "abcd", false},  // sub longer than s
		{"FLIPPER ZERO", "ZERO", true},
		{"hello", "ell", true},
	}
	for _, c := range cases {
		got := containsFold(c.s, c.sub)
		if got != c.want {
			t.Errorf("containsFold(%q, %q) = %v, want %v", c.s, c.sub, got, c.want)
		}
	}
}

// TestToLower covers the ASCII-only lowercase helper. Pin behaviour
// for non-ASCII bytes since the implementation only handles A-Z.
func TestToLower(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"FLIPPER", "flipper"},
		{"Flipper Zero", "flipper zero"},
		{"already-lower", "already-lower"},
		{"", ""},
		{"123ABC", "123abc"},
		{"Mix3D-c4se", "mix3d-c4se"},
		// Non-ASCII passes through verbatim — documents the limitation.
		{"ÀBC", "Àbc"},
	}
	for _, c := range cases {
		got := toLower(c.in)
		if got != c.want {
			t.Errorf("toLower(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestTruncate covers the table-rendering width helper. Edge cases:
// short strings pass through, long strings get an ellipsis suffix,
// n<=1 falls back to a hard slice (no room for the ellipsis).
func TestTruncate(t *testing.T) {
	cases := []struct {
		in   string
		n    int
		want string
	}{
		{"short", 10, "short"},
		{"exactly10c", 10, "exactly10c"},
		{"this-is-too-long", 8, "this-is…"},
		{"abc", 3, "abc"},
		// n<=1 returns the raw prefix without ellipsis.
		{"abcdef", 1, "a"},
		{"abcdef", 0, ""},
	}
	for _, c := range cases {
		got := truncate(c.in, c.n)
		if got != c.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
		}
	}
}

// TestDivider confirms the table separator helper renders n hyphens.
func TestDivider(t *testing.T) {
	got := divider(5)
	if got != "-----" {
		t.Errorf("divider(5) = %q, want '-----'", got)
	}
	if divider(0) != "" {
		t.Errorf("divider(0) should be empty, got %q", divider(0))
	}
	// Width matches input.
	if w := strings.Count(divider(42), "-"); w != 42 {
		t.Errorf("divider(42) had %d hyphens, want 42", w)
	}
}
