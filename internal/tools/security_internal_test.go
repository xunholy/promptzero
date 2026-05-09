package tools

import (
	"sort"
	"strings"
	"testing"
)

// TestParsePorts_SingleNumeric covers the simplest form: "80" → [80].
func TestParsePorts_SingleNumeric(t *testing.T) {
	got, err := parsePorts("80")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(got) != 1 || got[0] != 80 {
		t.Errorf("parsePorts(80) = %v, want [80]", got)
	}
}

// TestParsePorts_CommaList exercises the comma-separated form,
// including dedup of repeated values.
func TestParsePorts_CommaList(t *testing.T) {
	got, err := parsePorts("22,80,443,80")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	want := []int{22, 80, 443}
	if len(got) != len(want) {
		t.Fatalf("dedup failed: got %v, want %v", got, want)
	}
	for i, p := range want {
		if got[i] != p {
			t.Errorf("got[%d] = %d, want %d", i, got[i], p)
		}
	}
}

// TestParsePorts_Range covers the lo-hi range form and confirms the
// sorted ascending output contract.
func TestParsePorts_Range(t *testing.T) {
	got, err := parsePorts("100-105")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	want := []int{100, 101, 102, 103, 104, 105}
	if len(got) != len(want) {
		t.Fatalf("got = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %d, want %d", i, got[i], want[i])
		}
	}
}

// TestParsePorts_Mixed combines comma and range with overlap,
// asserting dedup + sort.
func TestParsePorts_Mixed(t *testing.T) {
	got, err := parsePorts(" 80, 100-102 , 81 ")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	want := []int{80, 81, 100, 101, 102}
	if len(got) != len(want) {
		t.Fatalf("got = %v, want %v", got, want)
	}
	if !sort.IntsAreSorted(got) {
		t.Errorf("output not sorted: %v", got)
	}
}

// TestParsePorts_Top1000Alias confirms the case-insensitive
// well-known alias maps to the embedded list.
func TestParsePorts_Top1000Alias(t *testing.T) {
	got, err := parsePorts("TOP1000")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(got) != len(top1000Ports) {
		t.Errorf("len(got) = %d, want len(top1000Ports) = %d", len(got), len(top1000Ports))
	}
}

// TestParsePorts_RejectsBoundaryViolations covers each error path:
// out-of-range, inverted range, non-numeric, empty, and both bounds
// at the extremes.
func TestParsePorts_RejectsBoundaryViolations(t *testing.T) {
	cases := []struct {
		in   string
		want string // error must contain this substring
	}{
		{"0", "invalid port"},               // < 1
		{"65536", "invalid port"},           // > 65535
		{"abc", "invalid port"},             // non-numeric
		{"100-50", "invalid port range"},    // inverted
		{"0-100", "invalid port range"},     // lo < 1
		{"100-70000", "invalid port range"}, // hi > 65535
		{"80,abc", "invalid port"},          // bad token mid-list
	}
	for _, c := range cases {
		_, err := parsePorts(c.in)
		if err == nil {
			t.Errorf("parsePorts(%q) returned nil error, want error containing %q", c.in, c.want)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("parsePorts(%q) error = %q, want it to contain %q", c.in, err.Error(), c.want)
		}
	}
}

// FuzzParsePorts is a no-panic + structural-invariant guarantee:
// any input either errors (with caps==nil) or returns a sorted,
// deduplicated, in-range port list. parsePorts is the LLM-supplied-
// argument parser for port_scan_tcp; an attacker-shaped input
// must not crash the tool.
//
// Run with `go test -fuzz=FuzzParsePorts ./internal/tools/`.
func FuzzParsePorts(f *testing.F) {
	for _, seed := range []string{
		"",
		"top1000",
		"80",
		"22,80,443",
		"100-200",
		"1-65535",
		"-",
		",,,",
		"0",
		"65536",
		"100-50",
		"abc",
		"80, 81, 82",
		strings.Repeat("80,", 1000), // huge dedup
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, err := parsePorts(s)
		if err != nil {
			if got != nil {
				t.Errorf("parsePorts(%q) returned err %v + non-nil ports %v", s, err, got)
			}
			return
		}
		// Success path invariants.
		if !sort.IntsAreSorted(got) {
			t.Errorf("parsePorts(%q) returned unsorted: %v", s, got)
		}
		seen := make(map[int]bool, len(got))
		for _, p := range got {
			if p < 1 || p > 65535 {
				t.Errorf("parsePorts(%q) returned out-of-range port %d", s, p)
			}
			if seen[p] {
				t.Errorf("parsePorts(%q) returned duplicate port %d", s, p)
			}
			seen[p] = true
		}
	})
}
