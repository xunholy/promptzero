package defense

import "testing"

// TestLookupOUI_KnownPrefixes confirms the curated table actually
// resolves the SoC families it claims to. Adding a new OUI to the
// ouiTable should add a case here so the description string stays
// linked to the prefix.
func TestLookupOUI_KnownPrefixes(t *testing.T) {
	cases := []struct {
		mac, family string
	}{
		// Espressif — full MAC with colons (canonical form).
		{"94:B9:7E:01:23:45", "Espressif"},
		// Nordic — dash-separated.
		{"D0-40-D0-AA-BB-CC", "Nordic Semiconductor"},
		// Lower-case + no separator.
		{"e0e5cffedcba", "Texas Instruments"},
	}
	for _, c := range cases {
		got := LookupOUI(c.mac)
		if got == "" {
			t.Errorf("LookupOUI(%q) = empty, expected %s", c.mac, c.family)
			continue
		}
		// Substring match keeps the test resilient to minor wording
		// changes in the description.
		if !contains(got, c.family) {
			t.Errorf("LookupOUI(%q) = %q, expected to contain %q", c.mac, got, c.family)
		}
	}
}

// TestLookupOUI_UnknownPrefix returns empty rather than misattributing.
func TestLookupOUI_UnknownPrefix(t *testing.T) {
	cases := []string{
		"AA:BB:CC:11:22:33",  // arbitrary
		"00:11:22:33:44:55",  // common in test fixtures
		"",                   // empty
		"short",              // too short
		"notvalidmacatall!!", // non-hex
	}
	for _, mac := range cases {
		if got := LookupOUI(mac); got != "" {
			t.Errorf("LookupOUI(%q) = %q, expected empty", mac, got)
		}
	}
}

// TestIsKnownAttackOUI matches LookupOUI's yes/no signal.
func TestIsKnownAttackOUI(t *testing.T) {
	if !IsKnownAttackOUI("94:B9:7E:00:00:00") {
		t.Error("known Espressif prefix should report true")
	}
	if IsKnownAttackOUI("AA:BB:CC:DD:EE:FF") {
		t.Error("unknown prefix should report false")
	}
}

// TestCanonicalOUIPrefix_Robustness covers the MAC-format
// normalisation: every accepted input shape should canonicalise to
// the same uppercase 6-hex-char prefix.
func TestCanonicalOUIPrefix_Robustness(t *testing.T) {
	cases := map[string]string{
		"94:B9:7E:01:23:45": "94B97E",
		"94-B9-7E-01-23-45": "94B97E",
		"94B97E012345":      "94B97E",
		"94.b9.7e.01.23.45": "94B97E",
		"94b97e012345":      "94B97E",
		"94 B9 7E 01 23 45": "94B97E", // spaces dropped
		// Too-short inputs return empty.
		"94:B9": "",
		"94B9":  "",
		"":      "",
		// Non-hex chars dropped, residual is too short → empty.
		"!@#$%^": "",
	}
	for in, want := range cases {
		if got := canonicalOUIPrefix(in); got != want {
			t.Errorf("canonicalOUIPrefix(%q) = %q, want %q", in, got, want)
		}
	}
}

// contains is a tiny helper to keep the test file self-contained
// without dragging in strings just for this.
func contains(haystack, needle string) bool {
	return len(needle) <= len(haystack) && indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
