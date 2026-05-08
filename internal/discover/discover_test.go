package discover

import (
	"strings"
	"testing"
)

// TestFormatApps_Empty pins the friendly message when nothing was
// found. Operators interpret an empty SD card via this string.
func TestFormatApps_Empty(t *testing.T) {
	got := FormatApps(nil)
	if !strings.Contains(got, "No applications") {
		t.Errorf("empty FormatApps = %q, want friendly empty-state message", got)
	}
	got2 := FormatApps([]App{})
	if got2 != got {
		t.Errorf("nil and []App{} should produce identical output")
	}
}

// TestFormatApps_GroupsInDeterministicOrder is the load-bearing
// regression: previously the function iterated a map directly, so
// callers saw the section order shuffle run-to-run. The fix sorts
// types alphabetically; this test runs the same input many times
// and asserts the output is byte-identical, which would fail
// reliably (P > 1 - 1/n!) under the old map-iteration code.
func TestFormatApps_GroupsInDeterministicOrder(t *testing.T) {
	apps := []App{
		{Name: "a1", Path: "/ext/subghz/a1.sub", Type: "subghz"},
		{Name: "b1", Path: "/ext/nfc/b1.nfc", Type: "nfc"},
		{Name: "c1", Path: "/ext/lfrfid/c1.rfid", Type: "rfid"},
		{Name: "d1", Path: "/ext/infrared/d1.ir", Type: "ir"},
		{Name: "e1", Path: "/ext/badusb/e1.txt", Type: "badusb"},
		{Name: "f1", Path: "/ext/apps/f1.fap", Type: "fap"},
	}
	first := FormatApps(apps)
	for i := 0; i < 50; i++ {
		next := FormatApps(apps)
		if next != first {
			t.Fatalf("FormatApps output is non-deterministic between runs:\n--- run 0 ---\n%s\n--- run %d ---\n%s",
				first, i+1, next)
		}
	}

	// Spot-check that the order is alphabetical by type.
	wantOrder := []string{"[BADUSB]", "[FAP]", "[IR]", "[NFC]", "[RFID]", "[SUBGHZ]"}
	idx := 0
	for _, want := range wantOrder {
		nextIdx := strings.Index(first[idx:], want)
		if nextIdx < 0 {
			t.Errorf("output missing %q at or after offset %d:\n%s", want, idx, first)
			continue
		}
		idx += nextIdx + len(want)
	}
}

// TestFormatApps_PreservesEntryOrderWithinGroup confirms entries
// within a group keep the order they appeared in the input slice.
// This matters because ScanApps walks the SD card in a fixed
// directory order and operators expect that order to survive.
func TestFormatApps_PreservesEntryOrderWithinGroup(t *testing.T) {
	apps := []App{
		{Name: "z_last", Path: "/ext/subghz/z_last.sub", Type: "subghz"},
		{Name: "m_mid", Path: "/ext/subghz/m_mid.sub", Type: "subghz"},
		{Name: "a_first", Path: "/ext/subghz/a_first.sub", Type: "subghz"},
	}
	got := FormatApps(apps)
	zPos := strings.Index(got, "z_last")
	mPos := strings.Index(got, "m_mid")
	aPos := strings.Index(got, "a_first")
	if zPos < 0 || mPos < 0 || aPos < 0 {
		t.Fatalf("entries missing from output: %q", got)
	}
	if zPos >= mPos || mPos >= aPos {
		t.Errorf("entry order changed (want input order z<m<a, got positions %d/%d/%d)", zPos, mPos, aPos)
	}
}

// TestFormatApps_GroupHeaderCount confirms the "(N files)" count
// matches the actual entry count per group. A future refactor that
// shifts the count formula would surface here.
func TestFormatApps_GroupHeaderCount(t *testing.T) {
	apps := []App{
		{Name: "one", Path: "/x", Type: "fap"},
		{Name: "two", Path: "/y", Type: "fap"},
		{Name: "alpha", Path: "/z", Type: "subghz"},
	}
	got := FormatApps(apps)
	if !strings.Contains(got, "[FAP] (2 files)") {
		t.Errorf("missing [FAP] (2 files) header:\n%s", got)
	}
	if !strings.Contains(got, "[SUBGHZ] (1 files)") {
		t.Errorf("missing [SUBGHZ] (1 files) header:\n%s", got)
	}
}
