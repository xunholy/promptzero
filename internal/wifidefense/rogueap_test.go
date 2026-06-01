// SPDX-License-Identifier: AGPL-3.0-or-later

package wifidefense

import "testing"

func countRogue(a *RogueAnalysis, kind string) int {
	n := 0
	for _, o := range a.Observations {
		if o.Kind == kind {
			n++
		}
	}
	return n
}

// TestRogue_SecurityMismatch: one SSID seen as both Open and WPA2 from two
// BSSIDs is the evil-twin signature.
func TestRogue_SecurityMismatch(t *testing.T) {
	aps := []AP{
		{SSID: "CorpNet", BSSID: "AA:AA:AA:AA:AA:AA", Security: "WPA2-Personal (PSK)"},
		{SSID: "CorpNet", BSSID: "BB:BB:BB:BB:BB:BB", Security: "Open"},
	}
	a, err := AnalyzeRogueAP(aps)
	if err != nil {
		t.Fatalf("AnalyzeRogueAP: %v", err)
	}
	if countRogue(a, "security_mismatch") != 1 {
		t.Errorf("security_mismatch = %d, want 1: %+v", countRogue(a, "security_mismatch"), a.Observations)
	}
}

// TestRogue_MultipleBSSIDConsistent: same SSID, same posture, two BSSIDs is
// info (legit roaming), not a warning.
func TestRogue_MultipleBSSIDConsistent(t *testing.T) {
	aps := []AP{
		{SSID: "CorpNet", BSSID: "AA:AA:AA:AA:AA:AA", Security: "WPA2-Personal (PSK)"},
		{SSID: "CorpNet", BSSID: "BB:BB:BB:BB:BB:BB", Security: "WPA2-Personal (PSK)"},
	}
	a, err := AnalyzeRogueAP(aps)
	if err != nil {
		t.Fatalf("AnalyzeRogueAP: %v", err)
	}
	if countRogue(a, "security_mismatch") != 0 {
		t.Errorf("unexpected security_mismatch: %+v", a.Observations)
	}
	if countRogue(a, "ssid_multiple_bssid") != 1 {
		t.Errorf("ssid_multiple_bssid = %d, want 1", countRogue(a, "ssid_multiple_bssid"))
	}
}

// TestRogue_BSSIDChangedSecurity: one BSSID flipping posture mid-capture.
func TestRogue_BSSIDChangedSecurity(t *testing.T) {
	aps := []AP{
		{SSID: "Home", BSSID: "AA:AA:AA:AA:AA:AA", Security: "WPA3-Personal (SAE)"},
		{SSID: "Home", BSSID: "AA:AA:AA:AA:AA:AA", Security: "Open"},
	}
	a, err := AnalyzeRogueAP(aps)
	if err != nil {
		t.Fatalf("AnalyzeRogueAP: %v", err)
	}
	if countRogue(a, "bssid_changed_security") != 1 {
		t.Errorf("bssid_changed_security = %d, want 1: %+v", countRogue(a, "bssid_changed_security"), a.Observations)
	}
}

// TestRogue_HiddenSSIDExcluded: empty SSIDs don't drive the SSID signals.
func TestRogue_HiddenSSIDExcluded(t *testing.T) {
	aps := []AP{
		{SSID: "", BSSID: "AA:AA:AA:AA:AA:AA", Security: "WPA2-Personal (PSK)"},
		{SSID: "", BSSID: "BB:BB:BB:BB:BB:BB", Security: "Open"},
	}
	a, err := AnalyzeRogueAP(aps)
	if err != nil {
		t.Fatalf("AnalyzeRogueAP: %v", err)
	}
	if countRogue(a, "security_mismatch") != 0 {
		t.Errorf("hidden SSID should not flag security_mismatch: %+v", a.Observations)
	}
}

// TestRogue_CleanNoFlags: distinct SSIDs each with one posture/BSSID.
func TestRogue_CleanNoFlags(t *testing.T) {
	aps := []AP{
		{SSID: "A", BSSID: "AA:AA:AA:AA:AA:AA", Security: "WPA2-Personal (PSK)"},
		{SSID: "B", BSSID: "BB:BB:BB:BB:BB:BB", Security: "WPA3-Personal (SAE)"},
	}
	a, err := AnalyzeRogueAP(aps)
	if err != nil {
		t.Fatalf("AnalyzeRogueAP: %v", err)
	}
	if len(a.Observations) != 0 {
		t.Errorf("clean set flagged: %+v", a.Observations)
	}
	if a.UniqueSSIDs != 2 || a.UniqueBSSIDs != 2 {
		t.Errorf("uniques = %d ssid / %d bssid, want 2/2", a.UniqueSSIDs, a.UniqueBSSIDs)
	}
}

// TestRogue_Deterministic: the observation order is stable across runs
// (keys are sorted), so output doesn't depend on map iteration.
func TestRogue_Deterministic(t *testing.T) {
	aps := []AP{
		{SSID: "Zeta", BSSID: "AA:AA:AA:AA:AA:AA", Security: "Open"},
		{SSID: "Zeta", BSSID: "BB:BB:BB:BB:BB:BB", Security: "WPA2-Personal (PSK)"},
		{SSID: "Alpha", BSSID: "CC:CC:CC:CC:CC:CC", Security: "Open"},
		{SSID: "Alpha", BSSID: "DD:DD:DD:DD:DD:DD", Security: "WPA3-Personal (SAE)"},
	}
	first, err := AnalyzeRogueAP(aps)
	if err != nil {
		t.Fatalf("AnalyzeRogueAP: %v", err)
	}
	for i := 0; i < 20; i++ {
		again, _ := AnalyzeRogueAP(aps)
		if len(again.Observations) != len(first.Observations) {
			t.Fatalf("observation count varied")
		}
		for j := range first.Observations {
			if again.Observations[j].SSID != first.Observations[j].SSID {
				t.Fatalf("observation order not deterministic at %d", j)
			}
		}
	}
	// Alpha sorts before Zeta.
	if first.Observations[0].SSID != "Alpha" {
		t.Errorf("first observation SSID = %q, want Alpha (sorted)", first.Observations[0].SSID)
	}
}

func TestRogue_Empty(t *testing.T) {
	if _, err := AnalyzeRogueAP(nil); err == nil {
		t.Error("expected error for empty AP list")
	}
}
