// SPDX-License-Identifier: AGPL-3.0-or-later

package wigle

import (
	"testing"
	"time"
)

func at(t *testing.T, rfc string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, rfc)
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

// TestMerge_DedupAndStrongestSignal: the same BSSID seen twice collapses to
// one, keeping the strongest (highest, i.e. closest-to-zero) RSSI.
func TestMerge_DedupAndStrongestSignal(t *testing.T) {
	obs := []Observation{
		{BSSID: "AA:AA:AA:AA:AA:01", SSID: "N", RSSI: -80, Latitude: 10, Longitude: 20, FirstSeen: at(t, "2026-06-25T10:00:00Z")},
		{BSSID: "AA:AA:AA:AA:AA:01", SSID: "N", RSSI: -40, Latitude: 11, Longitude: 21, FirstSeen: at(t, "2026-06-25T11:00:00Z")},
		{BSSID: "AA:AA:AA:AA:AA:02", SSID: "M", RSSI: -55, Latitude: 12, Longitude: 22, FirstSeen: at(t, "2026-06-25T10:00:00Z")},
	}
	res := Merge(obs)
	if res.InputCount != 3 || len(res.Observations) != 2 || res.Duplicates != 1 {
		t.Fatalf("got in=%d out=%d dup=%d; want 3/2/1", res.InputCount, len(res.Observations), res.Duplicates)
	}
	// AP01 should keep the -40 sighting (stronger) at 11,21.
	if res.Observations[0].BSSID != "AA:AA:AA:AA:AA:01" || res.Observations[0].RSSI != -40 || res.Observations[0].Latitude != 11 {
		t.Errorf("AP01 kept wrong sighting: %+v", res.Observations[0])
	}
}

// TestMerge_ZeroRSSIIsWeakest: an RSSI of 0 (no measurement) must not beat a
// real negative reading.
func TestMerge_ZeroRSSIIsWeakest(t *testing.T) {
	obs := []Observation{
		{BSSID: "BB:BB:BB:BB:BB:01", RSSI: 0, Latitude: 1, Longitude: 2, FirstSeen: at(t, "2026-06-25T10:00:00Z")},
		{BSSID: "BB:BB:BB:BB:BB:01", RSSI: -70, Latitude: 3, Longitude: 4, FirstSeen: at(t, "2026-06-25T10:00:00Z")},
	}
	res := Merge(obs)
	if len(res.Observations) != 1 || res.Observations[0].RSSI != -70 {
		t.Fatalf("zero RSSI wrongly won: %+v", res.Observations)
	}
}

// TestMerge_SSIDEnrichment: a BSSID hidden in the strongest sighting but
// named in a weaker one adopts the name (and its auth).
func TestMerge_SSIDEnrichment(t *testing.T) {
	obs := []Observation{
		{BSSID: "CC:CC:CC:CC:CC:01", SSID: "", AuthMode: "", RSSI: -40, Latitude: 1, Longitude: 2, FirstSeen: at(t, "2026-06-25T10:00:00Z")},
		{BSSID: "CC:CC:CC:CC:CC:01", SSID: "Hidden-Then-Named", AuthMode: "[WPA2][ESS]", RSSI: -80, Latitude: 3, Longitude: 4, FirstSeen: at(t, "2026-06-25T10:00:00Z")},
	}
	res := Merge(obs)
	if len(res.Observations) != 1 {
		t.Fatalf("want 1 obs, got %d", len(res.Observations))
	}
	o := res.Observations[0]
	// Keeps the stronger (-40) sighting's position but adopts the name/auth.
	if o.RSSI != -40 || o.Latitude != 1 {
		t.Errorf("should keep strongest sighting position: %+v", o)
	}
	if o.SSID != "Hidden-Then-Named" || o.AuthMode != "[WPA2][ESS]" {
		t.Errorf("SSID/auth enrichment failed: %+v", o)
	}
}

// TestMerge_DeterministicOrder: output is sorted by BSSID regardless of
// input order.
func TestMerge_DeterministicOrder(t *testing.T) {
	obs := []Observation{
		{BSSID: "FF:00:00:00:00:03", FirstSeen: at(t, "2026-06-25T10:00:00Z"), Latitude: 1, Longitude: 1, RSSI: -1},
		{BSSID: "00:00:00:00:00:01", FirstSeen: at(t, "2026-06-25T10:00:00Z"), Latitude: 1, Longitude: 1, RSSI: -1},
		{BSSID: "88:00:00:00:00:02", FirstSeen: at(t, "2026-06-25T10:00:00Z"), Latitude: 1, Longitude: 1, RSSI: -1},
	}
	res := Merge(obs)
	if len(res.Observations) != 3 {
		t.Fatalf("want 3, got %d", len(res.Observations))
	}
	want := []string{"00:00:00:00:00:01", "88:00:00:00:00:02", "FF:00:00:00:00:03"}
	for i, w := range want {
		if res.Observations[i].BSSID != w {
			t.Errorf("order[%d] = %s, want %s", i, res.Observations[i].BSSID, w)
		}
	}
}

// TestMerge_RoundTrip: merge output re-encodes to a valid WiGLE CSV.
func TestMerge_RoundTrip(t *testing.T) {
	obs := []Observation{
		{BSSID: "AA:AA:AA:AA:AA:01", SSID: "N", RSSI: -40, Latitude: 10, Longitude: 20, FirstSeen: at(t, "2026-06-25T10:00:00Z")},
		{BSSID: "AA:AA:AA:AA:AA:01", SSID: "N", RSSI: -50, Latitude: 11, Longitude: 21, FirstSeen: at(t, "2026-06-25T10:00:00Z")},
	}
	res := Merge(obs)
	csv, err := Encode(Metadata{}, "v", res.Observations)
	if err != nil {
		t.Fatalf("merged output not encodable: %v", err)
	}
	back, err := ParseCSV(csv)
	if err != nil || len(back.Observations) != 1 {
		t.Fatalf("merged CSV did not round-trip: err=%v obs=%d", err, len(back.Observations))
	}
}
