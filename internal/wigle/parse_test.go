// SPDX-License-Identifier: AGPL-3.0-or-later

package wigle

import (
	"testing"
)

// TestParse_RoundTrip encodes observations then parses them back, proving
// Encode and ParseCSV agree on the format.
func TestParse_RoundTrip(t *testing.T) {
	in := []Observation{
		{BSSID: "AA:BB:CC:DD:EE:FF", SSID: "Net,One", AuthMode: "[WPA2-PSK-CCMP][ESS]",
			Channel: 6, RSSI: -42, Latitude: 51.5, Longitude: -0.12, AltitudeM: 30, FirstSeen: fix(t)},
		{BSSID: "11:22:33:44:55:66", SSID: "", AuthMode: "[ESS]",
			Channel: 11, RSSI: -70, Latitude: 51.6, Longitude: -0.13, FirstSeen: fix(t)},
	}
	csvBytes, err := Encode(Metadata{}, "v", in)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	res, err := ParseCSV(csvBytes)
	if err != nil {
		t.Fatalf("ParseCSV: %v", err)
	}
	if len(res.Observations) != 2 || res.SkippedRows != 0 {
		t.Fatalf("got %d obs, %d skipped; want 2,0", len(res.Observations), res.SkippedRows)
	}
	for i, o := range res.Observations {
		if o.BSSID != in[i].BSSID || o.SSID != in[i].SSID || o.Channel != in[i].Channel ||
			o.RSSI != in[i].RSSI || o.Latitude != in[i].Latitude || o.Longitude != in[i].Longitude {
			t.Errorf("obs[%d] round-trip mismatch:\n got %+v\nwant %+v", i, o, in[i])
		}
	}
}

// TestParse_FormatVariants covers a file with no pre-header and extra,
// re-ordered columns (Kismet-style) — columns are matched by name.
func TestParse_FormatVariants(t *testing.T) {
	csv := "RSSI,MAC,SSID,Channel,CurrentLatitude,CurrentLongitude,Type,RCOIs\n" +
		"-55,aa:bb:cc:dd:ee:ff,Cafe,6,10.0,20.0,WIFI,\n"
	res, err := ParseCSV([]byte(csv))
	if err != nil {
		t.Fatalf("ParseCSV: %v", err)
	}
	if len(res.Observations) != 1 {
		t.Fatalf("got %d obs, want 1", len(res.Observations))
	}
	o := res.Observations[0]
	if o.BSSID != "AA:BB:CC:DD:EE:FF" || o.SSID != "Cafe" || o.RSSI != -55 || o.Channel != 6 {
		t.Errorf("variant parse wrong: %+v", o)
	}
}

// TestParse_SkipsBadAndNonWifi checks malformed rows and non-WiFi Type rows
// are skipped and counted, not fatal.
func TestParse_SkipsBadAndNonWifi(t *testing.T) {
	csv := "MAC,SSID,CurrentLatitude,CurrentLongitude,Type\n" +
		"aa:bb:cc:dd:ee:ff,Good,10,20,WIFI\n" +
		"not-a-mac,Bad,10,20,WIFI\n" + // bad MAC -> skip
		"11:22:33:44:55:66,NoCoord,x,y,WIFI\n" + // bad coords -> skip
		"22:33:44:55:66:77,Phone,10,20,BT\n" // non-WiFi -> skip
	res, err := ParseCSV([]byte(csv))
	if err != nil {
		t.Fatalf("ParseCSV: %v", err)
	}
	if len(res.Observations) != 1 {
		t.Fatalf("got %d obs, want 1 (only the good WIFI row)", len(res.Observations))
	}
	if res.SkippedRows != 3 {
		t.Errorf("SkippedRows = %d, want 3", res.SkippedRows)
	}
}

// TestParse_NoMacColumn is the hard-error case: not a recognisable wardrive.
func TestParse_NoMacColumn(t *testing.T) {
	if _, err := ParseCSV([]byte("foo,bar\n1,2\n")); err == nil {
		t.Error("expected error when no MAC/BSSID column present")
	}
}

func TestClassifyAuth(t *testing.T) {
	cases := map[string]string{
		"[WPA2-PSK-CCMP][ESS]": EncWPA2,
		"[WPA3-SAE][ESS]":      EncWPA3,
		"[WPA-PSK-TKIP][ESS]":  EncWPA,
		"[WEP][ESS]":           EncWEP,
		"[ESS]":                EncOpen,
		"":                     EncOpen,
		"[SAE]":                EncWPA3,
		"[RSN-PSK]":            EncWPA2,
		"[WeirdVendorTag]":     EncUnknown,
	}
	for auth, want := range cases {
		if got := Classify(auth); got != want {
			t.Errorf("Classify(%q) = %q, want %q", auth, got, want)
		}
	}
}

// TestSummarize covers the security-oriented aggregation: soft-target
// flagging, hidden SSIDs, no-fix exclusion from the bbox, and ranking.
func TestSummarize(t *testing.T) {
	obs := []Observation{
		{BSSID: "AA:AA:AA:AA:AA:01", SSID: "Free", AuthMode: "[ESS]", Channel: 1, Latitude: 10, Longitude: 20},
		{BSSID: "AA:AA:AA:AA:AA:02", SSID: "OldRouter", AuthMode: "[WEP][ESS]", Channel: 1, Latitude: 12, Longitude: 22},
		{BSSID: "AA:AA:AA:AA:AA:03", SSID: "Home", AuthMode: "[WPA2-PSK-CCMP][ESS]", Channel: 6, Latitude: 11, Longitude: 21},
		{BSSID: "AA:AA:AA:AA:AA:04", SSID: "", AuthMode: "[WPA2][ESS]", Channel: 6},                                           // hidden + no fix (0,0)
		{BSSID: "AA:AA:AA:AA:AA:03", SSID: "Home", AuthMode: "[WPA2-PSK-CCMP][ESS]", Channel: 6, Latitude: 11, Longitude: 21}, // dup BSSID + repeat SSID
	}
	s := Summarize(obs, 10)
	if s.AccessPoints != 5 {
		t.Errorf("AccessPoints = %d, want 5", s.AccessPoints)
	}
	if s.UniqueBSSIDs != 4 {
		t.Errorf("UniqueBSSIDs = %d, want 4", s.UniqueBSSIDs)
	}
	if s.SoftTargets != 2 { // one open + one WEP
		t.Errorf("SoftTargets = %d, want 2", s.SoftTargets)
	}
	if s.Encryption[EncOpen] != 1 || s.Encryption[EncWEP] != 1 || s.Encryption[EncWPA2] != 3 {
		t.Errorf("Encryption = %v", s.Encryption)
	}
	if s.HiddenSSIDs != 1 {
		t.Errorf("HiddenSSIDs = %d, want 1", s.HiddenSSIDs)
	}
	if s.WithFix != 4 || s.NoFix != 1 {
		t.Errorf("WithFix/NoFix = %d/%d, want 4/1", s.WithFix, s.NoFix)
	}
	if s.BBox == nil || s.BBox.MinLatitude != 10 || s.BBox.MaxLatitude != 12 {
		t.Errorf("BBox = %+v", s.BBox)
	}
	if len(s.TopSSIDs) == 0 || s.TopSSIDs[0].SSID != "Home" || s.TopSSIDs[0].Count != 2 {
		t.Errorf("TopSSIDs[0] = %+v, want Home/2", s.TopSSIDs)
	}
}

// TestParse_PreHeaderStripped confirms a leading WigleWifi metadata line is
// not mistaken for the column header.
func TestParse_PreHeaderStripped(t *testing.T) {
	csv := "WigleWifi-1.4,appRelease=x,model=y\n" +
		"MAC,SSID,CurrentLatitude,CurrentLongitude,Type\n" +
		"aa:bb:cc:dd:ee:ff,N,10,20,WIFI\n"
	res, err := ParseCSV([]byte(csv))
	if err != nil {
		t.Fatalf("ParseCSV: %v", err)
	}
	if len(res.Observations) != 1 {
		t.Fatalf("got %d obs, want 1", len(res.Observations))
	}
}

func TestParse_FirstSeenLayouts(t *testing.T) {
	for _, ts := range []string{"2026-06-25 12:34:56", "2026-06-25T12:34:56Z"} {
		if got := parseFirstSeen(ts); got.IsZero() {
			t.Errorf("parseFirstSeen(%q) returned zero", ts)
		}
	}
	if got := parseFirstSeen("garbage"); !got.IsZero() {
		t.Errorf("parseFirstSeen(garbage) should be zero, got %v", got)
	}
}
