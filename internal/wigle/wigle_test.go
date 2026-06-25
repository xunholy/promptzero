// SPDX-License-Identifier: AGPL-3.0-or-later

package wigle

import (
	"encoding/csv"
	"strings"
	"testing"
	"time"
)

func fix(t *testing.T) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, "2026-06-25T12:34:56Z")
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

// TestEncode_HappyPath pins the exact WigleWifi-1.4 layout: pre-header
// line, column header, and a well-formed WiFi row.
func TestEncode_HappyPath(t *testing.T) {
	obs := []Observation{{
		BSSID: "aa:bb:cc:dd:ee:ff", SSID: "CoffeeShop", AuthMode: "[WPA2-PSK-CCMP][ESS]",
		Channel: 6, RSSI: -42, Latitude: 51.5074, Longitude: -0.1278,
		AltitudeM: 35, AccuracyM: 5, FirstSeen: fix(t),
	}}
	out, err := Encode(Metadata{}, "v1.2.3", obs)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 3 lines (pre-header, header, 1 row), got %d:\n%s", len(lines), out)
	}
	if !strings.HasPrefix(lines[0], "WigleWifi-1.4,appRelease=promptzero v1.2.3,") {
		t.Errorf("pre-header = %q", lines[0])
	}
	wantHeader := "MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type"
	if lines[1] != wantHeader {
		t.Errorf("header =\n %q\nwant\n %q", lines[1], wantHeader)
	}
	wantRow := "AA:BB:CC:DD:EE:FF,CoffeeShop,[WPA2-PSK-CCMP][ESS],2026-06-25 12:34:56,6,-42,51.5074,-0.1278,35,5,WIFI"
	if lines[2] != wantRow {
		t.Errorf("row =\n %q\nwant\n %q", lines[2], wantRow)
	}
}

// TestEncode_BSSIDNormalisation covers the accepted MAC input forms.
func TestEncode_BSSIDNormalisation(t *testing.T) {
	for _, in := range []string{
		"aabbccddeeff", "AA-BB-CC-DD-EE-FF", "aabb.ccdd.eeff", "AA:bb:CC:dd:EE:ff",
	} {
		out, err := Encode(Metadata{}, "v", []Observation{{BSSID: in, Latitude: 1, Longitude: 2, FirstSeen: fix(t)}})
		if err != nil {
			t.Fatalf("Encode(%q): %v", in, err)
		}
		if !strings.Contains(string(out), "AA:BB:CC:DD:EE:FF,") {
			t.Errorf("input %q did not normalise to AA:BB:CC:DD:EE:FF\n%s", in, out)
		}
	}
}

// TestEncode_SSIDEscaping is the key correctness guard: an SSID containing
// CSV metacharacters must be RFC 4180 escaped so it round-trips as a single
// field and cannot inject extra columns. We re-parse the output with
// encoding/csv and check the SSID came back intact in an 11-column row.
func TestEncode_SSIDEscaping(t *testing.T) {
	hostile := []string{
		`evil,net`,              // comma — would shift columns if unquoted
		`say "hi"`,              // embedded quotes
		"line1\nline2",          // embedded newline — would forge a new row
		`AA:BB,99,99,WIFI,junk`, // an SSID crafted to look like trailing columns
	}
	for _, ssid := range hostile {
		out, err := Encode(Metadata{}, "v", []Observation{{
			BSSID: "aabbccddeeff", SSID: ssid, Channel: 1, RSSI: -50,
			Latitude: 10, Longitude: 20, FirstSeen: fix(t),
		}})
		if err != nil {
			t.Fatalf("Encode(ssid=%q): %v", ssid, err)
		}
		// Skip the non-CSV pre-header line, then parse the rest.
		body := out[strings.IndexByte(string(out), '\n')+1:]
		rows, err := csv.NewReader(strings.NewReader(string(body))).ReadAll()
		if err != nil {
			t.Fatalf("ssid=%q produced unparseable CSV: %v\n%s", ssid, err, out)
		}
		if len(rows) != 2 { // header + exactly one data row
			t.Fatalf("ssid=%q produced %d CSV rows, want 2 (header+row) — column injection?\n%s", ssid, len(rows), out)
		}
		if len(rows[1]) != len(columnHeader) {
			t.Errorf("ssid=%q row has %d columns, want %d", ssid, len(rows[1]), len(columnHeader))
		}
		if rows[1][1] != ssid {
			t.Errorf("ssid round-trip: got %q want %q", rows[1][1], ssid)
		}
	}
}

// TestEncode_Validation covers the fail-closed boundary checks.
func TestEncode_Validation(t *testing.T) {
	base := Observation{BSSID: "aabbccddeeff", Latitude: 1, Longitude: 2, FirstSeen: fix(t)}
	cases := []struct {
		name string
		mut  func(o *Observation)
	}{
		{"bad bssid len", func(o *Observation) { o.BSSID = "aabbcc" }},
		{"non-hex bssid", func(o *Observation) { o.BSSID = "zzbbccddeeff" }},
		{"lat too high", func(o *Observation) { o.Latitude = 90.1 }},
		{"lon too low", func(o *Observation) { o.Longitude = -180.1 }},
		{"channel too high", func(o *Observation) { o.Channel = 197 }},
		{"channel negative", func(o *Observation) { o.Channel = -1 }},
		{"zero timestamp", func(o *Observation) { o.FirstSeen = time.Time{} }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := base
			c.mut(&o)
			if _, err := Encode(Metadata{}, "v", []Observation{o}); err == nil {
				t.Errorf("expected validation error for %s", c.name)
			}
		})
	}
}

// TestEncode_EmptyAndCap covers the document-level guards.
func TestEncode_EmptyAndCap(t *testing.T) {
	if _, err := Encode(Metadata{}, "v", nil); err == nil {
		t.Error("empty observations should error")
	}
	big := make([]Observation, maxObservations+1)
	if _, err := Encode(Metadata{}, "v", big); err == nil {
		t.Error("over-cap observations should error")
	}
}

// TestMetadata_DefaultsAndSanitisation checks the pre-header fills defaults
// and strips commas/newlines that would corrupt the flat metadata line.
func TestMetadata_DefaultsAndSanitisation(t *testing.T) {
	out, err := Encode(Metadata{Model: "My,Rig\nv2"}, "v9", []Observation{{
		BSSID: "aabbccddeeff", Latitude: 1, Longitude: 2, FirstSeen: fix(t),
	}})
	if err != nil {
		t.Fatal(err)
	}
	pre := strings.SplitN(string(out), "\n", 2)[0]
	if strings.Contains(pre, "My,Rig") || strings.Contains(pre, "\n") {
		t.Errorf("metadata comma/newline not sanitised: %q", pre)
	}
	if !strings.Contains(pre, "model=My Rig v2") {
		t.Errorf("sanitised model not present: %q", pre)
	}
	if !strings.Contains(pre, "brand=xunholy") {
		t.Errorf("default brand missing: %q", pre)
	}
}
