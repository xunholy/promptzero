// SPDX-License-Identifier: AGPL-3.0-or-later

package wigle

import (
	"encoding/csv"
	"strings"
	"testing"
	"time"
)

// FuzzEncode throws adversarial SSID/BSSID/auth/coordinate values at the
// encoder. It must never panic, and whenever it succeeds the output must
// re-parse as a CSV whose data row has exactly the expected column count —
// i.e. no hostile SSID can ever forge columns or rows.
func FuzzEncode(f *testing.F) {
	seeds := []struct {
		bssid, ssid, auth string
		ch, rssi          int
		lat, lon          float64
	}{
		{"aabbccddeeff", "net", "[OPEN]", 1, -50, 10, 20},
		{"AA-BB-CC-DD-EE-FF", "a,b\"c\nd", "", 6, -90, -89.9, 179.9},
		{"zz", "", "x", 0, 0, 0, 0},
		{"aabbccddeeff", strings.Repeat("S", 64), "[WPA2]", 196, -1, 90, -180},
	}
	for _, s := range seeds {
		f.Add(s.bssid, s.ssid, s.auth, s.ch, s.rssi, s.lat, s.lon)
	}
	ts := time.Unix(1750000000, 0).UTC()
	f.Fuzz(func(t *testing.T, bssid, ssid, auth string, ch, rssi int, lat, lon float64) {
		out, err := Encode(Metadata{}, "fuzz", []Observation{{
			BSSID: bssid, SSID: ssid, AuthMode: auth, Channel: ch, RSSI: rssi,
			Latitude: lat, Longitude: lon, FirstSeen: ts,
		}})
		if err != nil {
			return // rejected at the boundary — that's fine
		}
		body := out[strings.IndexByte(string(out), '\n')+1:]
		rows, perr := csv.NewReader(strings.NewReader(string(body))).ReadAll()
		if perr != nil {
			t.Fatalf("encoded output is not valid CSV: %v\n%q", perr, out)
		}
		if len(rows) != 2 {
			t.Fatalf("expected header+1 row, got %d rows for ssid=%q", len(rows), ssid)
		}
		if len(rows[1]) != len(columnHeader) {
			t.Fatalf("row has %d columns, want %d (column injection) for ssid=%q", len(rows[1]), len(columnHeader), ssid)
		}
	})
}
