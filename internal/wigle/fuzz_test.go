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

// FuzzParseCSV throws arbitrary bytes at the wardrive importer. It must
// never panic, must stay within its row cap, and any observation it yields
// must itself re-encode (the parser cannot emit a row Encode would reject).
func FuzzParseCSV(f *testing.F) {
	f.Add([]byte("MAC,SSID,CurrentLatitude,CurrentLongitude,Type\naa:bb:cc:dd:ee:ff,N,10,20,WIFI\n"))
	f.Add([]byte("WigleWifi-1.4,x\nMAC,CurrentLatitude,CurrentLongitude\nzz,1,2\n"))
	f.Add([]byte(""))
	f.Add([]byte("MAC\n"))
	f.Add([]byte("not csv at all \x00\x01"))
	ts := time.Unix(1750000000, 0).UTC()
	f.Fuzz(func(t *testing.T, data []byte) {
		res, err := ParseCSV(data)
		if err != nil {
			return
		}
		if len(res.Observations) > maxParseRows {
			t.Fatalf("parsed %d observations, exceeds cap %d", len(res.Observations), maxParseRows)
		}
		// Summarize must not panic on whatever was parsed.
		_ = Summarize(res.Observations, 5)
		// Every parsed observation must be re-encodable: the parser must not
		// produce a row the encoder considers invalid.
		for _, o := range res.Observations {
			o.FirstSeen = ts // parser may leave FirstSeen zero; Encode requires it
			if _, err := Encode(Metadata{}, "fuzz", []Observation{o}); err != nil {
				t.Fatalf("parsed observation not re-encodable: %v (%+v)", err, o)
			}
		}
	})
}
