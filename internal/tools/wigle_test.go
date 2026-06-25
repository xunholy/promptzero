// SPDX-License-Identifier: AGPL-3.0-or-later

package tools

import (
	"context"
	"encoding/csv"
	"strings"
	"testing"
)

func runWigle(t *testing.T, params map[string]any) (string, error) {
	t.Helper()
	spec, ok := Get("wigle_wardrive_export")
	if !ok {
		t.Fatal("wigle_wardrive_export not registered")
	}
	return spec.Handler(context.Background(), &Deps{}, params)
}

// TestWigleExport_SharedFix covers the common flow: one GPS fix at the top
// level applied to a batch of scanned APs.
func TestWigleExport_SharedFix(t *testing.T) {
	out, err := runWigle(t, map[string]any{
		"latitude":   51.5074,
		"longitude":  -0.1278,
		"altitude_m": 35.0,
		"first_seen": "2026-06-25T12:34:56Z",
		"access_points": []any{
			map[string]any{"bssid": "aabbccddeeff", "ssid": "Net1", "channel": float64(6), "rssi": float64(-40)},
			map[string]any{"bssid": "11:22:33:44:55:66", "ssid": "Net2", "channel": float64(11), "rssi": float64(-70)},
		},
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	body := out[strings.IndexByte(out, '\n')+1:]
	rows, err := csv.NewReader(strings.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatalf("output not CSV: %v\n%s", err, out)
	}
	if len(rows) != 3 { // header + 2 APs
		t.Fatalf("want header+2 rows, got %d", len(rows))
	}
	if rows[1][0] != "AA:BB:CC:DD:EE:FF" || rows[2][0] != "11:22:33:44:55:66" {
		t.Errorf("MACs not normalised/ordered: %q %q", rows[1][0], rows[2][0])
	}
	// Both APs inherited the shared lat.
	if rows[1][6] != "51.5074" || rows[2][6] != "51.5074" {
		t.Errorf("shared latitude not applied: %q %q", rows[1][6], rows[2][6])
	}
}

// TestWigleExport_PerAPOverride checks a per-AP position overrides the
// shared fix (multi-point drive).
func TestWigleExport_PerAPOverride(t *testing.T) {
	out, err := runWigle(t, map[string]any{
		"latitude": 1.0, "longitude": 2.0, "first_seen": "2026-06-25T12:34:56Z",
		"access_points": []any{
			map[string]any{"bssid": "aabbccddeeff", "latitude": 40.0, "longitude": 5.0},
		},
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, ",40,5,") {
		t.Errorf("per-AP override not applied:\n%s", out)
	}
}

// TestWigleExport_Errors covers the fail-closed boundary cases.
func TestWigleExport_Errors(t *testing.T) {
	cases := []struct {
		name   string
		params map[string]any
	}{
		{"no access points", map[string]any{"latitude": 1.0, "longitude": 2.0}},
		{"missing position", map[string]any{
			"first_seen":    "2026-06-25T12:34:56Z",
			"access_points": []any{map[string]any{"bssid": "aabbccddeeff"}},
		}},
		{"missing timestamp", map[string]any{
			"latitude": 1.0, "longitude": 2.0,
			"access_points": []any{map[string]any{"bssid": "aabbccddeeff"}},
		}},
		{"bad timestamp", map[string]any{
			"latitude": 1.0, "longitude": 2.0, "first_seen": "not-a-time",
			"access_points": []any{map[string]any{"bssid": "aabbccddeeff"}},
		}},
		{"bad bssid", map[string]any{
			"latitude": 1.0, "longitude": 2.0, "first_seen": "2026-06-25T12:34:56Z",
			"access_points": []any{map[string]any{"bssid": "nope"}},
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := runWigle(t, c.params); err == nil {
				t.Errorf("expected error for %s", c.name)
			}
		})
	}
}
