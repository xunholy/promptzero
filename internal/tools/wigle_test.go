// SPDX-License-Identifier: AGPL-3.0-or-later

package tools

import (
	"context"
	"encoding/csv"
	"encoding/json"
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

// TestWigleAnalyze covers the import/triage tool end-to-end: round-trip from
// the exporter, the security summary, and the soft-target sample.
func TestWigleAnalyze(t *testing.T) {
	spec, ok := Get("wigle_wardrive_analyze")
	if !ok {
		t.Fatal("wigle_wardrive_analyze not registered")
	}
	csv := "WigleWifi-1.4,appRelease=x\n" +
		"MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type\n" +
		"AA:BB:CC:DD:EE:01,FreeWifi,[ESS],2026-06-25 12:00:00,1,-40,10.0,20.0,0,0,WIFI\n" +
		"AA:BB:CC:DD:EE:02,OldNet,[WEP][ESS],2026-06-25 12:00:00,6,-60,11.0,21.0,0,0,WIFI\n" +
		"AA:BB:CC:DD:EE:03,SecureNet,[WPA2-PSK-CCMP][ESS],2026-06-25 12:00:00,6,-50,10.5,20.5,0,0,WIFI\n" +
		"bad-row-here\n" +
		"AA:BB:CC:DD:EE:04,Phone,,2026-06-25 12:00:00,0,-70,10.0,20.0,0,0,BT\n"

	out, err := spec.Handler(context.Background(), &Deps{}, map[string]any{"csv": csv})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	var r struct {
		ParsedObs   int `json:"parsed_observations"`
		SkippedRows int `json:"skipped_rows"`
		Summary     struct {
			SoftTargets int            `json:"soft_targets"`
			Encryption  map[string]int `json:"encryption"`
		} `json:"summary"`
		SoftTargetSample []struct {
			Encryption string `json:"encryption"`
		} `json:"soft_target_sample"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, out)
	}
	if r.ParsedObs != 3 { // 3 WIFI rows; bad-row + BT skipped
		t.Errorf("parsed_observations = %d, want 3", r.ParsedObs)
	}
	if r.SkippedRows < 2 {
		t.Errorf("skipped_rows = %d, want >=2 (bad row + BT)", r.SkippedRows)
	}
	if r.Summary.SoftTargets != 2 { // open + WEP
		t.Errorf("soft_targets = %d, want 2", r.Summary.SoftTargets)
	}
	if len(r.SoftTargetSample) != 2 {
		t.Errorf("soft_target_sample len = %d, want 2", len(r.SoftTargetSample))
	}
}

// TestWigleAnalyze_Errors covers the boundary guards.
func TestWigleAnalyze_Errors(t *testing.T) {
	spec, _ := Get("wigle_wardrive_analyze")
	if _, err := spec.Handler(context.Background(), &Deps{}, map[string]any{}); err == nil {
		t.Error("missing csv should error")
	}
	if _, err := spec.Handler(context.Background(), &Deps{}, map[string]any{"csv": "foo,bar,baz\n1,2,3\n"}); err == nil {
		t.Error("csv with no MAC column should error")
	}
}
