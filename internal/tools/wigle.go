// SPDX-License-Identifier: AGPL-3.0-or-later

// wigle.go registers wigle_wardrive_export, which turns GPS-stamped WiFi
// access-point observations into a WiGLE "WigleWifi-1.4" CSV — the standard
// wardrive interchange format. It composes the data an operator already
// has: a Marauder AP scan (SSID / BSSID / RSSI / channel) plus a GPS fix
// (gps_nmea_decode → lat / lon / altitude). The tool only formats; it does
// not transmit or upload, so an operator reviews the file and uploads it to
// wigle.net themselves.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/version"
	"github.com/xunholy/promptzero/internal/wigle"
)

func init() { //nolint:gochecknoinits
	Register(wigleWardriveExportSpec)
	Register(wigleWardriveAnalyzeSpec)
}

// maxAnalyzeInput caps the CSV text the analyze tool will ingest, so a
// pasted multi-hundred-MB file can't blow up the tool-result. ParseCSV also
// caps rows; this bounds the byte input before parsing.
const maxAnalyzeInput = 32 << 20 // 32 MiB

// maxSoftTargetSample bounds the open/WEP network detail returned, so a
// wardrive full of open networks doesn't flood the tool-result. The full
// counts are always in the summary.
const maxSoftTargetSample = 50

var wigleWardriveExportSpec = Spec{
	Name: "wigle_wardrive_export",
	Description: "Build a **WiGLE-compatible wardrive CSV** (`WigleWifi-1.4`) from scanned WiFi access points and a " +
		"GPS fix — the standard format for importing/uploading a wardrive to wigle.net.\n\n" +
		"Typical flow: run a Marauder WiFi scan to get the access points, get a position with `gps_nmea_decode`, " +
		"then call this with the APs plus the fix. A single GPS fix usually covers a batch of APs, so set the " +
		"position once at the top level; for a multi-point drive, override `latitude`/`longitude`/`first_seen` " +
		"per access point.\n\n" +
		"Returns the CSV text — offline and deterministic, no transmit and **no upload**. Review it, then upload " +
		"to wigle.net yourself. Low risk (it only formats data you already captured).",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"latitude":{"type":"number","description":"Shared GPS latitude for all APs (decimal degrees); per-AP override allowed"},
			"longitude":{"type":"number","description":"Shared GPS longitude for all APs (decimal degrees); per-AP override allowed"},
			"altitude_m":{"type":"number","description":"Shared altitude in metres (default 0)"},
			"accuracy_m":{"type":"number","description":"Shared horizontal accuracy in metres (default 0)"},
			"first_seen":{"type":"string","description":"Shared observation time, RFC3339 (e.g. 2026-06-25T12:34:56Z); per-AP override allowed"},
			"access_points":{
				"type":"array",
				"description":"Scanned access points to export",
				"items":{
					"type":"object",
					"properties":{
						"bssid":{"type":"string","description":"AP MAC (any case/separator)"},
						"ssid":{"type":"string","description":"Network name (may be empty for hidden)"},
						"auth_mode":{"type":"string","description":"Capability string e.g. [WPA2-PSK-CCMP][ESS]; empty if unknown"},
						"channel":{"type":"integer","description":"802.11 channel"},
						"rssi":{"type":"integer","description":"Signal in dBm (negative)"},
						"latitude":{"type":"number","description":"Per-AP latitude override"},
						"longitude":{"type":"number","description":"Per-AP longitude override"},
						"altitude_m":{"type":"number","description":"Per-AP altitude override"},
						"accuracy_m":{"type":"number","description":"Per-AP accuracy override"},
						"first_seen":{"type":"string","description":"Per-AP time override, RFC3339"}
					},
					"required":["bssid"]
				}
			}
		},
		"required":["access_points"]
	}`),
	Required:  []string{"access_points"},
	Risk:      risk.Low,
	Group:     GroupMetaUtil,
	AgentOnly: false,
	Handler:   wigleWardriveExportHandler,
}

func wigleWardriveExportHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	rawAPs, ok := p["access_points"].([]any)
	if !ok || len(rawAPs) == 0 {
		return "", fmt.Errorf("wigle_wardrive_export: access_points must be a non-empty array")
	}

	// Shared GPS fix: NaN sentinel marks "not set" so a missing position is
	// caught explicitly (NaN would otherwise slip past a numeric range check).
	sharedLat := floatOr(p, "latitude", math.NaN())
	sharedLon := floatOr(p, "longitude", math.NaN())
	sharedAlt := floatOr(p, "altitude_m", 0)
	sharedAcc := floatOr(p, "accuracy_m", 0)
	sharedSeen, sharedSeenErr := parseRFC3339Opt(str(p, "first_seen"))

	obs := make([]wigle.Observation, 0, len(rawAPs))
	for i, raw := range rawAPs {
		ap, ok := raw.(map[string]any)
		if !ok {
			return "", fmt.Errorf("wigle_wardrive_export: access_points[%d] is not an object", i)
		}

		lat := floatOr(ap, "latitude", sharedLat)
		lon := floatOr(ap, "longitude", sharedLon)
		if math.IsNaN(lat) || math.IsNaN(lon) {
			return "", fmt.Errorf("wigle_wardrive_export: access_points[%d]: latitude/longitude required "+
				"(set them at the top level for a shared fix, or per access point)", i)
		}

		// Resolve the timestamp: per-AP first_seen wins, else the shared one.
		seen := sharedSeen
		if apSeenStr := str(ap, "first_seen"); apSeenStr != "" {
			ts, err := parseRFC3339Opt(apSeenStr)
			if err != nil {
				return "", fmt.Errorf("wigle_wardrive_export: access_points[%d]: %w", i, err)
			}
			seen = ts
		} else if sharedSeenErr != nil {
			return "", fmt.Errorf("wigle_wardrive_export: %w", sharedSeenErr)
		} else if seen.IsZero() {
			return "", fmt.Errorf("wigle_wardrive_export: access_points[%d]: first_seen required "+
				"(set it at the top level, or per access point), RFC3339 e.g. 2026-06-25T12:34:56Z", i)
		}

		obs = append(obs, wigle.Observation{
			BSSID:     str(ap, "bssid"),
			SSID:      str(ap, "ssid"),
			AuthMode:  str(ap, "auth_mode"),
			Channel:   intOr(ap, "channel", 0),
			RSSI:      intOr(ap, "rssi", 0),
			Latitude:  lat,
			Longitude: lon,
			AltitudeM: floatOr(ap, "altitude_m", sharedAlt),
			AccuracyM: floatOr(ap, "accuracy_m", sharedAcc),
			FirstSeen: seen,
		})
	}

	csvBytes, err := wigle.Encode(wigle.Metadata{}, version.Version, obs)
	if err != nil {
		return "", err
	}
	return string(csvBytes), nil
}

// parseRFC3339Opt parses an optional RFC3339 timestamp. An empty string
// returns the zero time with no error (the caller decides whether absence
// is acceptable); a non-empty malformed string is an error.
func parseRFC3339Opt(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid first_seen %q: want RFC3339 (e.g. 2026-06-25T12:34:56Z): %w", s, err)
	}
	return ts, nil
}

// softTarget is one open/WEP network surfaced for triage.
type softTarget struct {
	BSSID      string  `json:"bssid"`
	SSID       string  `json:"ssid,omitempty"`
	Encryption string  `json:"encryption"`
	Channel    int     `json:"channel"`
	Latitude   float64 `json:"latitude"`
	Longitude  float64 `json:"longitude"`
}

// wigleAnalyzeOutput is the JSON the analyze tool returns.
type wigleAnalyzeOutput struct {
	DataRows         int           `json:"data_rows"`
	ParsedObs        int           `json:"parsed_observations"`
	SkippedRows      int           `json:"skipped_rows"`
	Summary          wigle.Summary `json:"summary"`
	SoftTargetSample []softTarget  `json:"soft_target_sample,omitempty"`
}

var wigleWardriveAnalyzeSpec = Spec{
	Name: "wigle_wardrive_analyze",
	Description: "Parse and **triage a WiGLE / Kismet wardrive CSV** — the inverse of `wigle_wardrive_export`. " +
		"Load an existing wardrive (a `WigleWifi-1.4` export, or a close variant with extra/reordered columns) " +
		"and get a security-oriented summary:\n" +
		"- **encryption breakdown** (open / WEP / WPA / WPA2 / WPA3 / unknown) and a **soft_targets** count " +
		"(open + WEP — the networks worth looking at first), with a sample of those networks;\n" +
		"- unique BSSIDs, hidden (no-SSID) networks, channel distribution;\n" +
		"- geographic bounding box + center over the located observations (0,0 'no-fix' rows excluded);\n" +
		"- the most common SSIDs.\n\n" +
		"Resilient: malformed rows and non-WiFi (BT/BLE/GSM) rows are skipped and counted, not fatal. Offline, " +
		"read-only; nothing is transmitted. Low risk.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"csv":{"type":"string","description":"The wardrive CSV text (WigleWifi-1.4 or a close variant)"},
			"top_ssids":{"type":"integer","description":"How many of the most common SSIDs to list (default 10)"}
		},
		"required":["csv"]
	}`),
	Required:  []string{"csv"},
	Risk:      risk.Low,
	Group:     GroupMetaUtil,
	AgentOnly: false,
	Handler:   wigleWardriveAnalyzeHandler,
}

func wigleWardriveAnalyzeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	csv := str(p, "csv")
	if csv == "" {
		return "", fmt.Errorf("wigle_wardrive_analyze: csv is required")
	}
	if len(csv) > maxAnalyzeInput {
		return "", fmt.Errorf("wigle_wardrive_analyze: input %d bytes exceeds cap of %d", len(csv), maxAnalyzeInput)
	}

	res, err := wigle.ParseCSV([]byte(csv))
	if err != nil {
		return "", err
	}

	out := wigleAnalyzeOutput{
		DataRows:    res.DataRows,
		ParsedObs:   len(res.Observations),
		SkippedRows: res.SkippedRows,
		Summary:     wigle.Summarize(res.Observations, intOr(p, "top_ssids", 10)),
	}
	// Surface a capped sample of the actionable (open/WEP) networks.
	for _, o := range res.Observations {
		enc := wigle.Classify(o.AuthMode)
		if enc != wigle.EncOpen && enc != wigle.EncWEP {
			continue
		}
		out.SoftTargetSample = append(out.SoftTargetSample, softTarget{
			BSSID: o.BSSID, SSID: o.SSID, Encryption: enc,
			Channel: o.Channel, Latitude: o.Latitude, Longitude: o.Longitude,
		})
		if len(out.SoftTargetSample) >= maxSoftTargetSample {
			break
		}
	}

	body, _ := json.MarshalIndent(out, "", "  ")
	return string(body), nil
}
