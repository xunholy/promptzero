// gps_nmea.go — host-side GPS/GNSS NMEA 0183 sentence decode Spec, delegating
// to internal/nmea.
//
// Wrap-vs-native: native — NMEA 0183 is public comma-delimited ASCII + an XOR
// checksum; parsing is string splitting + ddmm.mmmm→decimal-degree arithmetic.
// The offline complement to the device-side gps_* / marauder_nmea stream tools.
// Offline; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/nmea"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(gpsNMEADecodeSpec)
}

var gpsNMEADecodeSpec = Spec{
	Name: "gps_nmea_decode",
	Description: "Decode GPS/GNSS NMEA 0183 sentences (the line-based ASCII output of virtually every GPS " +
		"receiver — including the GPS modules used with the Flipper Zero and the ESP32 Marauder devboard). " +
		"The **offline complement** to the device-side `marauder_nmea` / `gps_*` tools, which only stream " +
		"the raw sentences: paste a captured NMEA log (a wardriving track, a geotag stream, a " +
		"drone-telemetry dump, or a single `$GPGGA…` line) and get the parsed fix.\n\n" +
		"Decodes the position / velocity / fix sentences and validates each sentence's checksum:\n" +
		"- **GGA** — time, latitude/longitude, fix quality (+ name), satellites used, HDOP, altitude.\n" +
		"- **RMC** — time, status (valid/void), lat/lon, speed (knots), course, date, magnetic variation.\n" +
		"- **GLL** — lat/lon, time, status.\n" +
		"- **VTG** — true + magnetic course, speed (knots + km/h).\n" +
		"- **GSA** — fix type (no-fix / 2D / 3D), PDOP / HDOP / VDOP.\n" +
		"- **GSV** — satellites in view, with per-satellite PRN / elevation / azimuth / SNR " +
		"(for GPS signal-quality and spoofing/jamming analysis — anomalous SNR or geometry).\n" +
		"- **GST** — pseudorange error statistics: RMS, error-ellipse (major/minor/orientation), " +
		"and lat/lon/altitude standard deviations (fix integrity).\n" +
		"- **ZDA** — UTC time + date.\n\n" +
		"It also decodes the **marine-instrument sentences** carried on a vessel's NMEA 0183 bus alongside " +
		"GPS — **HDT/HDG** (heading true / magnetic + deviation + variation), **VHW** (water speed + " +
		"heading), **DBT/DPT** (depth below transducer / depth + transducer offset), **MTW** (water " +
		"temperature), **MWV/MWD** (wind speed + angle, relative or true), and **ROT** (rate of turn). " +
		"NMEA 0183 is unauthenticated, so a spoofed depth / heading / wind value injected onto the bus can " +
		"mislead an autopilot or crew — the maritime counterpart to GPS spoofing — making a captured marine " +
		"NMEA stream a genuine integrity-analysis surface (companion to `ais_nmea_decode`).\n\n" +
		"Coordinates are converted from `ddmm.mmmm`/hemisphere to signed decimal degrees; the talker ID " +
		"(GP=GPS, GN=combined GNSS, GL=GLONASS, GA=Galileo, GB/BD=BeiDou, …) is identified. Multiple " +
		"sentences (newline-separated) decode to an array. Each sentence reports `checksum_ok` (the NMEA " +
		"XOR checksum); a bad/absent checksum is still parsed but flagged, an empty field (no fix yet) " +
		"decodes to null (never a zero), and an unrecognised sentence type is surfaced with its raw fields " +
		"rather than guessed. No network, no device, transmits nothing, so it is Low risk.\n\n" +
		"Source: docs/catalog/gap-analysis.md (GPS/GNSS decode — the offline complement to marauder_nmea; " +
		"companion to ais_nmea_decode). Wrap-vs-native: native — public ASCII format + XOR checksum, " +
		"stdlib only, no new go.mod dep. Anchored to the pynmea2 reference library: the canonical example " +
		"sentences reproduce its decoded latitude/longitude/time/speed/course/fix fields exactly.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"sentence":{"type":"string","description":"One or more NMEA 0183 sentences (e.g. $GPGGA,…*47), newline-separated for a stream."}
		},
		"required":["sentence"]
	}`),
	Required:  []string{"sentence"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   gpsNMEADecodeHandler,
}

func gpsNMEADecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	in := strings.TrimSpace(str(p, "sentence"))
	if in == "" {
		return "", fmt.Errorf("gps_nmea_decode: 'sentence' is required")
	}
	res, err := nmea.Decode(in)
	if err != nil {
		return "", fmt.Errorf("gps_nmea_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
