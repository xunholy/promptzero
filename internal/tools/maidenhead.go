// maidenhead.go — host-side Maidenhead grid-locator converter Spec, delegating
// to internal/maidenhead.
//
// Wrap-vs-native: native — the Maidenhead system is public fixed-base
// arithmetic (alternating base-18 / base-10 / base-24 pairs over a 360x180
// grid). Bidirectional: a `grid` decodes to lat/lon, a `latitude`+`longitude`
// encodes to a locator. The offline geo companion to the aprs / ais / nmea
// decoders. Offline; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/maidenhead"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(maidenheadLocatorSpec)
}

var maidenheadLocatorSpec = Spec{
	Name: "maidenhead_locator",
	Description: "Convert between geographic coordinates and Maidenhead grid locators (a.k.a. QTH / grid " +
		"squares, e.g. `FN31pr`) — the location format used throughout amateur radio: in APRS, ham logging, " +
		"contesting, and on the displays of many handheld/mobile rigs. The offline geo companion to the " +
		"aprs_packet_decode / ais_nmea_decode / gps_nmea_decode family.\n\n" +
		"**Bidirectional**, by which field you supply:\n" +
		"- **decode** — pass `grid` (e.g. `FN31pr`, case-insensitive, 2-8 chars / 1-4 pairs): returns the " +
		"grid square's **center** latitude/longitude (the value to plot) plus its **south-west corner** and " +
		"the cell size, so the precision is explicit and never overstated.\n" +
		"- **encode** — pass `latitude` + `longitude` (signed decimal degrees) and optional `pairs` " +
		"(1-4, default 3 → a 6-character locator): returns the locator.\n\n" +
		"Maidenhead alternates a base-18 field (letters A-R), a base-10 square (digits), a base-24 " +
		"subsquare (letters a-x), and a base-10 extended square over the 360°×180° world grid. A malformed " +
		"locator (odd length, out-of-range character) or an out-of-range coordinate is rejected. No network, " +
		"no device, transmits nothing, so it is Low risk.\n\n" +
		"Source: docs/catalog/gap-analysis.md (ham-radio geo utility; companion to the APRS/AIS/NMEA " +
		"decoders). Wrap-vs-native: native — public fixed-base arithmetic, stdlib only, no new go.mod dep. " +
		"Anchored to the `maidenhead` reference library: e.g. (41.714, -72.728) → `FN31pr`; `JN58td` → " +
		"center 48.1458°N, 11.625°E.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"grid":{"type":"string","description":"DECODE: a Maidenhead locator (e.g. FN31pr), case-insensitive, 2-8 chars."},
			"latitude":{"type":"number","description":"ENCODE: latitude in signed decimal degrees (-90..90)."},
			"longitude":{"type":"number","description":"ENCODE: longitude in signed decimal degrees (-180..180)."},
			"pairs":{"type":"integer","description":"ENCODE: precision in pairs (1-4; default 3 = 6-character locator)."}
		}
	}`),
	Required:  []string{},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   maidenheadLocatorHandler,
}

func maidenheadLocatorHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	grid := strings.TrimSpace(str(p, "grid"))
	_, hasLat := p["latitude"].(float64)
	_, hasLon := p["longitude"].(float64)

	switch {
	case grid != "":
		loc, err := maidenhead.Decode(grid)
		if err != nil {
			return "", fmt.Errorf("maidenhead_locator: %w", err)
		}
		out, _ := json.MarshalIndent(loc, "", "  ")
		return string(out), nil
	case hasLat && hasLon:
		lat := floatOr(p, "latitude", 0)
		lon := floatOr(p, "longitude", 0)
		pairs := int(floatOr(p, "pairs", 0))
		g, err := maidenhead.Encode(lat, lon, pairs)
		if err != nil {
			return "", fmt.Errorf("maidenhead_locator: %w", err)
		}
		out, _ := json.MarshalIndent(struct {
			Grid      string  `json:"grid"`
			Latitude  float64 `json:"latitude"`
			Longitude float64 `json:"longitude"`
		}{Grid: g, Latitude: lat, Longitude: lon}, "", "  ")
		return string(out), nil
	default:
		return "", fmt.Errorf("maidenhead_locator: supply either 'grid' (to decode) or 'latitude'+'longitude' (to encode)")
	}
}
