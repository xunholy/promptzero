// geohash.go — host-side geohash converter Spec, delegating to internal/geohash.
//
// Wrap-vs-native: native — a geohash is deterministic base-32 range-bisection;
// bidirectional (a `geohash` decodes to lat/lon, a `latitude`+`longitude`
// encodes to a geohash). The geo companion to the redis / mongodb / bson
// decoders (geohashes appear in their GEO values / geo fields). Offline.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/geohash"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(geohashSpec)
}

var geohashSpec = Spec{
	Name: "geohash_decode",
	Description: "Convert between geographic coordinates and geohash strings (the compact base-32 geocode, " +
		"e.g. `ezs42`, `u4pruydqqvj`) used pervasively in location databases and APIs — Redis GEO " +
		"(GEOADD/GEOPOS store a geohash), Elasticsearch / MongoDB geo indexes, and countless mobile/web " +
		"location payloads. The geo companion to the redis_decode / mongodb_decode / bson_decode tools: a " +
		"geohash surfaced in a captured cache value, document, or API response decodes here to a real " +
		"latitude+longitude.\n\n" +
		"**Bidirectional**, by which field you supply:\n" +
		"- **decode** — pass `geohash` (case-insensitive, 1-12 chars): returns the cell **center** " +
		"latitude/longitude, the ± error (half-cell), and the bounding box, so the precision is explicit " +
		"and never overstated.\n" +
		"- **encode** — pass `latitude` + `longitude` (signed decimal degrees) and optional `precision` " +
		"(1-12, default 9 ≈ 4.8 m cells): returns the geohash.\n\n" +
		"A geohash interleaves the binary bisections of the latitude (−90..90) and longitude (−180..180) " +
		"ranges, 5 bits per base-32 character (alphabet `0123456789bcdefghjkmnpqrstuvwxyz` — no a/i/l/o). " +
		"A character outside that alphabet, or an out-of-range coordinate, is rejected. No network, no " +
		"device, transmits nothing, so it is Low risk.\n\n" +
		"Source: docs/catalog/gap-analysis.md (geo companion to the redis/mongodb/bson decoders; sibling " +
		"of maidenhead_locator). Wrap-vs-native: native — base-32 range-bisection, stdlib only, no new " +
		"go.mod dep. Anchored to the pygeohash reference library: `ezs42` → (42.60498, −5.60303); " +
		"(57.64911, 10.40744) → `u4pruydqqvj`.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"geohash":{"type":"string","description":"DECODE: a geohash (e.g. ezs42), case-insensitive, 1-12 chars."},
			"latitude":{"type":"number","description":"ENCODE: latitude in signed decimal degrees (-90..90)."},
			"longitude":{"type":"number","description":"ENCODE: longitude in signed decimal degrees (-180..180)."},
			"precision":{"type":"integer","description":"ENCODE: geohash length in chars (1-12; default 9)."}
		}
	}`),
	Required:  []string{},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   geohashHandler,
}

func geohashHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	gh := strings.TrimSpace(str(p, "geohash"))
	_, hasLat := p["latitude"].(float64)
	_, hasLon := p["longitude"].(float64)

	switch {
	case gh != "":
		loc, err := geohash.Decode(gh)
		if err != nil {
			return "", fmt.Errorf("geohash_decode: %w", err)
		}
		out, _ := json.MarshalIndent(loc, "", "  ")
		return string(out), nil
	case hasLat && hasLon:
		lat := floatOr(p, "latitude", 0)
		lon := floatOr(p, "longitude", 0)
		prec := int(floatOr(p, "precision", 0))
		g, err := geohash.Encode(lat, lon, prec)
		if err != nil {
			return "", fmt.Errorf("geohash_decode: %w", err)
		}
		out, _ := json.MarshalIndent(struct {
			Geohash   string  `json:"geohash"`
			Latitude  float64 `json:"latitude"`
			Longitude float64 `json:"longitude"`
		}{Geohash: g, Latitude: lat, Longitude: lon}, "", "  ")
		return string(out), nil
	default:
		return "", fmt.Errorf("geohash_decode: supply either 'geohash' (to decode) or 'latitude'+'longitude' (to encode)")
	}
}
