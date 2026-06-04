// SPDX-License-Identifier: AGPL-3.0-or-later

// Package geohash converts between geographic coordinates and geohash strings —
// the compact base-32 geocode (e.g. "ezs42", "u4pruydqqvj") used pervasively in
// location databases and APIs: Redis GEO (GEOADD/GEOPOS store a 52-bit
// geohash), Elasticsearch/MongoDB geo indexes, and countless mobile/web
// location payloads. It is the geo companion to the project's data decoders
// (internal/redis, internal/mongodb, internal/bson) — a geohash surfaced in a
// captured cache value / document / API response decodes here to a real
// latitude+longitude. Pure offline transform; no network or device.
//
// # Wrap-vs-native judgement
//
// Native. A geohash is a deterministic interleaving of the binary bisections of
// the latitude (-90..90) and longitude (-180..180) ranges, packed 5 bits per
// base-32 character (alphabet "0123456789bcdefghjkmnpqrstuvwxyz", no a/i/l/o).
// Encoding/decoding is a few lines of range-bisection — there is nothing to
// wrap, and a third-party geohash library would be a runtime dep for trivial
// bit work. Consistent with the other in-tree geo transforms (internal/maidenhead).
//
// # Verifiable / no confidently-wrong output
//
// Both directions are anchored to the reference pygeohash library: the canonical
// examples reproduce its output exactly — "ezs42" ↔ (42.60498, -5.60303) ± a
// 0.0220° cell, "u4pruydqqvj" ↔ (57.649111, 10.407440), "9q8yy" ↔ San Francisco,
// the single character "0" ↔ (-67.5, -157.5) ± 22.5°. Decode reports the cell
// center, its ± error (half-cell), and the bounding box, so the precision is
// explicit and never overstated. A geohash with a character outside the base-32
// alphabet, or an empty string, is rejected.
package geohash

import (
	"fmt"
	"strings"
)

const alphabet = "0123456789bcdefghjkmnpqrstuvwxyz"

// MaxPrecision is the deepest precision supported (12 chars = 60 bits, far below
// the float64 / sub-centimetre limit).
const MaxPrecision = 12

// Location is the decoded view of a geohash.
type Location struct {
	Geohash   string  `json:"geohash"`
	Precision int     `json:"precision"` // number of characters
	Lat       float64 `json:"lat"`       // cell center
	Lon       float64 `json:"lon"`
	LatErr    float64 `json:"lat_err"` // ± half-cell
	LonErr    float64 `json:"lon_err"`
	MinLat    float64 `json:"min_lat"`
	MaxLat    float64 `json:"max_lat"`
	MinLon    float64 `json:"min_lon"`
	MaxLon    float64 `json:"max_lon"`
}

// Decode parses a geohash into its cell center, ± error, and bounding box.
func Decode(gh string) (*Location, error) {
	g := strings.TrimSpace(gh)
	if g == "" {
		return nil, fmt.Errorf("geohash: empty geohash")
	}
	if len(g) > MaxPrecision {
		return nil, fmt.Errorf("geohash: %q has %d chars; the supported maximum is %d", gh, len(g), MaxPrecision)
	}
	latMin, latMax := -90.0, 90.0
	lonMin, lonMax := -180.0, 180.0
	isLon := true
	for i := 0; i < len(g); i++ {
		cd := strings.IndexByte(alphabet, lower(g[i]))
		if cd < 0 {
			return nil, fmt.Errorf("geohash: character %q is not in the base-32 alphabet (no a/i/l/o)", string(g[i]))
		}
		for bit := 4; bit >= 0; bit-- {
			b := (cd >> uint(bit)) & 1
			if isLon {
				mid := (lonMin + lonMax) / 2
				if b == 1 {
					lonMin = mid
				} else {
					lonMax = mid
				}
			} else {
				mid := (latMin + latMax) / 2
				if b == 1 {
					latMin = mid
				} else {
					latMax = mid
				}
			}
			isLon = !isLon
		}
	}
	return &Location{
		Geohash:   g,
		Precision: len(g),
		Lat:       (latMin + latMax) / 2,
		Lon:       (lonMin + lonMax) / 2,
		LatErr:    (latMax - latMin) / 2,
		LonErr:    (lonMax - lonMin) / 2,
		MinLat:    latMin, MaxLat: latMax, MinLon: lonMin, MaxLon: lonMax,
	}, nil
}

// Encode renders (lat, lon) as a geohash of the given character precision
// (1..MaxPrecision). precision<=0 defaults to 9 (≈ 4.8 m cells).
func Encode(lat, lon float64, precision int) (string, error) {
	if precision <= 0 {
		precision = 9
	}
	if precision > MaxPrecision {
		return "", fmt.Errorf("geohash: precision %d exceeds the supported maximum of %d", precision, MaxPrecision)
	}
	if lat < -90 || lat > 90 {
		return "", fmt.Errorf("geohash: latitude %.6f out of range (-90..90)", lat)
	}
	if lon < -180 || lon > 180 {
		return "", fmt.Errorf("geohash: longitude %.6f out of range (-180..180)", lon)
	}
	latMin, latMax := -90.0, 90.0
	lonMin, lonMax := -180.0, 180.0
	isLon := true
	var b strings.Builder
	ch, bits := 0, 0
	for b.Len() < precision {
		if isLon {
			mid := (lonMin + lonMax) / 2
			if lon >= mid {
				ch = ch<<1 | 1
				lonMin = mid
			} else {
				ch <<= 1
				lonMax = mid
			}
		} else {
			mid := (latMin + latMax) / 2
			if lat >= mid {
				ch = ch<<1 | 1
				latMin = mid
			} else {
				ch <<= 1
				latMax = mid
			}
		}
		isLon = !isLon
		bits++
		if bits == 5 {
			b.WriteByte(alphabet[ch])
			ch, bits = 0, 0
		}
	}
	return b.String(), nil
}

func lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}
