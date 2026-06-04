// SPDX-License-Identifier: AGPL-3.0-or-later

// Package maidenhead converts between geographic coordinates and Maidenhead
// grid locators (a.k.a. QTH / grid squares, e.g. "FN31pr"), the location format
// used throughout amateur radio — in APRS, ham logging, contesting, and on the
// LCDs of many handheld/mobile rigs. It is the offline geo companion to the
// project's other ham/RF decoders (internal/aprs, internal/ais, internal/nmea):
// decode a locator from a logged QSO / beacon into latitude+longitude, or encode
// a fix into a locator to compare against one. Pure offline transform; no
// network or device.
//
// # Wrap-vs-native judgement
//
// Native. The Maidenhead system is a fully public, deterministic positional
// notation: alternating base-18 (field, letters A-R), base-10 (square, digits),
// and base-24 (subsquare, letters a-x) pairs subdividing a 360°×180° world grid.
// Encoding/decoding is a few lines of fixed-base arithmetic — there is nothing
// to wrap, and a third-party locator library would be a runtime dep for trivial
// math. Consistent with the other in-tree geo/ham transforms.
//
// # Verifiable / no confidently-wrong output
//
// Both directions are anchored to the reference `maidenhead` Python library:
// the canonical examples reproduce its output exactly — e.g. (41.714, -72.728)
// → "FN31pr" at 3-pair precision, "JN58td" ↔ (48.125, 11.5833) SW corner /
// (48.1458, 11.625) center, "JJ00aa" ↔ the equator/prime-meridian origin. Decode
// reports BOTH the grid square's south-west corner and its center, plus the cell
// size, so the precision is explicit and never overstated. A malformed locator
// (odd length, out-of-range field/square/subsquare character) is rejected.
package maidenhead

import (
	"fmt"
	"math"
	"strings"
)

// bases are the per-pair radices: field (A-R, 18), square (0-9, 10), subsquare
// (a-x, 24), extended (0-9, 10), then 24/10 repeating.
var bases = []int{18, 10, 24, 10, 24, 10, 24, 10}

// MaxPairs is the deepest precision supported (each pair = 2 characters).
const MaxPairs = 4

// Location is the decoded view of a Maidenhead locator.
type Location struct {
	Grid          string  `json:"grid"`
	Pairs         int     `json:"pairs"`
	CenterLat     float64 `json:"center_lat"`
	CenterLon     float64 `json:"center_lon"`
	CornerLat     float64 `json:"sw_corner_lat"`
	CornerLon     float64 `json:"sw_corner_lon"`
	CellHeightDeg float64 `json:"cell_height_deg"`
	CellWidthDeg  float64 `json:"cell_width_deg"`
}

// lonCell / latCell return the cell width (lon) and height (lat) at level i —
// the world span (360°/180°) divided by the product of the radices up to and
// including level i.
func lonCell(i int) float64 { return 360.0 / prodBases(i) }
func latCell(i int) float64 { return 180.0 / prodBases(i) }

func prodBases(i int) float64 {
	p := 1.0
	for k := 0; k <= i; k++ {
		p *= float64(bases[k])
	}
	return p
}

// Encode renders (lat, lon) as a Maidenhead locator of the given pair count
// (2 chars per pair; pairs 1..MaxPairs). pairs<=0 defaults to 3 (the common
// 6-character locator).
func Encode(lat, lon float64, pairs int) (string, error) {
	if pairs <= 0 {
		pairs = 3
	}
	if pairs > MaxPairs {
		return "", fmt.Errorf("maidenhead: precision %d pairs exceeds the supported maximum of %d", pairs, MaxPairs)
	}
	if lat < -90 || lat > 90 {
		return "", fmt.Errorf("maidenhead: latitude %.6f out of range (-90..90)", lat)
	}
	if lon < -180 || lon > 180 {
		return "", fmt.Errorf("maidenhead: longitude %.6f out of range (-180..180)", lon)
	}
	// Clamp the poles / antimeridian so floor() can't index one past the grid.
	lonRem := math.Min(lon+180, 360-1e-9)
	latRem := math.Min(lat+90, 180-1e-9)

	var b strings.Builder
	for i := 0; i < pairs; i++ {
		lw, lh := lonCell(i), latCell(i)
		lonIdx := int(math.Floor(lonRem / lw))
		latIdx := int(math.Floor(latRem / lh))
		lonRem -= float64(lonIdx) * lw
		latRem -= float64(latIdx) * lh
		b.WriteByte(emit(i, lonIdx))
		b.WriteByte(emit(i, latIdx))
	}
	return b.String(), nil
}

// emit renders index idx as the character for pair level i: uppercase letters
// for the field (level 0), digits for odd levels, lowercase letters for even
// levels > 0.
func emit(level, idx int) byte {
	switch {
	case level == 0:
		return byte('A' + idx)
	case level%2 == 1:
		return byte('0' + idx)
	default:
		return byte('a' + idx)
	}
}

// Decode parses a Maidenhead locator into its south-west corner, its center,
// and the cell size. Input is case-insensitive and may be 2..2*MaxPairs
// characters (an even length).
func Decode(grid string) (*Location, error) {
	g := strings.TrimSpace(grid)
	if g == "" {
		return nil, fmt.Errorf("maidenhead: empty locator")
	}
	if len(g)%2 != 0 {
		return nil, fmt.Errorf("maidenhead: locator %q has an odd length; it must be pairs of characters", grid)
	}
	pairs := len(g) / 2
	if pairs > MaxPairs {
		return nil, fmt.Errorf("maidenhead: locator %q has %d pairs; the supported maximum is %d", grid, pairs, MaxPairs)
	}

	lon, lat := -180.0, -90.0
	for i := 0; i < pairs; i++ {
		lonIdx, err := decodeChar(i, g[2*i])
		if err != nil {
			return nil, err
		}
		latIdx, err := decodeChar(i, g[2*i+1])
		if err != nil {
			return nil, err
		}
		lon += float64(lonIdx) * lonCell(i)
		lat += float64(latIdx) * latCell(i)
	}
	cw, ch := lonCell(pairs-1), latCell(pairs-1)
	return &Location{
		Grid:          canonical(g),
		Pairs:         pairs,
		CornerLat:     lat,
		CornerLon:     lon,
		CenterLat:     lat + ch/2,
		CenterLon:     lon + cw/2,
		CellHeightDeg: ch,
		CellWidthDeg:  cw,
	}, nil
}

// decodeChar maps a locator character at pair level i back to its index,
// validating it against that level's radix.
func decodeChar(level int, c byte) (int, error) {
	base := bases[level]
	var idx int
	switch level % 2 {
	case 1: // digit pair
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("maidenhead: expected a digit at position pair %d, got %q", level+1, string(c))
		}
		idx = int(c - '0')
	default: // letter pair (case-insensitive)
		u := c
		if u >= 'a' && u <= 'z' {
			u -= 'a' - 'A'
		}
		if u < 'A' || u > 'Z' {
			return 0, fmt.Errorf("maidenhead: expected a letter at position pair %d, got %q", level+1, string(c))
		}
		idx = int(u - 'A')
	}
	if idx >= base {
		return 0, fmt.Errorf("maidenhead: character %q is out of range for pair %d (radix %d)", string(c), level+1, base)
	}
	return idx, nil
}

// canonical re-cases a (validated) locator to convention: the field pair
// uppercase, digit pairs as-is, and letter subsquare/extended pairs lowercase.
func canonical(g string) string {
	out := []byte(strings.ToUpper(g))
	for i := 4; i < len(out); i++ {
		if (i/2)%2 == 0 { // even pair index > 0 → letter pair → lowercase
			if out[i] >= 'A' && out[i] <= 'Z' {
				out[i] += 'a' - 'A'
			}
		}
	}
	return string(out)
}
