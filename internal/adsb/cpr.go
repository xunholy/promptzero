// SPDX-License-Identifier: AGPL-3.0-or-later

package adsb

import (
	"fmt"
	"math"
)

// GlobalPosition is the resolved output of pairing an even and an odd
// airborne-position frame.
type GlobalPosition struct {
	ICAOAddress string  `json:"icao_address,omitempty"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	// Reference names how the coordinate was resolved: "even" or "odd"
	// for a global even/odd pair (the reported fix is that frame's
	// instant, since the two are captured moments apart), or "local" for
	// a single-frame decode against a supplied reference position.
	Reference  string `json:"reference"`
	AltitudeFt *int   `json:"altitude_ft,omitempty"`
}

// GlobalPositionFromFrames decodes an even-format and an odd-format
// airborne-position hex frame and resolves their shared coordinate with
// no reference position. evenRecent picks which frame's instant to report
// (true = even, false = odd). It refuses — rather than emit a wrong fix —
// when a frame is not an airborne-position message, when the two are not
// one even + one odd, when they are from different aircraft, or when the
// pair straddles a latitude-zone boundary and cannot be resolved.
func GlobalPositionFromFrames(evenHex, oddHex string, evenRecent bool) (*GlobalPosition, error) {
	e, err := airbornePositionOf(evenHex)
	if err != nil {
		return nil, fmt.Errorf("even frame: %w", err)
	}
	o, err := airbornePositionOf(oddHex)
	if err != nil {
		return nil, fmt.Errorf("odd frame: %w", err)
	}
	if e.pos.CPRFormat != 0 {
		return nil, fmt.Errorf("even frame has CPR format %d, expected 0 (even)", e.pos.CPRFormat)
	}
	if o.pos.CPRFormat != 1 {
		return nil, fmt.Errorf("odd frame has CPR format %d, expected 1 (odd)", o.pos.CPRFormat)
	}
	if e.icao != "" && o.icao != "" && e.icao != o.icao {
		return nil, fmt.Errorf("frames are from different aircraft (%s vs %s) — not a valid CPR pair", e.icao, o.icao)
	}

	lat, lon, ok := GlobalAirbornePosition(e.pos.CPRLatRaw, e.pos.CPRLonRaw, o.pos.CPRLatRaw, o.pos.CPRLonRaw, evenRecent)
	if !ok {
		return nil, fmt.Errorf("CPR pair cannot be resolved (latitude-zone boundary straddle or out-of-range) — wait for a fresh even/odd pair")
	}

	gp := &GlobalPosition{
		ICAOAddress: firstNonEmpty(e.icao, o.icao),
		Latitude:    lat,
		Longitude:   lon,
		Reference:   "odd",
	}
	ref := o
	if evenRecent {
		gp.Reference, ref = "even", e
	}
	if ref.pos.AltitudeValid {
		alt := ref.pos.AltitudeFt
		gp.AltitudeFt = &alt
	}
	return gp, nil
}

// airbornePos couples a decoded airborne-position body with its ICAO.
type airbornePos struct {
	pos  *AirbornePosition
	icao string
}

// airbornePositionOf decodes a hex frame and returns its airborne-position
// body, erroring if the frame is not a TC 9-18/20-22 airborne-position
// message.
func airbornePositionOf(hexFrame string) (airbornePos, error) {
	f, err := Decode(hexFrame)
	if err != nil {
		return airbornePos{}, err
	}
	if f.ADSB == nil || f.ADSB.AirbornePosition == nil {
		return airbornePos{}, fmt.Errorf("not an airborne-position message (need ADS-B TC 9-18/20-22)")
	}
	return airbornePos{pos: f.ADSB.AirbornePosition, icao: f.ICAOAddress}, nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// Compact Position Reporting (CPR) global decode — the reference-free half
// of ADS-B position that the frame decoder deliberately leaves to a
// higher layer (see the package doc). Given one even-format and one
// odd-format airborne-position frame's raw 17-bit CPR latitude/longitude,
// GlobalAirbornePosition recovers an unambiguous WGS-84 lat/lon with no
// prior reference position — this is what pairs the two raw CPR values the
// Frame decoder surfaces into an actual coordinate.
//
// Native, from the published algorithm (ICAO Annex 10 / DO-260B, as laid
// out in Junzi Sun's "The 1090 MHz Riddle"): the NL longitude-zone count
// via the arccos formula, the latitude-index j, and the longitude-index
// m — pure float maths, no dependency. Airborne only; surface CPR (which
// uses a 90° latitude span and a reference quadrant) is out of scope.
//
// Anchored to the canonical worked example: even (93000, 51372) + odd
// (74158, 50194) resolve to 52.2572°, 3.91937°.

// cprNZ is the number of geographic latitude zones between the equator and
// a pole in the CPR grid — 15, fixed by the spec.
const cprNZ = 15

// cprNL returns NL(lat): the number of longitude zones at latitude lat.
// It follows the ICAO transition-latitude formula rather than the 59-row
// lookup table — the two agree exactly, and the formula is self-evidently
// the spec. The polar and equatorial special cases avoid the formula's
// singularities (acos domain at the poles, division shape at the equator).
func cprNL(lat float64) int {
	lat = math.Abs(lat)
	switch {
	case lat == 0:
		return 59
	case lat >= 87:
		// 87.0 exactly maps to 2; anything strictly poleward is 1.
		if lat == 87 {
			return 2
		}
		return 1
	}
	a := 1 - math.Cos(math.Pi/(2*cprNZ))
	b := math.Cos(math.Pi/180*lat) * math.Cos(math.Pi/180*lat)
	return int(math.Floor(2 * math.Pi / math.Acos(1-a/b)))
}

// GlobalAirbornePosition recovers a WGS-84 latitude/longitude from a paired
// even/odd airborne-position message using their raw 17-bit CPR values.
// evenRecent selects which frame is the more recent (its coordinate is the
// one reported): true reports the even frame's position, false the odd's —
// the caller knows the arrival order.
//
// ok is false when the two frames straddle a latitude-zone boundary
// (NL(lat_even) != NL(lat_odd)); such a pair cannot be resolved and the
// caller must wait for a fresh pair rather than emit a wrong fix. Latitudes
// are validated to the legal ±90° range for the same reason.
func GlobalAirbornePosition(latCPREven, lonCPREven, latCPROdd, lonCPROdd int, evenRecent bool) (lat, lon float64, ok bool) {
	const two17 = 131072.0 // 2^17

	latE := float64(latCPREven) / two17
	latO := float64(latCPROdd) / two17
	lonE := float64(lonCPREven) / two17
	lonO := float64(lonCPROdd) / two17

	const dLatEven = 360.0 / (4 * cprNZ)     // 6°
	const dLatOdd = 360.0 / (4*cprNZ - 1)    // 360/59
	j := math.Floor(59*latE - 60*latO + 0.5) // latitude-index

	latEven := dLatEven * (cprMod(j, 60) + latE)
	latOdd := dLatOdd * (cprMod(j, 59) + latO)
	// The southern hemisphere is encoded as [270,360); fold it to [-90,90).
	if latEven >= 270 {
		latEven -= 360
	}
	if latOdd >= 270 {
		latOdd -= 360
	}
	if math.Abs(latEven) > 90 || math.Abs(latOdd) > 90 {
		return 0, 0, false
	}
	// A boundary-straddling pair sits in different longitude-zone counts and
	// cannot be resolved — signal the caller to wait for a fresh pair.
	if cprNL(latEven) != cprNL(latOdd) {
		return 0, 0, false
	}

	if evenRecent {
		nl := cprNL(latEven)
		ni := maxInt(nl, 1)
		m := math.Floor(lonE*float64(nl-1) - lonO*float64(nl) + 0.5)
		lon = (360.0 / float64(ni)) * (cprMod(m, float64(ni)) + lonE)
		lat = latEven
	} else {
		nl := cprNL(latOdd)
		ni := maxInt(nl-1, 1)
		m := math.Floor(lonE*float64(nl-1) - lonO*float64(nl) + 0.5)
		lon = (360.0 / float64(ni)) * (cprMod(m, float64(ni)) + lonO)
		lat = latOdd
	}
	if lon >= 180 {
		lon -= 360
	}
	return lat, lon, true
}

// LocalAirbornePosition recovers a WGS-84 latitude/longitude from a single
// airborne-position frame's raw CPR values, disambiguated against a nearby
// reference position (refLat/refLon) instead of an even/odd pair. odd tells
// which CPR format the frame carries. This is what a receiver uses once it
// has any reference — its own site location, or a prior global fix — to get
// an immediate position from every frame without waiting to pair.
//
// The reference must be within ~180 NM (roughly 3°) of the true position:
// local CPR resolves the position within one grid zone, and a reference
// farther than half a zone away silently selects the wrong zone. The caller
// owns that guarantee (hence the explicit reference), so this returns a
// coordinate whenever the inputs are in range; ok is false only on an
// out-of-range reference or CPR value.
func LocalAirbornePosition(latCPR, lonCPR int, odd bool, refLat, refLon float64) (lat, lon float64, ok bool) {
	const two17 = 131072.0
	if math.Abs(refLat) > 90 || math.Abs(refLon) > 180 ||
		latCPR < 0 || latCPR >= 131072 || lonCPR < 0 || lonCPR >= 131072 {
		return 0, 0, false
	}
	latC := float64(latCPR) / two17
	lonC := float64(lonCPR) / two17

	i := 0.0
	if odd {
		i = 1.0
	}
	dLat := 360.0 / (4*cprNZ - i)
	j := math.Floor(refLat/dLat) + math.Floor(0.5+cprMod(refLat, dLat)/dLat-latC)
	lat = dLat * (j + latC)

	nl := float64(cprNL(lat))
	ni := nl - i
	if ni < 1 {
		ni = 1
	}
	dLon := 360.0 / ni
	m := math.Floor(refLon/dLon) + math.Floor(0.5+cprMod(refLon, dLon)/dLon-lonC)
	lon = dLon * (m + lonC)
	return lat, lon, true
}

// LocalPositionFromFrame decodes a single airborne-position hex frame and
// resolves its coordinate against refLat/refLon (see LocalAirbornePosition
// for the reference-range contract). It errors when the frame is not an
// airborne-position message or the reference is out of range.
func LocalPositionFromFrame(hexFrame string, refLat, refLon float64) (*GlobalPosition, error) {
	ap, err := airbornePositionOf(hexFrame)
	if err != nil {
		return nil, err
	}
	lat, lon, ok := LocalAirbornePosition(ap.pos.CPRLatRaw, ap.pos.CPRLonRaw, ap.pos.CPRFormat == 1, refLat, refLon)
	if !ok {
		return nil, fmt.Errorf("reference position out of range or CPR value invalid")
	}
	gp := &GlobalPosition{
		ICAOAddress: ap.icao,
		Latitude:    lat,
		Longitude:   lon,
		Reference:   "local",
	}
	if ap.pos.AltitudeValid {
		alt := ap.pos.AltitudeFt
		gp.AltitudeFt = &alt
	}
	return gp, nil
}

// cprMod is the CPR modulo: a floored (always-non-negative) modulus, unlike
// Go's truncated math.Mod, which the latitude/longitude indices require.
func cprMod(a, b float64) float64 {
	r := math.Mod(a, b)
	if r < 0 {
		r += b
	}
	return r
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
