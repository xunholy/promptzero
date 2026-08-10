// SPDX-License-Identifier: AGPL-3.0-or-later

package adsb

// BDS 4,5 — Meteorological Hazard Report (MHR). The companion to BDS 4,4:
// a Comm-B register carrying discrete in-flight hazard levels
// (turbulence, wind shear, microburst, icing, wake vortex) plus static
// air temperature, static pressure, and radio height.
//
// Like BDS 4,4 this is an EXPLICIT decode kept OUT of decodeCommB's
// automatic inference (meteorological registers are heuristic to
// identify): the caller asserts the register and IsBDS45 is reported as a
// confidence signal. Field layout, scaling, and the validity heuristic are
// ported from pyModeS v3 (decoder/bds/bds45.py), which fixes two v2 bugs
// this port also avoids: the static air temperature is honoured only when
// its status bit is set, and a BDS 1,7 (GICB capability) look-alike is
// rejected via the shared is17 gate. Bit numbers in comments are 1-indexed
// to match the ICAO Doc 9871 spec table; extractBits takes the 0-indexed
// start.

// BDS45 is the decoded Meteorological Hazard Report. Each hazard level is
// 0=NIL / 1=Light / 2=Moderate / 3=Severe, set only when its status bit is
// present.
type BDS45 struct {
	Turbulence     *int   `json:"turbulence,omitempty"`
	TurbulenceName string `json:"turbulence_name,omitempty"`
	WindShear      *int   `json:"wind_shear,omitempty"`
	WindShearName  string `json:"wind_shear_name,omitempty"`
	Microburst     *int   `json:"microburst,omitempty"`
	MicroburstName string `json:"microburst_name,omitempty"`
	Icing          *int   `json:"icing,omitempty"`
	IcingName      string `json:"icing_name,omitempty"`
	WakeVortex     *int   `json:"wake_vortex,omitempty"`
	WakeVortexName string `json:"wake_vortex_name,omitempty"`
	// StaticAirTemperatureC is gated by its status bit (bit 16); nil when
	// absent (the v2-vs-v3 fix — v2 reported it unconditionally).
	StaticAirTemperatureC *float64 `json:"static_air_temperature_c,omitempty"`
	StaticPressureHpa     *int     `json:"static_pressure_hpa,omitempty"`
	// RadioHeightFt is the height above terrain, gated by its status bit.
	RadioHeightFt *int `json:"radio_height_ft,omitempty"`
	// IsBDS45 is pyModeS v3's is_bds45 heuristic: status/field
	// consistency for all 8 fields, a zero 5-bit reserved tail, a
	// temperature in [-80,60] when present, and NOT a BDS 1,7 look-alike.
	// False means the field is unlikely to be a genuine MHR.
	IsBDS45 bool `json:"is_bds45"`
}

// hazardNames is the shared 2-bit hazard scale used by every BDS 4,5
// hazard field (ICAO Doc 9871).
var hazardNames = [...]string{"NIL", "Light", "Moderate", "Severe"} //nolint:gochecknoglobals

// DecodeBDS45 decodes a 7-byte (56-bit) Comm-B MB field as BDS 4,5. It
// always returns a decode (the caller has asserted the register); consult
// IsBDS45 for whether the field passes the MHR plausibility checks.
func DecodeBDS45(mb []byte) *BDS45 {
	if len(mb) < 7 {
		return nil
	}
	b := &BDS45{}

	// Five hazard fields: each is a status bit followed by a 2-bit level.
	if extractBits(mb, 0, 1) == 1 {
		b.Turbulence, b.TurbulenceName = hazard(mb, 1)
	}
	if extractBits(mb, 3, 1) == 1 {
		b.WindShear, b.WindShearName = hazard(mb, 4)
	}
	if extractBits(mb, 6, 1) == 1 {
		b.Microburst, b.MicroburstName = hazard(mb, 7)
	}
	if extractBits(mb, 9, 1) == 1 {
		b.Icing, b.IcingName = hazard(mb, 10)
	}
	if extractBits(mb, 12, 1) == 1 {
		b.WakeVortex, b.WakeVortexName = hazard(mb, 13)
	}
	// Temperature: status bit 16 (0-indexed 15), sign bit 17, 9-bit
	// magnitude bits 18-26, 0.25 C/LSB. Present only when status is set.
	if extractBits(mb, 15, 1) == 1 {
		t := temp45(mb)
		b.StaticAirTemperatureC = &t
	}
	// Static pressure: status bit 27 (0-indexed 26) gates bits 28-38.
	if extractBits(mb, 26, 1) == 1 {
		p := extractBits(mb, 27, 11)
		b.StaticPressureHpa = &p
	}
	// Radio height: status bit 39 (0-indexed 38) gates bits 40-51, 16 ft/LSB.
	if extractBits(mb, 38, 1) == 1 {
		rh := extractBits(mb, 39, 12) * 16
		b.RadioHeightFt = &rh
	}

	b.IsBDS45 = is45(mb)
	return b
}

// hazard reads a 2-bit hazard level at the 0-indexed bit position and
// returns it with its name.
func hazard(mb []byte, startBit int) (*int, string) {
	level := extractBits(mb, startBit, 2)
	return &level, hazardNames[level]
}

// temp45 decodes the BDS 4,5 static air temperature: sign bit 17 (0-indexed
// 16) + 9-bit magnitude bits 18-26, 0.25 C per LSB.
func temp45(mb []byte) float64 {
	sign := extractBits(mb, 16, 1)
	value := extractBits(mb, 17, 9)
	if sign == 1 {
		value -= 512
	}
	return float64(value) * 0.25
}

// is45 mirrors pyModeS v3 is_bds45. Bit numbers are 1-indexed to match the
// spec and the package's wrongStatus helper.
func is45(mb []byte) bool {
	if commbAllZero(mb) {
		return false
	}
	// Disambiguate from BDS 1,7 (GICB capability report): a 1,7 payload
	// trivially satisfies 4,5's reserved/status heuristics, so the more
	// specific 1,7 pattern wins.
	if is17(mb) {
		return false
	}
	// Reserved: bits 52-56 (0-indexed 51-55) must be zero.
	if extractBits(mb, 51, 5) != 0 {
		return false
	}
	// Status/field consistency for all eight gated fields.
	if wrongStatus(mb, 1, 2, 3) || // turbulence
		wrongStatus(mb, 4, 5, 6) || // wind shear
		wrongStatus(mb, 7, 8, 9) || // microburst
		wrongStatus(mb, 10, 11, 12) || // icing
		wrongStatus(mb, 13, 14, 15) || // wake vortex
		wrongStatus(mb, 16, 17, 26) || // temperature (sign + 9-bit magnitude)
		wrongStatus(mb, 27, 28, 38) || // static pressure
		wrongStatus(mb, 39, 40, 51) { // radio height
		return false
	}
	// Temperature range only checked when its status bit is set.
	if extractBits(mb, 15, 1) == 1 {
		temp := temp45(mb)
		if temp < -80 || temp > 60 {
			return false
		}
	}
	return true
}
