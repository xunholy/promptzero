// SPDX-License-Identifier: AGPL-3.0-or-later

package adsb

// BDS 4,4 — Meteorological Routine Air Report (MRAR). A Comm-B register
// some aircraft transmit carrying live wind, static air temperature,
// static pressure, turbulence, and humidity measured aloft — useful
// aviation-weather data the main frame decoder deliberately leaves out.
//
// Meteorological registers are NOT self-describing and are heuristic to
// identify, so — mirroring pyModeS, which hides BDS 4,4 from its default
// register inference — this is an EXPLICIT decode: the caller asserts the
// MB field is BDS 4,4 (e.g. an operator who knows the feed carries MRAR),
// and IsBDS44 is reported alongside as a confidence signal rather than a
// silent gate. It is deliberately absent from decodeCommB's automatic
// inference so a look-alike frame is never auto-labelled as weather.
//
// Field layout and scaling are ported verbatim from the ICAO Doc 9871
// BDS 4,4 table as implemented by pyModeS (decoder/bds/bds44.py). Bit
// numbers below are 1-indexed within the 56-bit MB field to match the
// spec table; extractBits takes the 0-indexed start.

// BDS44 is the decoded Meteorological Routine Air Report.
type BDS44 struct {
	// FigureOfMerit is the source/quality indicator (bits 1-4); values
	// above 4 are reserved and cause IsBDS44 to be false.
	FigureOfMerit int `json:"figure_of_merit"`
	// WindSpeedKt / WindDirectionDeg are set together, gated by the wind
	// status bit; nil when the status bit is clear.
	WindSpeedKt      *int     `json:"wind_speed_kt,omitempty"`
	WindDirectionDeg *float64 `json:"wind_direction_deg,omitempty"`
	// StaticAirTemperatureC is always present (the register carries no
	// temperature status bit); 11-bit two's complement at 0.25 C/LSB.
	StaticAirTemperatureC float64 `json:"static_air_temperature_c"`
	// StaticPressureHpa is gated by its status bit; nil when absent.
	StaticPressureHpa *int `json:"static_pressure_hpa,omitempty"`
	// Turbulence is gated by its status bit: 0=NIL, 1=Light, 2=Moderate,
	// 3=Severe; nil when absent.
	Turbulence     *int   `json:"turbulence,omitempty"`
	TurbulenceName string `json:"turbulence_name,omitempty"`
	// HumidityPct is gated by its status bit; nil when absent.
	HumidityPct *float64 `json:"humidity_pct,omitempty"`
	// IsBDS44 is pyModeS's is44 heuristic over this MB field: status/field
	// consistency, FOM<=4, wind<=250kt, temperature in [-80,60], and not
	// an all-zero meteo payload. False means the field is unlikely to be a
	// genuine MRAR — treat the decoded values as suspect.
	IsBDS44 bool `json:"is_bds44"`
}

var turbulenceNames = [...]string{"NIL", "Light", "Moderate", "Severe"} //nolint:gochecknoglobals

// DecodeBDS44 decodes a 7-byte (56-bit) Comm-B MB field as BDS 4,4. It
// always returns a decode (the caller has asserted the register); consult
// IsBDS44 for whether the field passes the MRAR plausibility checks.
func DecodeBDS44(mb []byte) *BDS44 {
	if len(mb) < 7 {
		return nil
	}
	b := &BDS44{
		FigureOfMerit:         extractBits(mb, 0, 4),
		StaticAirTemperatureC: temp44(mb),
	}

	// Wind: status bit 5 (0-indexed 4) gates speed (bits 6-14) + direction
	// (bits 15-23).
	if extractBits(mb, 4, 1) == 1 {
		speed := extractBits(mb, 5, 9)
		dir := float64(extractBits(mb, 14, 9)) * 180.0 / 256.0
		b.WindSpeedKt = &speed
		b.WindDirectionDeg = &dir
	}
	// Static pressure: status bit 35 (0-indexed 34) gates bits 36-46.
	if extractBits(mb, 34, 1) == 1 {
		p := extractBits(mb, 35, 11)
		b.StaticPressureHpa = &p
	}
	// Turbulence: status bit 47 (0-indexed 46) gates bits 48-49.
	if extractBits(mb, 46, 1) == 1 {
		t := extractBits(mb, 47, 2)
		b.Turbulence = &t
		b.TurbulenceName = turbulenceNames[t]
	}
	// Humidity: status bit 50 (0-indexed 49) gates bits 51-56.
	if extractBits(mb, 49, 1) == 1 {
		h := float64(extractBits(mb, 50, 6)) * 100.0 / 64.0
		b.HumidityPct = &h
	}

	b.IsBDS44 = is44(mb)
	return b
}

// temp44 decodes the static air temperature: 11-bit two's complement over
// bits 24-34 (0-indexed 23), 0.25 C per LSB.
func temp44(mb []byte) float64 {
	sign := extractBits(mb, 23, 1)
	value := extractBits(mb, 24, 10)
	if sign == 1 {
		value -= 1024
	}
	return float64(value) * 0.25
}

// is44 mirrors pyModeS bds44.is44: the heuristic that a 56-bit MB field is
// a genuine BDS 4,4 report. All bit numbers are 1-indexed to match the
// spec table and pyModeS.
func is44(mb []byte) bool {
	if commbAllZero(mb) {
		return false
	}
	// status/field consistency: a clear status bit with a non-zero field
	// is a contradiction.
	if wrongStatus(mb, 5, 6, 23) || // wind status gates speed+direction
		wrongStatus(mb, 35, 36, 46) || // pressure status gates pressure
		wrongStatus(mb, 47, 48, 49) || // turbulence status gates level
		wrongStatus(mb, 50, 51, 56) { // humidity status gates humidity
		return false
	}
	// Bits 1-4 (source / figure of merit) above 4 are reserved.
	if extractBits(mb, 0, 4) > 4 {
		return false
	}

	windValid := extractBits(mb, 4, 1) == 1
	speed := extractBits(mb, 5, 9)
	dir := extractBits(mb, 14, 9)
	if windValid && speed > 250 {
		return false
	}
	temp := temp44(mb)
	if temp < -80 || temp > 60 {
		return false
	}
	// An all-zero meteo payload (valid wind status but zero wind and zero
	// temperature) is more likely a non-MRAR frame.
	if windValid && speed == 0 && dir == 0 && temp == 0 {
		return false
	}
	// No wind at all (status clear) leaves nothing identifying.
	if !windValid {
		return false
	}
	return true
}
