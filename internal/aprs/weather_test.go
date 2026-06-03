// SPDX-License-Identifier: AGPL-3.0-or-later

package aprs

import (
	"strconv"
	"testing"
)

func iptr(v int) *int         { return &v }
func fptr(v float64) *float64 { return &v }

// TestWeatherCanonicalExample decodes the exact APRS101 §12 canonical
// positionless weather report, anchoring every field against the spec's own
// worked example:
//
//	_10090556c220s004g005t077r000p000P000h50b09900wRSW
func TestWeatherCanonicalExample(t *testing.T) {
	f, err := Decode("N0CALL>APRS:_10090556c220s004g005t077r000p000P000h50b09900wRSW")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if f.InfoType != "_" {
		t.Fatalf("InfoType = %q, want _", f.InfoType)
	}
	w := f.Weather
	if w == nil {
		t.Fatal("Weather is nil")
	}
	if w.Timestamp != "10090556" {
		t.Errorf("Timestamp = %q, want 10090556", w.Timestamp)
	}
	checkInt(t, "wind_direction_deg", w.WindDirectionDeg, iptr(220))
	checkInt(t, "wind_speed_mph", w.WindSpeedMph, iptr(4))
	checkInt(t, "gust_mph", w.GustMph, iptr(5))
	checkInt(t, "temperature_f", w.TemperatureF, iptr(77))
	checkFloat(t, "rain_last_hour_in", w.RainLastHourIn, fptr(0))
	checkFloat(t, "rain_last_24h_in", w.RainLast24hIn, fptr(0))
	checkFloat(t, "rain_since_midnight_in", w.RainSinceMidnightIn, fptr(0))
	checkInt(t, "humidity_pct", w.HumidityPct, iptr(50))
	checkFloat(t, "pressure_hpa", w.PressureHpa, fptr(990.0))
	if w.Raw != "wRSW" {
		t.Errorf("Raw = %q, want wRSW (software+unit trailer)", w.Raw)
	}
}

// TestWeatherNonZeroValues exercises real readings (not all zeros) so the
// hundredths→inches and tenths→hPa scaling is verified, plus humidity 00=100%
// and a below-zero temperature.
func TestWeatherNonZeroValues(t *testing.T) {
	// t-05 = -5°F, r012 = 0.12 in, h00 = 100%, b10134 = 1013.4 hPa.
	f, err := Decode("WX>APRS:_01011200c090s012g025t-05r012p034P056h00b10134")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	w := f.Weather
	checkInt(t, "wind_direction_deg", w.WindDirectionDeg, iptr(90))
	checkInt(t, "wind_speed_mph", w.WindSpeedMph, iptr(12))
	checkInt(t, "gust_mph", w.GustMph, iptr(25))
	checkInt(t, "temperature_f", w.TemperatureF, iptr(-5))
	checkFloat(t, "rain_last_hour_in", w.RainLastHourIn, fptr(0.12))
	checkFloat(t, "rain_last_24h_in", w.RainLast24hIn, fptr(0.34))
	checkFloat(t, "rain_since_midnight_in", w.RainSinceMidnightIn, fptr(0.56))
	checkInt(t, "humidity_pct", w.HumidityPct, iptr(100)) // h00 → 100%
	checkFloat(t, "pressure_hpa", w.PressureHpa, fptr(1013.4))
}

// TestWeatherUnknownSensors confirms the '...' absent-sensor placeholders
// decode to nil (not zero), per the APRS101 example _10090556c...s...g...t...P012Jim.
func TestWeatherUnknownSensors(t *testing.T) {
	f, err := Decode("RAINWX>APRS:_10090556c...s...g...t...P012Jim")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	w := f.Weather
	if w.WindDirectionDeg != nil || w.WindSpeedMph != nil || w.GustMph != nil || w.TemperatureF != nil {
		t.Errorf("unknown-sensor fields should be nil, got dir=%v spd=%v gust=%v temp=%v",
			w.WindDirectionDeg, w.WindSpeedMph, w.GustMph, w.TemperatureF)
	}
	checkFloat(t, "rain_since_midnight_in", w.RainSinceMidnightIn, fptr(0.12))
	if w.Raw != "Jim" {
		t.Errorf("Raw = %q, want Jim", w.Raw)
	}
}

// TestWeatherLuminosity covers the L (≤999) and l (≥1000) luminosity forms.
func TestWeatherLuminosity(t *testing.T) {
	lo, _ := Decode("S>APRS:_01010000c000s000g000t050L123")
	checkInt(t, "luminosity_wm2 (L)", lo.Weather.LuminosityWm2, iptr(123))
	hi, _ := Decode("S>APRS:_01010000c000s000g000t050l050") // l050 → 1050
	checkInt(t, "luminosity_wm2 (l)", hi.Weather.LuminosityWm2, iptr(1050))
}

// TestWeatherSnowfallLeftRaw confirms the under-specified snowfall 's' in the
// optional tail is surfaced raw, never decoded into a possibly-wrong number.
func TestWeatherSnowfallLeftRaw(t *testing.T) {
	f, _ := Decode("S>APRS:_01010000c000s000g000t032s010")
	if f.Weather.Raw != "s010" {
		t.Errorf("tail snowfall should be raw, Raw = %q want s010", f.Weather.Raw)
	}
}

// TestCompleteWeatherCanonicalExample decodes the exact APRS101 §12
// "Complete Weather Report — Lat/Long, no Timestamp" example, anchoring the
// ddd/sss wind extension + position + weather fields:
//
//	!4903.50N/07201.75W_220/004g005t077r000p000P000h50b09900wRSW
func TestCompleteWeatherCanonicalExample(t *testing.T) {
	f, err := Decode("WX>APRS:!4903.50N/07201.75W_220/004g005t077r000p000P000h50b09900wRSW")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if f.Position == nil || f.Position.SymbolCode != "_" {
		t.Fatalf("expected weather-station position, got %+v", f.Position)
	}
	w := f.Weather
	if w == nil {
		t.Fatal("Weather is nil for a '_'-symbol position report")
	}
	checkInt(t, "wind_direction_deg", w.WindDirectionDeg, iptr(220))
	checkInt(t, "wind_speed_mph", w.WindSpeedMph, iptr(4))
	checkInt(t, "gust_mph", w.GustMph, iptr(5))
	checkInt(t, "temperature_f", w.TemperatureF, iptr(77))
	checkFloat(t, "rain_last_hour_in", w.RainLastHourIn, fptr(0))
	checkInt(t, "humidity_pct", w.HumidityPct, iptr(50))
	checkFloat(t, "pressure_hpa", w.PressureHpa, fptr(990.0))
	if w.Raw != "wRSW" {
		t.Errorf("Raw = %q, want wRSW", w.Raw)
	}
	// The weather data must not leak into the free-text comment.
	if f.Comment != "" {
		t.Errorf("Comment should be empty for a complete weather report, got %q", f.Comment)
	}
}

// TestCompleteWeatherTimestamped decodes the APRS101 §12 timestamped example
// (with a below-zero temperature):
//
//	@092345z4903.50N/07201.75W_220/004g005t-07r000p000P000h50b09900wRSW
func TestCompleteWeatherTimestamped(t *testing.T) {
	f, err := Decode("WX>APRS:@092345z4903.50N/07201.75W_220/004g005t-07r000p000P000h50b09900wRSW")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if f.Position == nil || f.Position.Timestamp != "092345z" {
		t.Fatalf("timestamp not preserved: %+v", f.Position)
	}
	w := f.Weather
	if w == nil {
		t.Fatal("Weather is nil")
	}
	checkInt(t, "wind_direction_deg", w.WindDirectionDeg, iptr(220))
	checkInt(t, "temperature_f", w.TemperatureF, iptr(-7))
	checkFloat(t, "pressure_hpa", w.PressureHpa, fptr(990.0))
}

// TestCompleteWeatherGate confirms a '_'-symbol position carrying a free-text
// comment (no ddd/sss wind extension) is NOT mis-parsed as weather.
func TestCompleteWeatherGate(t *testing.T) {
	f, err := Decode("WX>APRS:!4903.50N/07201.75W_Just a comment")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if f.Weather != nil {
		t.Errorf("non-weather '_' position must not produce Weather, got %+v", f.Weather)
	}
	if f.Comment != "Just a comment" {
		t.Errorf("Comment = %q, want 'Just a comment'", f.Comment)
	}
}

// TestWeatherShortTrailingField pins the fix for a recognised field code
// whose value is too short to consume (e.g. "L3"): the decoder must surface
// it raw and terminate, not spin forever re-reading the same code byte
// (regression for the fuzz-found liveness bug, seed 766c72891564fcd2).
func TestWeatherShortTrailingField(t *testing.T) {
	f, err := Decode("S>APRS:_01010000c000s000g000t050L3")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if f.Weather == nil || f.Weather.Raw != "L3" {
		t.Errorf("short trailing field: want Raw=L3, got %+v", f.Weather)
	}
	if f.Weather.LuminosityWm2 != nil {
		t.Errorf("malformed luminosity must not decode, got %v", *f.Weather.LuminosityWm2)
	}
}

// TestWeatherShortBody must not panic on a truncated report.
func TestWeatherShortBody(t *testing.T) {
	f, err := Decode("S>APRS:_1009")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if f.Weather == nil || f.Weather.Raw != "1009" {
		t.Errorf("short body: want Raw=1009, got %+v", f.Weather)
	}
}

func checkInt(t *testing.T, name string, got, want *int) {
	t.Helper()
	switch {
	case got == nil && want == nil:
	case got == nil || want == nil:
		t.Errorf("%s: got %v, want %v", name, ptrIntStr(got), ptrIntStr(want))
	case *got != *want:
		t.Errorf("%s: got %d, want %d", name, *got, *want)
	}
}

func checkFloat(t *testing.T, name string, got, want *float64) {
	t.Helper()
	switch {
	case got == nil && want == nil:
	case got == nil || want == nil:
		t.Errorf("%s: got %v, want %v", name, got, want)
	case *got != *want:
		t.Errorf("%s: got %g, want %g", name, *got, *want)
	}
}

func ptrIntStr(p *int) string {
	if p == nil {
		return "nil"
	}
	return strconv.Itoa(*p)
}
