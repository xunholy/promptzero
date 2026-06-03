// SPDX-License-Identifier: AGPL-3.0-or-later

package aprs

import (
	"strconv"
	"strings"
)

// Weather is the decoded APRS positionless weather report (APRS101 §12).
//
// Every measurement is a pointer so an absent or unknown-sensor field
// (encoded as '...' or spaces in the wire format) is distinguishable from a
// genuine zero. Under-specified fields (snowfall, the '#' raw rain counter,
// and the trailing software / WX-unit code) are not decoded into numbers —
// they are left verbatim in Raw so a wrong scaling can never be asserted.
type Weather struct {
	// Timestamp is the 8-char MDHM (month-day-hour-minute) stamp.
	Timestamp string `json:"timestamp,omitempty"`

	WindDirectionDeg *int `json:"wind_direction_deg,omitempty"`
	WindSpeedMph     *int `json:"wind_speed_mph,omitempty"`
	GustMph          *int `json:"gust_mph,omitempty"`
	TemperatureF     *int `json:"temperature_f,omitempty"`

	RainLastHourIn      *float64 `json:"rain_last_hour_in,omitempty"`
	RainLast24hIn       *float64 `json:"rain_last_24h_in,omitempty"`
	RainSinceMidnightIn *float64 `json:"rain_since_midnight_in,omitempty"`

	HumidityPct   *int     `json:"humidity_pct,omitempty"`
	PressureHpa   *float64 `json:"pressure_hpa,omitempty"`
	LuminosityWm2 *int     `json:"luminosity_wm2,omitempty"`

	// Raw is any trailing data after the decoded weather fields — the
	// APRS-software type + WX-unit code (e.g. "wRSW"), snowfall, the '#'
	// raw rain counter, or a free-text comment. Surfaced verbatim.
	Raw string `json:"raw,omitempty"`
}

// decodeWeatherPositionless parses the positionless weather report body (the
// bytes after the '_' Data Type Identifier): an 8-char MDHM timestamp, the
// mandatory wind-direction / wind-speed / gust / temperature head (fixed
// order, so the leading 's' is unambiguously wind speed rather than
// snowfall), then any of the optional r/p/P/h/b/L/l fields in any order, with
// the remainder surfaced raw.
func decodeWeatherPositionless(f *Frame, body string) error {
	w := &Weather{}
	f.Weather = w

	// MDHM timestamp (8 chars). If the body is too short to carry the
	// mandatory head, record whatever timestamp is present and stop.
	if len(body) >= 8 {
		w.Timestamp = body[:8]
		body = body[8:]
	} else {
		w.Raw = body
		return nil
	}

	// Mandatory head, fixed order: c<dir> s<spd>, then the shared
	// gust/temp/optional tail.
	body = consumeIntField(body, 'c', 3, func(v *int) { w.WindDirectionDeg = v })
	body = consumeIntField(body, 's', 3, func(v *int) { w.WindSpeedMph = v })
	parseWeatherTail(w, body)
	return nil
}

// decodeCompleteWeather parses the weather data of a Complete Weather Report
// (APRS101 §12) — the bytes after a position report's '_' symbol code. The
// spec replaces the positionless cccc/ssss fields with a 7-byte
// "ddd/sss" Wind Direction/Speed Data Extension; gust, temperature and the
// optional fields then follow exactly as in the positionless form. It returns
// false (consuming nothing) when the data does not begin with the ddd/sss
// extension, so a plain '_'-symbol position carrying a free-text comment is
// not mis-parsed as weather.
func decodeCompleteWeather(f *Frame, data string) bool {
	dir, spd, rest, ok := splitWindExtension(data)
	if !ok {
		return false
	}
	w := &Weather{
		WindDirectionDeg: numericOrNil(dir),
		WindSpeedMph:     numericOrNil(spd),
	}
	parseWeatherTail(w, rest)
	f.Weather = w
	return true
}

// splitWindExtension matches the 7-byte "ddd/sss" wind direction/speed data
// extension at the start of data (each of ddd and sss being 3 digits, or dots
// / spaces for an absent sensor). It returns the dir and speed value chars and
// the remaining bytes.
func splitWindExtension(data string) (dir, spd, rest string, ok bool) {
	if len(data) < 7 || data[3] != '/' {
		return "", "", data, false
	}
	d, s := data[:3], data[4:7]
	if !looksLikeWindField(d) || !looksLikeWindField(s) {
		return "", "", data, false
	}
	return d, s, data[7:], true
}

// looksLikeWindField reports whether a 3-char field is either all digits or an
// absent-sensor placeholder (dots/spaces) — the only forms the spec allows for
// the ddd/sss extension. This keeps a course/speed on a non-weather symbol
// from being misread as wind data.
func looksLikeWindField(s string) bool {
	if len(s) != 3 {
		return false
	}
	digits, placeholder := 0, 0
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] >= '0' && s[i] <= '9':
			digits++
		case s[i] == '.' || s[i] == ' ':
			placeholder++
		default:
			return false
		}
	}
	return digits == 3 || placeholder == 3
}

// parseWeatherTail parses the portion of a weather report common to both the
// positionless and complete forms: the mandatory gust (g) and temperature (t)
// fields, then the optional r/p/P/h/b/L/l fields in any order, with the
// remainder (software/WX-unit trailer, snowfall, '#' counter, comment)
// surfaced verbatim in w.Raw.
func parseWeatherTail(w *Weather, body string) {
	body = consumeIntField(body, 'g', 3, func(v *int) { w.GustMph = v })
	body = consumeTempField(body, w)

	// Optional fields, any order, until an unrecognised code is hit.
	for len(body) > 0 {
		before := len(body)
		switch body[0] {
		case 'r':
			body = consumeRainField(body, 'r', func(v *float64) { w.RainLastHourIn = v })
		case 'p':
			body = consumeRainField(body, 'p', func(v *float64) { w.RainLast24hIn = v })
		case 'P':
			body = consumeRainField(body, 'P', func(v *float64) { w.RainSinceMidnightIn = v })
		case 'h':
			body = consumeHumidity(body, w)
		case 'b':
			body = consumePressure(body, w)
		case 'L':
			body = consumeLuminosity(body, 'L', 0, w)
		case 'l':
			body = consumeLuminosity(body, 'l', 1000, w)
		}
		// A recognised code whose field is too short to consume (or any
		// unrecognised code — snowfall 's', the '#' raw counter, the
		// software/unit trailer, a comment) makes no progress: surface the
		// remainder verbatim and stop, rather than guessing or looping.
		if len(body) == before {
			w.Raw = body
			return
		}
	}
}

// splitField returns the n value chars following a leading code byte, the
// rest of the body, and whether the field was present. ok is false when the
// leading byte does not match or the body is too short — in that case rest is
// the original body so the caller leaves the input unconsumed.
func splitField(body string, code byte, n int) (val, rest string, ok bool) {
	if len(body) < 1+n || body[0] != code {
		return "", body, false
	}
	return body[1 : 1+n], body[1+n:], true
}

// numericOrNil parses val as an integer, returning nil when the field is an
// absent-sensor placeholder (dots/spaces) or otherwise non-numeric.
func numericOrNil(val string) *int {
	t := strings.TrimSpace(val)
	if t == "" || strings.Trim(t, ".") == "" {
		return nil
	}
	n, err := strconv.Atoi(t)
	if err != nil {
		return nil
	}
	return &n
}

func consumeIntField(body string, code byte, n int, set func(*int)) string {
	val, rest, ok := splitField(body, code, n)
	if !ok {
		return body
	}
	set(numericOrNil(val))
	return rest
}

// consumeTempField handles 't' + 3 chars, where a below-zero reading is the
// "-NN" form (APRS101: temperatures below zero are expressed as -01 to -99).
func consumeTempField(body string, w *Weather) string {
	val, rest, ok := splitField(body, 't', 3)
	if !ok {
		return body
	}
	t := strings.TrimSpace(val)
	if t == "" || strings.Trim(t, ".") == "" {
		return rest
	}
	if n, err := strconv.Atoi(t); err == nil {
		w.TemperatureF = &n
	}
	return rest
}

// consumeRainField handles r/p/P + 3 digits in hundredths of an inch.
func consumeRainField(body string, code byte, set func(*float64)) string {
	val, rest, ok := splitField(body, code, 3)
	if !ok {
		return body
	}
	if n := numericOrNil(val); n != nil {
		in := float64(*n) / 100.0
		set(&in)
	}
	return rest
}

// consumeHumidity handles 'h' + 2 digits, where 00 encodes 100%.
func consumeHumidity(body string, w *Weather) string {
	val, rest, ok := splitField(body, 'h', 2)
	if !ok {
		return body
	}
	if n := numericOrNil(val); n != nil {
		h := *n
		if h == 0 {
			h = 100
		}
		w.HumidityPct = &h
	}
	return rest
}

// consumePressure handles 'b' + 5 digits in tenths of hPa (millibars).
func consumePressure(body string, w *Weather) string {
	val, rest, ok := splitField(body, 'b', 5)
	if !ok {
		return body
	}
	if n := numericOrNil(val); n != nil {
		hpa := float64(*n) / 10.0
		w.PressureHpa = &hpa
	}
	return rest
}

// consumeLuminosity handles L (≤999) / l (≥1000, value = 1000+NNN) + 3 digits.
func consumeLuminosity(body string, code byte, base int, w *Weather) string {
	val, rest, ok := splitField(body, code, 3)
	if !ok {
		return body
	}
	if n := numericOrNil(val); n != nil {
		v := base + *n
		w.LuminosityWm2 = &v
	}
	return rest
}
