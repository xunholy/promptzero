// Package dcf77 decodes DCF77 time-signal frames — the
// long-wave (77.5 kHz) radio broadcast from Mainflingen,
// Germany, that carries the current Central European time + date.
// Pure offline parser; no transport, no hardware.
//
// Wrap-vs-native judgement: the DCF77 frame format is a fully
// public spec (PTB / "Time signal and frequency standard
// DCF77", ETSI EN 300 220-1). The walker is bit-level decoding
// over a 60-bit frame with BCD-weighted time/date fields and
// three parity bits. Wrapping a FAP for this would require an
// SD-card install + a firmware-fork dependency for a pure
// parser. Native delivers offline analysis — operators paste a
// 60-bit DCF77 bit-stream captured by their SDR (rtl_sdr →
// gnuradio DCF77 block) or consumer radio-clock test pin and
// decode the time without running a fresh capture.
//
// What this package covers:
//   - 60-bit frame walker: header (start-of-minute marker,
//     weather, antenna-switch announcement, DST-change
//     announcement, CET/CEST indicator, leap-second
//     announcement), time field (start marker + 7-bit BCD
//     minutes + parity + 6-bit BCD hours + parity), date
//     field (6-bit BCD day-of-month + 3-bit BCD day-of-week +
//     5-bit BCD month + 8-bit BCD year + parity)
//   - BCD weighting per the official table (1+2+4+8+10+20+40+80)
//   - Even-parity validity checks for minutes / hours / date
//   - DST flag interpretation (CET vs CEST = UTC+1 vs UTC+2)
//   - Day-of-week mapping (1=Monday through 7=Sunday)
//
// What this package does NOT cover (deliberately out of scope):
//   - The first 14 bits (weather data) — encrypted by PTB,
//     surfaced as raw hex for cross-reference
//   - Demodulation / sync detection (operators bring the
//     pre-aligned 60-bit frame)
//   - Year-rollover detection (the 2-digit year wraps every
//     century — we surface the raw decode and let the caller
//     decide what century to apply)
package dcf77

import (
	"fmt"
	"strings"
)

// Frame is the top-level decoded DCF77 frame.
type Frame struct {
	// StartOfMinute is bit 0 — must be 0 per spec. Surfaced so
	// callers can flag malformed inputs.
	StartOfMinute bool `json:"start_of_minute_marker"`
	// WeatherDataHex is bits 1..14 — encrypted by PTB, surfaced
	// as 14-bit binary string for cross-reference.
	WeatherDataBits string `json:"weather_data_bits"`
	// AntennaSwitchAnnouncement (bit 15) — set when DCF77 is
	// about to switch from main to backup antenna in the next
	// hour.
	AntennaSwitchAnnouncement bool `json:"antenna_switch_announcement"`
	// DSTChangeAnnouncement (bit 16) — set when CET/CEST
	// transition will occur in the next hour.
	DSTChangeAnnouncement bool `json:"dst_change_announcement"`
	// CESTActive (bits 17..18) — true when CEST (UTC+2) is in
	// effect, false when CET (UTC+1).
	CESTActive bool `json:"cest_active"`
	// TimezoneOffsetHours is +1 for CET, +2 for CEST.
	TimezoneOffsetHours int `json:"timezone_offset_hours"`
	// LeapSecondAnnouncement (bit 19) — set when a leap second
	// will be inserted at end of the next hour.
	LeapSecondAnnouncement bool `json:"leap_second_announcement"`
	// StartOfTime (bit 20) — must be 1 per spec.
	StartOfTime bool `json:"start_of_time_marker"`
	// Minute (bits 21..27): 0-59.
	Minute int `json:"minute"`
	// MinuteParityValid — even parity over bits 21..27 (bit 28).
	MinuteParityValid bool `json:"minute_parity_valid"`
	// Hour (bits 29..34): 0-23.
	Hour int `json:"hour"`
	// HourParityValid — even parity over bits 29..34 (bit 35).
	HourParityValid bool `json:"hour_parity_valid"`
	// DayOfMonth (bits 36..41): 1-31.
	DayOfMonth int `json:"day_of_month"`
	// DayOfWeek (bits 42..44): 1=Mon, 2=Tue, ..., 7=Sun.
	DayOfWeek     int    `json:"day_of_week"`
	DayOfWeekName string `json:"day_of_week_name"`
	// Month (bits 45..49): 1-12.
	Month int `json:"month"`
	// Year (bits 50..57): 0-99 (the caller chooses the century).
	Year int `json:"year"`
	// DateParityValid — even parity over bits 36..57 (bit 58).
	DateParityValid bool `json:"date_parity_valid"`
	// FormattedTime renders the decoded time as "HH:MM" for
	// quick reads.
	FormattedTime string `json:"formatted_time"`
	// FormattedDate renders the decoded date as "YYYY-MM-DD"
	// using a 20YY century assumption (covers DCF77's current
	// operating window 2000-2099).
	FormattedDate string `json:"formatted_date"`
	// AllParityValid is the AND of MinuteParityValid +
	// HourParityValid + DateParityValid. Convenience flag for
	// callers that want a single "frame integrity" indicator.
	AllParityValid bool `json:"all_parity_valid"`
}

// Decode parses a 60-bit string of '0' and '1' characters into
// a Frame. Tolerates ':' / '-' / '_' / whitespace separators.
func Decode(bitStream string) (Frame, error) {
	cleaned := stripSeparators(bitStream)
	if cleaned == "" {
		return Frame{}, fmt.Errorf("dcf77: empty bit-stream")
	}
	if len(cleaned) != 60 {
		return Frame{}, fmt.Errorf("dcf77: bit-stream must be exactly 60 bits; got %d",
			len(cleaned))
	}
	for i, c := range cleaned {
		if c != '0' && c != '1' {
			return Frame{}, fmt.Errorf("dcf77: invalid bit %q at position %d (expected '0' or '1')",
				c, i)
		}
	}
	b := make([]byte, 60)
	for i, c := range cleaned {
		if c == '1' {
			b[i] = 1
		}
	}
	return decodeBits(b)
}

// decodeBits walks a pre-validated 60-byte slice (each entry 0
// or 1) into the structured Frame.
func decodeBits(b []byte) (Frame, error) {
	out := Frame{
		StartOfMinute:             b[0] == 0,
		WeatherDataBits:           bitsToString(b[1:15]),
		AntennaSwitchAnnouncement: b[15] == 1,
		DSTChangeAnnouncement:     b[16] == 1,
		CESTActive:                b[17] == 1 && b[18] == 0,
		LeapSecondAnnouncement:    b[19] == 1,
		StartOfTime:               b[20] == 1,
	}
	if out.CESTActive {
		out.TimezoneOffsetHours = 2
	} else {
		out.TimezoneOffsetHours = 1
	}
	// Minute: bits 21..27 BCD with weights 1, 2, 4, 8, 10, 20, 40
	out.Minute = bcdValue(b[21:28], []int{1, 2, 4, 8, 10, 20, 40})
	out.MinuteParityValid = evenParity(b[21:28]) == int(b[28])
	// Hour: bits 29..34 BCD with weights 1, 2, 4, 8, 10, 20
	out.Hour = bcdValue(b[29:35], []int{1, 2, 4, 8, 10, 20})
	out.HourParityValid = evenParity(b[29:35]) == int(b[35])
	// Day of month: bits 36..41 BCD with weights 1, 2, 4, 8, 10, 20
	out.DayOfMonth = bcdValue(b[36:42], []int{1, 2, 4, 8, 10, 20})
	// Day of week: bits 42..44 BCD with weights 1, 2, 4
	out.DayOfWeek = bcdValue(b[42:45], []int{1, 2, 4})
	out.DayOfWeekName = dayOfWeekName(out.DayOfWeek)
	// Month: bits 45..49 BCD with weights 1, 2, 4, 8, 10
	out.Month = bcdValue(b[45:50], []int{1, 2, 4, 8, 10})
	// Year: bits 50..57 BCD with weights 1, 2, 4, 8, 10, 20, 40, 80
	out.Year = bcdValue(b[50:58], []int{1, 2, 4, 8, 10, 20, 40, 80})
	// Date parity: even parity over bits 36..57 (the full date field)
	out.DateParityValid = evenParity(b[36:58]) == int(b[58])
	// Formatted renders
	out.FormattedTime = fmt.Sprintf("%02d:%02d", out.Hour, out.Minute)
	out.FormattedDate = fmt.Sprintf("20%02d-%02d-%02d", out.Year, out.Month, out.DayOfMonth)
	out.AllParityValid = out.MinuteParityValid && out.HourParityValid && out.DateParityValid
	return out, nil
}

// bcdValue computes the BCD-weighted sum for a slice of bits
// against a slice of weights. The DCF77 spec uses 1-2-4-8-10-20-...
// style weights rather than positional powers of 2.
func bcdValue(bits []byte, weights []int) int {
	if len(bits) != len(weights) {
		return -1
	}
	sum := 0
	for i, b := range bits {
		if b == 1 {
			sum += weights[i]
		}
	}
	return sum
}

// evenParity returns the count of 1 bits modulo 2 — DCF77's
// parity field is "even" meaning the parity bit makes the total
// number of 1 bits (including the parity bit itself) even. So
// the expected parity bit value = count of 1s mod 2.
func evenParity(bits []byte) int {
	count := 0
	for _, b := range bits {
		if b == 1 {
			count++
		}
	}
	return count % 2
}

// dayOfWeekName maps the DCF77 day-of-week BCD value (1..7) to
// the English day name. DCF77 uses 1=Monday through 7=Sunday
// (ISO 8601 convention).
func dayOfWeekName(d int) string {
	switch d {
	case 1:
		return "Monday"
	case 2:
		return "Tuesday"
	case 3:
		return "Wednesday"
	case 4:
		return "Thursday"
	case 5:
		return "Friday"
	case 6:
		return "Saturday"
	case 7:
		return "Sunday"
	}
	return ""
}

// bitsToString renders a slice of 0/1 bytes as a binary string.
func bitsToString(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c == 1 {
			sb.WriteByte('1')
		} else {
			sb.WriteByte('0')
		}
	}
	return sb.String()
}

// stripSeparators mirrors the convention across our pure-decoder
// packages.
func stripSeparators(s string) string {
	repl := strings.NewReplacer(
		" ", "",
		"\t", "",
		"\n", "",
		"\r", "",
		":", "",
		"-", "",
		"_", "",
	)
	return repl.Replace(strings.TrimSpace(s))
}
