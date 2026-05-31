// SPDX-License-Identifier: AGPL-3.0-or-later

package dcf77

import (
	"fmt"
	"strings"
)

// SynthInput is the wall-clock time + timezone to encode into a DCF77
// minute telegram. Fields use the same conventions Decode reports:
// DayOfWeek is ISO (1=Monday … 7=Sunday), Year is the two-digit
// year-within-century (0–99), CEST selects summer time (UTC+2) vs CET
// (UTC+1).
type SynthInput struct {
	Minute     int  `json:"minute"`
	Hour       int  `json:"hour"`
	DayOfMonth int  `json:"day_of_month"`
	DayOfWeek  int  `json:"day_of_week"`
	Month      int  `json:"month"`
	Year       int  `json:"year"`
	CEST       bool `json:"cest"`
}

// Synth builds the 60-bit DCF77 minute telegram for the given time, with
// correct BCD fields and the three even-parity bits, exactly as Decode
// expects it (round-trip inverse of Decode). It is the offline telegram
// generator behind a DCF77 clock-spoof payload — it does NOT transmit;
// operators feed the returned bit-string to a Sub-GHz/long-wave TX stage.
//
// # Wrap-vs-native judgement
//
// Native, and the inverse of the existing Decode. The DCF77 frame format
// is fully public (PTB DCF77 spec / ETSI EN 300 220-1) and the encoding is
// pure bit-level BCD + even parity over a fixed 60-bit frame — no crypto,
// no state, no hardware. Correctness is verifiable three ways: round-trip
// against Decode, hand-computed BCD/parity, and the published spec.
//
// Bit 0 is the start-of-minute marker (0); bit 20 is the start-of-time
// marker (1); bit 59 is the (untransmitted) minute mark, left 0. Weather
// bits (1–14) and the announcement bits are left 0 — the telegram carries
// a clean time/date with no warnings.
func Synth(in SynthInput) (string, error) {
	if in.Minute < 0 || in.Minute > 59 {
		return "", fmt.Errorf("dcf77: minute %d out of range (0-59)", in.Minute)
	}
	if in.Hour < 0 || in.Hour > 23 {
		return "", fmt.Errorf("dcf77: hour %d out of range (0-23)", in.Hour)
	}
	if in.DayOfMonth < 1 || in.DayOfMonth > 31 {
		return "", fmt.Errorf("dcf77: day_of_month %d out of range (1-31)", in.DayOfMonth)
	}
	if in.DayOfWeek < 1 || in.DayOfWeek > 7 {
		return "", fmt.Errorf("dcf77: day_of_week %d out of range (1=Mon..7=Sun)", in.DayOfWeek)
	}
	if in.Month < 1 || in.Month > 12 {
		return "", fmt.Errorf("dcf77: month %d out of range (1-12)", in.Month)
	}
	if in.Year < 0 || in.Year > 99 {
		return "", fmt.Errorf("dcf77: year %d out of range (0-99, two-digit year-within-century)", in.Year)
	}

	b := make([]byte, 60)
	// bit 0: start of minute = 0 (already zero)
	// bits 17-18: timezone — CEST=10, CET=01 (Decode: CEST = b17==1 && b18==0)
	if in.CEST {
		b[17] = 1
	} else {
		b[18] = 1
	}
	// bit 20: start of time = 1
	b[20] = 1

	encodeBCD(b[21:28], in.Minute, []int{1, 2, 4, 8, 10, 20, 40})
	b[28] = byte(evenParity(b[21:28]))

	encodeBCD(b[29:35], in.Hour, []int{1, 2, 4, 8, 10, 20})
	b[35] = byte(evenParity(b[29:35]))

	encodeBCD(b[36:42], in.DayOfMonth, []int{1, 2, 4, 8, 10, 20})
	encodeBCD(b[42:45], in.DayOfWeek, []int{1, 2, 4})
	encodeBCD(b[45:50], in.Month, []int{1, 2, 4, 8, 10})
	encodeBCD(b[50:58], in.Year, []int{1, 2, 4, 8, 10, 20, 40, 80})
	// date parity: even over the full date field (bits 36-57)
	b[58] = byte(evenParity(b[36:58]))

	var sb strings.Builder
	sb.Grow(60)
	for _, c := range b {
		if c == 1 {
			sb.WriteByte('1')
		} else {
			sb.WriteByte('0')
		}
	}
	return sb.String(), nil
}

// encodeBCD writes the DCF77 BCD-weighted bits for value into bits, the
// inverse of decoder.bcdValue. Weights are the DCF77 1-2-4-8-10-20-40-80
// style (units digit in the <10 weights, tens digit in the >=10 weights);
// the greedy largest-weight-first fill produces valid BCD for any value
// the field's weights can represent.
func encodeBCD(bits []byte, value int, weights []int) {
	for i := len(weights) - 1; i >= 0 && value > 0; i-- {
		if weights[i] <= value {
			bits[i] = 1
			value -= weights[i]
		}
	}
}
