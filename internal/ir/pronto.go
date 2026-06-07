// SPDX-License-Identifier: AGPL-3.0-or-later

package ir

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Pronto (a.k.a. Pronto HEX / CCF) is the universal textual IR-code format used
// by remote databases and learning remotes (Philips Pronto, Logitech Harmony,
// JP1, RemoteCentral, IrScrutinizer). A Pronto code is a list of 16-bit hex
// words: a format word, a frequency word, the intro and repeat burst-pair
// counts, then the burst values (each in carrier cycles). This decodes a raw
// Pronto code into its carrier frequency and the intro / repeat timing
// sequences in microseconds, and — for the common "raw oscillated" format — runs
// the converted intro sequence through the protocol decoder to name the protocol.
//
// # Wrap-vs-native judgement
//
//	Native. The Pronto -> timings conversion is fixed, documented arithmetic
//	(carrier period = freqWord x 0.241246 µs, each burst = cycles x period);
//	stdlib only, no new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The format-word meanings, the 0.241246 µs Pronto clock unit, and the
//	burst-pair layout are the long-documented Pronto/CCF spec (RemoteCentral,
//	IrScrutinizer, Arduino-IRremote). The frequency word 0x006D -> 38029 Hz is
//	the canonical anchor. Only the raw formats (0x0000 oscillated / 0x0100
//	unmodulated) carry burst pairs and are converted; a predefined-code format
//	word is reported by value with a note rather than mis-converted. The chained
//	protocol decode is best-effort: when the intro timings match a known
//	protocol it is named, otherwise the carrier + raw timings are surfaced (no
//	guess).

// ProntoResult is the decoded view of a Pronto HEX IR code.
type ProntoResult struct {
	Format        string   `json:"format"`
	FormatWord    string   `json:"format_word"`
	CarrierHz     int      `json:"carrier_hz,omitempty"`
	IntroPairs    int      `json:"intro_pairs"`
	RepeatPairs   int      `json:"repeat_pairs"`
	IntroTimings  []int    `json:"intro_timings_us"`
	RepeatTimings []int    `json:"repeat_timings_us,omitempty"`
	Protocol      *Result  `json:"protocol,omitempty"`
	Notes         []string `json:"notes,omitempty"`
}

// prontoClockUS is the Pronto carrier-clock unit: one frequency-word count is
// 0.241246 µs (derived from the 4.145146 MHz Pronto reference).
const prontoClockUS = 0.241246

// DecodePronto parses a Pronto HEX code (space-separated 4-hex-digit words; a
// '0x' prefix and ':'/'-' separators tolerated) into carrier + timings.
func DecodePronto(input string) (*ProntoResult, error) {
	words, err := parseProntoWords(input)
	if err != nil {
		return nil, err
	}
	if len(words) < 4 {
		return nil, fmt.Errorf("ir: Pronto code needs at least 4 words (format, frequency, intro count, repeat count); got %d", len(words))
	}

	format := words[0]
	freqWord := words[1]
	nIntro := int(words[2])
	nRepeat := int(words[3])

	want := 4 + 2*(nIntro+nRepeat)
	if len(words) != want {
		return nil, fmt.Errorf("ir: Pronto burst-pair counts (%d intro + %d repeat) imply %d words but got %d", nIntro, nRepeat, want, len(words))
	}
	if freqWord == 0 {
		return nil, fmt.Errorf("ir: Pronto frequency word is 0000 (would divide by zero)")
	}

	period := float64(freqWord) * prontoClockUS // µs per carrier cycle

	r := &ProntoResult{
		FormatWord:  fmt.Sprintf("0x%04X", format),
		IntroPairs:  nIntro,
		RepeatPairs: nRepeat,
	}

	switch format {
	case 0x0000:
		r.Format = "raw (oscillated / modulated)"
		r.CarrierHz = int(math.Round(1_000_000 / period))
	case 0x0100:
		r.Format = "raw (unmodulated / no carrier)"
		r.Notes = append(r.Notes, "format 0x0100 is unmodulated — the frequency word sets only the timebase, there is no IR carrier")
	default:
		// Predefined-code formats (e.g. 0x5000 RC5, 0x6000 RC6, 0x900A NECx)
		// encode the protocol + data directly rather than as burst pairs; this
		// decoder converts only the raw burst-pair formats.
		r.Format = fmt.Sprintf("predefined-code format 0x%04X (not a raw burst-pair code)", format)
		r.Notes = append(r.Notes, "only the raw Pronto formats (0x0000 oscillated, 0x0100 unmodulated) carry burst pairs and are converted to timings; this is a predefined-code format and is reported by value, not converted")
		return r, nil
	}

	bursts := words[4:]
	r.IntroTimings = burstsToUS(bursts[:2*nIntro], period)
	if nRepeat > 0 {
		r.RepeatTimings = burstsToUS(bursts[2*nIntro:2*nIntro+2*nRepeat], period)
	}

	// Best-effort: name the protocol from the intro timing sequence.
	if len(r.IntroTimings) >= 2 {
		if dec, derr := DecodeRaw(joinInts(r.IntroTimings)); derr == nil {
			r.Protocol = dec
		} else {
			r.Notes = append(r.Notes, "intro timings did not match a known protocol ("+derr.Error()+"); carrier + raw timings surfaced")
		}
	}
	r.Notes = append(r.Notes, "Pronto HEX IR code — carrier + intro/repeat timings converted per the documented Pronto/CCF clock (0.241246 µs/count); chain the timings into a remote or compare against ir_raw_decode")
	return r, nil
}

// EncodePronto is the inverse of DecodePronto: it converts a raw IR timing
// sequence (space/comma-separated microsecond mark/space durations) and a
// carrier frequency into a raw-oscillated (format 0x0000) Pronto HEX code with
// no repeat sequence. It round-trips with DecodePronto (decode of the emitted
// code reproduces the input timings within carrier-period rounding).
func EncodePronto(timings string, carrierHz int) (string, error) {
	t, err := parseTimings(timings)
	if err != nil {
		return "", err
	}
	if len(t) < 2 {
		return "", fmt.Errorf("ir: need at least one mark/space pair; got %d timing(s)", len(t))
	}
	if len(t)%2 != 0 {
		return "", fmt.Errorf("ir: Pronto needs an even number of timings (mark/space pairs); got %d", len(t))
	}
	if carrierHz <= 0 {
		return "", fmt.Errorf("ir: carrier frequency must be positive (Hz); got %d", carrierHz)
	}

	freqWord := int(math.Round(1_000_000 / (float64(carrierHz) * prontoClockUS)))
	if freqWord < 1 || freqWord > 0xFFFF {
		return "", fmt.Errorf("ir: carrier %d Hz maps to out-of-range Pronto frequency word %d", carrierHz, freqWord)
	}
	period := float64(freqWord) * prontoClockUS

	pairs := len(t) / 2
	words := make([]uint16, 0, 4+len(t))
	words = append(words, 0x0000, uint16(freqWord), uint16(pairs), 0x0000)
	for _, us := range t {
		burst := int(math.Round(float64(us) / period))
		if burst < 1 {
			burst = 1 // a sub-cycle duration still needs at least one carrier cycle
		}
		if burst > 0xFFFF {
			return "", fmt.Errorf("ir: timing %dµs exceeds the Pronto burst range at %d Hz", us, carrierHz)
		}
		words = append(words, uint16(burst))
	}

	parts := make([]string, len(words))
	for i, w := range words {
		parts[i] = fmt.Sprintf("%04X", w)
	}
	return strings.Join(parts, " "), nil
}

func burstsToUS(bursts []uint16, period float64) []int {
	out := make([]int, len(bursts))
	for i, b := range bursts {
		out[i] = int(math.Round(float64(b) * period))
	}
	return out
}

func joinInts(v []int) string {
	var sb strings.Builder
	for i, n := range v {
		if i > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(strconv.Itoa(n))
	}
	return sb.String()
}

func parseProntoWords(s string) ([]uint16, error) {
	s = strings.TrimSpace(s)
	rep := strings.NewReplacer(",", " ", ":", " ", "-", " ", "\t", " ", "\n", " ", "\r", " ", "0x", "", "0X", "")
	fields := strings.Fields(rep.Replace(s))
	if len(fields) == 0 {
		return nil, fmt.Errorf("ir: empty Pronto code")
	}
	out := make([]uint16, 0, len(fields))
	for _, f := range fields {
		if len(f) != 4 {
			return nil, fmt.Errorf("ir: Pronto word %q is not 4 hex digits", f)
		}
		n, err := strconv.ParseUint(f, 16, 16)
		if err != nil {
			return nil, fmt.Errorf("ir: Pronto word %q is not valid hex: %w", f, err)
		}
		out = append(out, uint16(n))
	}
	return out, nil
}
