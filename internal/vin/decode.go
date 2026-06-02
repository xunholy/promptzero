// SPDX-License-Identifier: AGPL-3.0-or-later

// Package vin decodes and validates a 17-character Vehicle Identification
// Number (ISO 3779 / ISO 3780). It is the offline complement to the
// automotive diagnostic stack: a VIN is what UDS ReadDataByIdentifier
// (DID 0xF190) and OBD-II Mode 09 PID 02 return, so an operator who has read
// one over CAN can validate and break it down here without any further bus
// access.
//
// # Wrap-vs-native judgement
//
// Native. The VIN structure, the position-9 check-digit algorithm (a fixed
// transliteration table + position weights, mod 11), the ISO 3780 first-
// character region ranges, and the 30-character model-year cycle are all
// public, fixed, deterministic specs — pure arithmetic and small fixed
// tables over a 17-byte string. There is nothing to wrap.
//
// # Verifiable / no confidently-wrong output
//
// The check digit is the verification anchor: it is recomputed from the other
// 16 characters and compared to position 9. Because the check digit is
// mandatory only in North America and China (other markets may carry any
// character there), a mismatch is reported as advisory — check_digit_valid
// plus a note — rather than asserting the VIN is invalid. The model-year code
// is genuinely ambiguous (the 30-character cycle repeats), so candidate years
// are returned, not a single confident year. The world-manufacturer
// identifier (WMI) is surfaced raw — the WMI-to-manufacturer registry is a
// large proprietary table, so a manufacturer name is deliberately NOT guessed.
//
// # Covered / deferred
//
// Covered: length + character-set validation (the I/O/Q exclusion), the
// check-digit computation + validity, the ISO 3780 region from the first
// character, the model-year candidates from position 10, and the structural
// split (WMI / VDS / VIS, plant code). Deferred: WMI-to-manufacturer lookup
// (proprietary), and any manufacturer-specific VDS interpretation.
package vin

import (
	"fmt"
	"strings"
)

// Result is the decoded view of a VIN.
type Result struct {
	VIN                 string   `json:"vin"`
	WMI                 string   `json:"wmi"` // world manufacturer identifier (chars 1-3)
	VDS                 string   `json:"vds"` // vehicle descriptor section (chars 4-9)
	VIS                 string   `json:"vis"` // vehicle identifier section (chars 10-17)
	Region              string   `json:"region"`
	CheckDigit          string   `json:"check_digit"`          // the character at position 9
	CheckDigitComputed  string   `json:"check_digit_computed"` // recomputed from the other 16
	CheckDigitValid     bool     `json:"check_digit_valid"`
	ModelYearCode       string   `json:"model_year_code"`       // character at position 10
	ModelYearCandidates []int    `json:"model_year_candidates"` // the cyclic-code candidate years
	PlantCode           string   `json:"plant_code"`            // character at position 11
	SerialSection       string   `json:"serial_section"`        // characters 12-17
	Notes               []string `json:"notes,omitempty"`
}

// position weights for the check-digit calculation (1-indexed positions 1..17;
// position 9 — the check digit itself — has weight 0).
var checkWeights = [17]int{8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2}

// modelYearCycle is the 30-character model-year code sequence, starting at
// 'A' = 1980 (and repeating: 'A' = 2010, 2040, …). The letters I, O, Q, U, Z
// and the digit 0 are excluded.
const modelYearCycle = "ABCDEFGHJKLMNPRSTVWXY123456789"

// Decode validates and breaks down a 17-character VIN.
func Decode(raw string) (*Result, error) {
	v := strings.ToUpper(strings.TrimSpace(raw))
	v = strings.NewReplacer(" ", "", "-", "", "_", "").Replace(v)
	if len(v) != 17 {
		return nil, fmt.Errorf("vin: must be 17 characters; got %d", len(v))
	}
	for i := 0; i < 17; i++ {
		if _, ok := translit(v[i]); !ok {
			return nil, fmt.Errorf("vin: character %q at position %d is not valid in a VIN (I, O, Q and punctuation are excluded)", string(v[i]), i+1)
		}
	}

	sum := 0
	for i := 0; i < 17; i++ {
		val, _ := translit(v[i])
		sum += val * checkWeights[i]
	}
	rem := sum % 11
	computed := "X"
	if rem != 10 {
		computed = fmt.Sprintf("%d", rem)
	}
	checkChar := string(v[8]) // position 9

	r := &Result{
		VIN:                v,
		WMI:                v[0:3],
		VDS:                v[3:9],
		VIS:                v[9:17],
		Region:             region(v[0]),
		CheckDigit:         checkChar,
		CheckDigitComputed: computed,
		CheckDigitValid:    checkChar == computed,
		ModelYearCode:      string(v[9]),
		PlantCode:          string(v[10]),
		SerialSection:      v[11:17],
	}
	r.ModelYearCandidates = modelYears(v[9])
	if !r.CheckDigitValid {
		r.Notes = append(r.Notes, fmt.Sprintf("check digit %q does not match the computed %q — the VIN may be mistyped, or from a market that does not enforce the check digit (it is mandatory only in North America and China)", checkChar, computed))
	}
	if len(r.ModelYearCandidates) == 0 {
		r.Notes = append(r.Notes, fmt.Sprintf("position-10 code %q is not a recognised model-year code", string(v[9])))
	} else {
		r.Notes = append(r.Notes, "model year is from a 30-year cyclic code; later cycles (e.g. +60 years) are also possible")
	}
	return r, nil
}

// translit maps a VIN character to its numeric value for the check digit.
// Digits map to themselves; letters follow the standard VIN table; I, O, Q and
// any other character are invalid (ok=false).
func translit(c byte) (int, bool) {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0'), true
	case c >= 'A' && c <= 'Z':
		// A=1..H=8 (skip I); J=1..N=5 (skip O); P=7 (skip Q); R=9;
		// S=2..Z=9.
		const table = "A1B2C3D4E5F6G7H8J1K2L3M4N5P7R9S2T3U4V5W6X7Y8Z9"
		idx := strings.IndexByte(table, c)
		if idx < 0 || idx%2 != 0 {
			return 0, false // I, O, Q are absent from the table
		}
		return int(table[idx+1] - '0'), true
	default:
		return 0, false
	}
}

// region returns the broad ISO 3780 geographic region for the first VIN
// character.
func region(c byte) string {
	switch {
	case c >= 'A' && c <= 'H':
		return "Africa"
	case c >= 'J' && c <= 'R':
		return "Asia"
	case c >= 'S' && c <= 'Z':
		return "Europe"
	case c >= '1' && c <= '5':
		return "North America"
	case c >= '6' && c <= '7':
		return "Oceania"
	case c >= '8' && c <= '9':
		return "South America"
	default:
		return "unknown"
	}
}

// modelYears returns the candidate model years for a position-10 code (the
// 1980-based and 2010-based cycles; the cycle repeats every 30 years).
func modelYears(c byte) []int {
	idx := strings.IndexByte(modelYearCycle, c)
	if idx < 0 {
		return nil
	}
	return []int{1980 + idx, 2010 + idx}
}
