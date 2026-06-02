// SPDX-License-Identifier: AGPL-3.0-or-later

// Package imei decodes and validates a GSM device identity — the 15-digit
// IMEI (with its Luhn check digit) and the 16-digit IMEISV (software-version
// variant). It is the offline complement to the cellular tooling: an IMEI is
// disclosed in a GSM/LTE Identity Response (the message an IMSI-catcher forces
// to deanonymise a handset, visible in a gsmtap capture), so an identity read
// off the air can be validated and broken down here.
//
// # Wrap-vs-native judgement
//
// Native. The IMEI structure (8-digit Type Allocation Code + 6-digit serial +
// 1 Luhn check digit, per 3GPP TS 23.003) and the Luhn algorithm are public,
// fixed specs — pure arithmetic over a digit string. There is nothing to wrap.
//
// # Verifiable / no confidently-wrong output
//
// The Luhn check digit is the verification anchor: it is recomputed from the
// first 14 digits and compared to the 15th. A mismatch is reported as
// luhn_valid=false with a note, not asserted as a definitively fake device
// (a mistyped digit also fails it). The IMEISV form carries a software version
// in place of the check digit and so is not Luhn-checked — it is labelled as
// such. The Type Allocation Code is surfaced raw, including its leading
// Reporting Body Identifier: the TAC-to-manufacturer/model registry (the
// GSMA database) is large and not public in full, so a manufacturer or model
// is deliberately NOT guessed.
//
// # Covered / deferred
//
// Covered: IMEI vs IMEISV discrimination by length, the Luhn validation, and
// the structural split (TAC / RBI / serial / check or SVN). Deferred: the
// TAC-to-device lookup (proprietary GSMA data) and any IMSI/TMSI decoding
// (different identifiers, no check digit).
package imei

import (
	"fmt"
	"strings"
)

// Result is the decoded view of a GSM device identity.
type Result struct {
	Type               string   `json:"type"` // "IMEI" or "IMEISV"
	Number             string   `json:"number"`
	TAC                string   `json:"tac"` // Type Allocation Code (digits 1-8)
	ReportingBodyID    string   `json:"reporting_body_id"`
	SerialNumber       string   `json:"serial_number"`         // digits 9-14
	CheckDigit         string   `json:"check_digit,omitempty"` // IMEI only
	CheckDigitComputed string   `json:"check_digit_computed,omitempty"`
	LuhnValid          bool     `json:"luhn_valid,omitempty"`
	SoftwareVersion    string   `json:"software_version,omitempty"` // IMEISV only
	Notes              []string `json:"notes,omitempty"`
}

// Decode validates and breaks down an IMEI (15 digits) or IMEISV (16 digits).
func Decode(raw string) (*Result, error) {
	d := strings.NewReplacer(" ", "", "-", "", "_", "", "/", "").Replace(strings.TrimSpace(raw))
	if d == "" {
		return nil, fmt.Errorf("imei: empty input")
	}
	for i := 0; i < len(d); i++ {
		if d[i] < '0' || d[i] > '9' {
			return nil, fmt.Errorf("imei: character %q at position %d is not a digit", string(d[i]), i+1)
		}
	}

	switch len(d) {
	case 15:
		r := &Result{
			Type:            "IMEI",
			Number:          d,
			TAC:             d[0:8],
			ReportingBodyID: d[0:2],
			SerialNumber:    d[8:14],
			CheckDigit:      d[14:15],
		}
		computed := luhnCheckDigit(d[0:14])
		r.CheckDigitComputed = fmt.Sprintf("%d", computed)
		r.LuhnValid = int(d[14]-'0') == computed
		if !r.LuhnValid {
			r.Notes = append(r.Notes, fmt.Sprintf("Luhn check digit %s does not match the computed %d — the IMEI is mistyped or invalid", r.CheckDigit, computed))
		}
		return r, nil
	case 16:
		return &Result{
			Type:            "IMEISV",
			Number:          d,
			TAC:             d[0:8],
			ReportingBodyID: d[0:2],
			SerialNumber:    d[8:14],
			SoftwareVersion: d[14:16],
			Notes:           []string{"IMEISV carries a 2-digit software version in place of the Luhn check digit, so it is not check-digit validated"},
		}, nil
	default:
		return nil, fmt.Errorf("imei: must be 15 digits (IMEI) or 16 digits (IMEISV); got %d", len(d))
	}
}

// luhnCheckDigit computes the Luhn check digit for a numeric payload string
// (the check digit is appended so the full number satisfies the Luhn sum).
func luhnCheckDigit(payload string) int {
	sum := 0
	double := true // the rightmost payload digit is doubled (check digit will be position 1)
	for i := len(payload) - 1; i >= 0; i-- {
		n := int(payload[i] - '0')
		if double {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		double = !double
	}
	return (10 - (sum % 10)) % 10
}
