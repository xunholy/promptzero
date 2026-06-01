// SPDX-License-Identifier: AGPL-3.0-or-later

package wps

import (
	"fmt"
	"strings"
)

// Checksum computes the WPS PIN check digit for a 7-digit prefix, per the
// Wi-Fi Simple Configuration PIN-checksum algorithm (the same routine
// reaver / bully use). The 8-digit device PIN is the 7-digit prefix
// followed by this digit, so a brute-force only needs to search the 10^7
// prefixes — the checksum makes the 8th digit free.
//
//	accum over digits: 3*(units) + tens, repeated; digit = (10 - accum%10) % 10
func Checksum(prefix7 int) int {
	pin := prefix7
	accum := 0
	for pin > 0 {
		accum += 3 * (pin % 10)
		pin /= 10
		accum += pin % 10
		pin /= 10
	}
	return (10 - accum%10) % 10
}

// PINResult is the decoded view of a WPS PIN check.
type PINResult struct {
	Input         string `json:"input"`
	Digits        int    `json:"digits"`
	Mode          string `json:"mode"` // "validate" | "complete"
	Valid         *bool  `json:"valid,omitempty"`
	ExpectedDigit *int   `json:"expected_check_digit,omitempty"`
	FullPIN       string `json:"full_pin,omitempty"`
	WellKnown     string `json:"well_known,omitempty"`
	Note          string `json:"note,omitempty"`
}

// wellKnownPINs are the universally-cited weak/default 8-digit WPS PINs.
// Vendor-specific default-PIN derivations (ComputePIN from the BSSID — the
// large reaver/bully "known PINs" databases) are deliberately not embedded:
// they are device-specific and a partial table would be confidently-wrong.
var wellKnownPINs = map[string]string{
	"12345670": "the canonical example / common factory default",
	"00000000": "all-zero default",
}

// CheckPIN validates an 8-digit PIN, or completes a 7-digit prefix with its
// check digit. The input must be all digits (separators are stripped).
func CheckPIN(s string) (*PINResult, error) {
	clean := strings.NewReplacer(" ", "", "-", "", ":", "").Replace(strings.TrimSpace(s))
	if clean == "" {
		return nil, fmt.Errorf("wps: empty PIN")
	}
	for _, r := range clean {
		if r < '0' || r > '9' {
			return nil, fmt.Errorf("wps: PIN must be all digits; got %q", s)
		}
	}
	r := &PINResult{Input: clean, Digits: len(clean)}
	switch len(clean) {
	case 7:
		r.Mode = "complete"
		prefix := atoi(clean)
		d := Checksum(prefix)
		r.ExpectedDigit = &d
		r.FullPIN = fmt.Sprintf("%07d%d", prefix, d)
		if wk, ok := wellKnownPINs[r.FullPIN]; ok {
			r.WellKnown = wk
		}
	case 8:
		r.Mode = "validate"
		prefix := atoi(clean[:7])
		last := int(clean[7] - '0')
		expected := Checksum(prefix)
		r.ExpectedDigit = &expected
		valid := expected == last
		r.Valid = &valid
		if !valid {
			r.Note = fmt.Sprintf("check digit %d does not match expected %d; this 8-digit PIN is not WPS-checksum-valid", last, expected)
		}
		if wk, ok := wellKnownPINs[clean]; ok {
			r.WellKnown = wk
		}
	default:
		return nil, fmt.Errorf("wps: PIN must be 7 digits (to complete) or 8 digits (to validate); got %d", len(clean))
	}
	return r, nil
}

func atoi(s string) int {
	n := 0
	for _, r := range s {
		n = n*10 + int(r-'0')
	}
	return n
}
