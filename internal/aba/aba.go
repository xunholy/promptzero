// SPDX-License-Identifier: AGPL-3.0-or-later

// Package aba decodes and validates an ABA routing transit number (RTN)
// — the 9-digit code that identifies a US bank or credit union in ACH
// and wire transfers. It is the US-domestic counterpart to internal/iban
// (the international account): a routing number turns up in ACH-fraud /
// business-email-compromise lures, leaked direct-deposit forms, and
// check images, so decoding one off a paste tells an operator whether
// the number is internally consistent and which Federal Reserve district
// issued it.
//
// # Wrap-vs-native judgement
//
//	Native. An RTN is a fixed digit-field layout — a 4-digit Federal
//	Reserve routing symbol, a 4-digit ABA institution identifier, and 1
//	check digit — guarded by a weighted modulus-10 checksum. Validating
//	it is integer arithmetic plus a small fixed range classification; no
//	runtime dependency or hand-transcribed lookup beyond the 12 statutory
//	Federal Reserve districts is justified. stdlib only, no new go.mod
//	dep.
//
// # Verifiable / no confidently-wrong output
//
//	The modulus-10 checksum is the verification anchor — it is recomputed
//	and compared, and a mismatch is reported as checksum_valid=false with
//	a note (a mistyped RTN), never asserted as a definitively fake bank.
//	The Federal Reserve district and the institution type are derived
//	from the leading two digits by the published numbering ranges (not a
//	guess); a prefix outside those ranges leaves the district undetermined
//	rather than inventing one. The institution identifier is surfaced raw
//	— it maps to a specific bank only via the proprietary American Bankers
//	Association registry, which is not embedded.
package aba

import (
	"fmt"
	"strings"
)

// Result is the decoded view of an ABA routing transit number.
type Result struct {
	RoutingNumber string   `json:"routing_number"`
	RoutingSymbol string   `json:"federal_reserve_routing_symbol"` // digits 1-4
	InstitutionID string   `json:"aba_institution_identifier"`     // digits 5-8
	CheckDigit    string   `json:"check_digit"`                    // digit 9
	Type          string   `json:"type"`                           // Government / Primary / Thrift / Electronic / Traveler's
	District      int      `json:"federal_reserve_district,omitempty"`
	DistrictName  string   `json:"federal_reserve_district_name,omitempty"`
	ChecksumValid bool     `json:"checksum_valid"` // ABA weighted modulus-10 (the verification anchor)
	Notes         []string `json:"notes,omitempty"`
}

// rtnLength is the fixed digit count of an ABA routing transit number.
const rtnLength = 9

// frbDistricts maps the 12 statutory Federal Reserve districts (defined
// by the Federal Reserve Act of 1913) to their head-office city. Fixed
// by law, not drifting reference data.
//
//nolint:gochecknoglobals
var frbDistricts = map[int]string{
	1: "Boston", 2: "New York", 3: "Philadelphia", 4: "Cleveland",
	5: "Richmond", 6: "Atlanta", 7: "Chicago", 8: "St. Louis",
	9: "Minneapolis", 10: "Kansas City", 11: "Dallas", 12: "San Francisco",
}

// Decode validates and breaks down an ABA routing number. Spaces, '-'
// and ':' separators are tolerated.
func Decode(raw string) (*Result, error) {
	// Keep only digits — RTNs are sometimes pasted with grouping spaces
	// or dashes (e.g. from a check's MICR line).
	d := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		switch r {
		case ' ', '-', ':', '\t', '\n', '\r':
			return -1
		}
		// Any other rune (a letter, punctuation) is a hard signal this
		// is not an RTN; mark it so the length check below rejects it.
		return 'x'
	}, raw)

	if d == "" {
		return nil, fmt.Errorf("aba: empty input")
	}
	if strings.ContainsRune(d, 'x') {
		return nil, fmt.Errorf("aba: input contains non-digit characters — a routing number is 9 digits")
	}
	if len(d) != rtnLength {
		return nil, fmt.Errorf("aba: %d digits — an ABA routing number is exactly %d", len(d), rtnLength)
	}

	r := &Result{
		RoutingNumber: d,
		RoutingSymbol: d[:4],
		InstitutionID: d[4:8],
		CheckDigit:    d[8:9],
	}
	r.ChecksumValid = checksumValid(d)
	if !r.ChecksumValid {
		r.Notes = append(r.Notes,
			"weighted modulus-10 checksum failed — the routing number is mistyped or transposed")
	}
	classify(r, int(d[0]-'0')*10+int(d[1]-'0'))
	return r, nil
}

// classify resolves the institution type and Federal Reserve district
// from the leading two digits per the published RTN numbering ranges.
func classify(r *Result, prefix int) {
	switch {
	case prefix == 0:
		r.Type = "US Government / Treasury"
	case prefix >= 1 && prefix <= 12:
		r.Type = "Primary (Federal Reserve Bank)"
		r.District = prefix
	case prefix >= 21 && prefix <= 32:
		r.Type = "Thrift institution"
		r.District = prefix - 20
	case prefix >= 61 && prefix <= 72:
		r.Type = "Electronic / ACH"
		r.District = prefix - 60
	case prefix == 80:
		r.Type = "Traveler's cheque"
	default:
		r.Type = "unknown"
		r.Notes = append(r.Notes, fmt.Sprintf(
			"leading digits %02d are outside the assigned RTN ranges; Federal Reserve district undetermined", prefix))
	}
	if name, ok := frbDistricts[r.District]; ok {
		r.DistrictName = name
	}
}

// checksumValid reports whether the 9-digit RTN satisfies the ABA
// weighted modulus-10 checksum (weights 3,7,1 repeating, sum ≡ 0 mod 10).
func checksumValid(d string) bool {
	weights := [9]int{3, 7, 1, 3, 7, 1, 3, 7, 1}
	sum := 0
	for i := 0; i < rtnLength; i++ {
		sum += int(d[i]-'0') * weights[i]
	}
	return sum%10 == 0
}
