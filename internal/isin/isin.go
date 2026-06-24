// SPDX-License-Identifier: AGPL-3.0-or-later

// Package isin decodes and validates an International Securities
// Identification Number (ISO 6166) — the 12-character code that
// identifies a tradable security (a stock, bond, or fund). It is the
// securities leg of the financial-data decoder family alongside
// internal/iban (the account) and internal/lei (the entity): an ISIN
// turns up in brokerage statements, trade confirmations, market-data
// dumps, and investment-fraud lures, so decoding one off a paste tells
// an operator the issuing prefix and whether the number is internally
// consistent.
//
// # Wrap-vs-native judgement
//
//	Native. An ISIN is a fixed character-field layout — a 2-letter
//	prefix (an ISO 3166-1 country code, or a special code such as XS for
//	internationally-cleared issues), a 9-character National Securities
//	Identifying Number, then 1 check digit — guarded by an ISO 6166
//	modulus-10 (Luhn) checksum over the letter-expanded body. Validating
//	it is integer arithmetic; no runtime dependency or hand-transcribed
//	table is justified. stdlib only, no new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The Luhn check digit is the verification anchor — it is recomputed
//	and compared, and a mismatch is reported as luhn_valid=false with the
//	expected check digit in a note (a mistyped ISIN), never asserted as a
//	definitively fake security. The 2-letter prefix is surfaced raw, not
//	mapped to a country name — that would need a hand-transcribed table
//	the ISIN does not carry, and several prefixes (XS, EU) are not
//	countries at all. The NSIN is surfaced whole, not split into its
//	national scheme (CUSIP, SEDOL, WKN, …) — that split is
//	prefix-specific with no single public rule. The algorithm is verified
//	against five well-known real ISINs in the tests (Apple, IBM, Nokia,
//	BAE Systems, Microsoft).
package isin

import (
	"fmt"
	"strings"
)

// Result is the decoded view of an ISIN.
type Result struct {
	ISIN       string   `json:"isin"`        // normalised: separators stripped, upper-cased
	Prefix     string   `json:"prefix"`      // chars 1-2: ISO 3166-1 country code (or a special code such as XS)
	NSIN       string   `json:"nsin"`        // chars 3-11: National Securities Identifying Number
	CheckDigit string   `json:"check_digit"` // char 12
	LuhnValid  bool     `json:"luhn_valid"`  // ISO 6166 modulus-10 (the verification anchor)
	Notes      []string `json:"notes,omitempty"`
}

// isinLength is the fixed character count of an ISO 6166 ISIN.
const isinLength = 12

// Decode validates and breaks down an ISIN. Spaces, '-' and ':'
// separators are tolerated and the input is upper-cased.
func Decode(raw string) (*Result, error) {
	s := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '-', ':', '\t', '\n', '\r':
			return -1
		}
		return r
	}, raw)
	s = strings.ToUpper(s)

	if s == "" {
		return nil, fmt.Errorf("isin: empty input")
	}
	// ISO 6166 restricts an ISIN to the upper-case Latin alphabet and the
	// digits; any other rune means this is not an ISIN.
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isDigit(c) || isAlpha(c) {
			continue
		}
		return nil, fmt.Errorf("isin: invalid character %q — an ISIN is letters and digits only", c)
	}
	if len(s) != isinLength {
		return nil, fmt.Errorf("isin: %d characters — an ISIN is exactly %d (ISO 6166)", len(s), isinLength)
	}
	// Positions 1-2 are the prefix (always letters); position 12 is the
	// check digit (always numeric).
	if !isAlpha(s[0]) || !isAlpha(s[1]) {
		return nil, fmt.Errorf("isin: positions 1-2 must be a 2-letter prefix, got %q", s[:2])
	}
	if !isDigit(s[11]) {
		return nil, fmt.Errorf("isin: position 12 must be a check digit, got %q", s[11:12])
	}

	r := &Result{
		ISIN:       s,
		Prefix:     s[:2],
		NSIN:       s[2:11],
		CheckDigit: s[11:12],
	}
	r.LuhnValid = luhnValid(s)
	if !r.LuhnValid {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"Luhn check digit %s does not match the computed %d — the ISIN is mistyped",
			r.CheckDigit, luhnCheckDigit(s[:11])))
	}
	r.Notes = append(r.Notes,
		"the NSIN (chars 3-11) is surfaced whole — its national scheme (CUSIP / SEDOL / WKN / …) is "+
			"prefix-specific with no single public rule, so it is not split (no confidently-wrong output)")
	return r, nil
}

func isAlpha(c byte) bool { return c >= 'A' && c <= 'Z' }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// expand converts an ISIN character to its digit value(s): a digit maps
// to itself, a letter to the two digits of A=10 … Z=35. It appends to
// dst so the caller can build the full digit string in one pass.
func expand(dst []int, c byte) []int {
	if c >= '0' && c <= '9' {
		return append(dst, int(c-'0'))
	}
	v := int(c-'A') + 10
	return append(dst, v/10, v%10)
}

// luhnSum applies the Luhn doubling to a digit slice, doubling every
// second digit starting from the rightmost position that should be
// doubled (controlled by startDouble), and returns the total. Splitting
// the doubling out lets both luhnValid and luhnCheckDigit share it.
func luhnSum(digits []int, startDouble bool) int {
	sum := 0
	double := startDouble
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum
}

// luhnValid reports whether the full 12-char ISIN satisfies the ISO 6166
// modulus-10 checksum. The rightmost digit is the check digit and is NOT
// doubled, so doubling starts at the second-from-right.
func luhnValid(isin string) bool {
	var digits []int
	for i := 0; i < len(isin); i++ {
		digits = expand(digits, isin[i])
	}
	return luhnSum(digits, false)%10 == 0
}

// luhnCheckDigit computes the check digit for an 11-char ISIN body
// (prefix + NSIN, no check digit). The check digit will sit at the
// not-doubled position, so the rightmost body digit IS doubled.
func luhnCheckDigit(body string) int {
	var digits []int
	for i := 0; i < len(body); i++ {
		digits = expand(digits, body[i])
	}
	return (10 - luhnSum(digits, true)%10) % 10
}
