// SPDX-License-Identifier: AGPL-3.0-or-later

// Package iban decodes and validates an International Bank Account
// Number (ISO 13616) — the financial-account leg of the data-decoder
// family alongside internal/iccid (SIM), internal/imei (device) and
// internal/track2 (payment card). An IBAN turns up in leaked
// spreadsheets, invoice fraud / BEC lures, and clipboard-hijacker
// payloads; decoding one off a paste tells an operator the issuing
// country and whether the number is internally consistent.
//
// # Wrap-vs-native judgement
//
//	Native. An IBAN is a fixed character-field layout — a 2-letter
//	ISO 3166-1 country code, 2 check digits, then a country-specific
//	Basic Bank Account Number (BBAN) — guarded by an ISO 7064
//	MOD-97-10 checksum. Validating it is integer arithmetic over the
//	rearranged string; no runtime dependency or hand-transcribed table
//	is justified. stdlib only, no new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The MOD-97-10 checksum is the verification anchor — it is
//	recomputed and compared, and a mismatch is reported as
//	mod97_valid=false with the expected check digits in a note (a
//	mistyped IBAN, or one whose check digits were stripped), never
//	asserted as a definitively fraudulent account. The country code is
//	surfaced as the raw ISO 3166-1 alpha-2 letters, not mapped to a
//	country name, because that would need a hand-transcribed table the
//	IBAN itself does not carry. The BBAN is surfaced whole, not split
//	into bank / branch / account, because that split is country-specific
//	with no single public rule (the same reason iccid_decode surfaces
//	issuer+account combined). The per-country IBAN length is likewise
//	not enforced — the MOD-97-10 check already catches truncation and
//	transposition, and an authoritative length table is not embedded.
package iban

import (
	"fmt"
	"strings"
)

// Result is the decoded view of an IBAN.
type Result struct {
	IBAN        string   `json:"iban"`         // normalised: separators stripped, upper-cased
	Formatted   string   `json:"formatted"`    // print form, grouped in fours
	CountryCode string   `json:"country_code"` // ISO 3166-1 alpha-2
	CheckDigits string   `json:"check_digits"`
	BBAN        string   `json:"bban"` // Basic Bank Account Number (country-specific, not split)
	Length      int      `json:"length"`
	Mod97Valid  bool     `json:"mod97_valid"` // ISO 7064 MOD-97-10 (the verification anchor)
	Notes       []string `json:"notes,omitempty"`
}

// normalize strips the separators commonly used to group an IBAN / BBAN
// for printing and upper-cases the rest, so 'gb82 west …' and
// 'GB82WEST…' are treated identically.
func normalize(raw string) string {
	s := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '-', ':', '\t', '\n', '\r':
			return -1
		}
		return r
	}, raw)
	return strings.ToUpper(s)
}

// Decode validates and breaks down an IBAN. Spaces, '-' and ':'
// separators are tolerated and the input is upper-cased.
func Decode(raw string) (*Result, error) {
	s := normalize(raw)
	if s == "" {
		return nil, fmt.Errorf("iban: empty input")
	}
	// ISO 13616 restricts the IBAN to the upper-case Latin alphabet and
	// the digits; any other rune means this is not an IBAN.
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isDigit(c) || isAlpha(c) {
			continue
		}
		return nil, fmt.Errorf("iban: invalid character %q — an IBAN is letters and digits only", c)
	}
	// 15 is the shortest national IBAN length (Norway); 34 is the ISO
	// 13616 maximum. Anything outside cannot be a well-formed IBAN.
	if len(s) < 15 || len(s) > 34 {
		return nil, fmt.Errorf("iban: %d characters — an IBAN is 15-34 (ISO 13616)", len(s))
	}
	// Positions 1-2 are the ISO 3166-1 country code (letters); 3-4 are
	// the check digits (digits).
	if !isAlpha(s[0]) || !isAlpha(s[1]) {
		return nil, fmt.Errorf("iban: positions 1-2 must be a 2-letter country code, got %q", s[:2])
	}
	if !isDigit(s[2]) || !isDigit(s[3]) {
		return nil, fmt.Errorf("iban: positions 3-4 must be 2 check digits, got %q", s[2:4])
	}

	r := &Result{
		IBAN:        s,
		Formatted:   group4(s),
		CountryCode: s[:2],
		CheckDigits: s[2:4],
		BBAN:        s[4:],
		Length:      len(s),
	}
	r.Mod97Valid = mod97(rearrange(s)) == 1
	if !r.Mod97Valid {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"MOD-97-10 check failed — the IBAN is mistyped or its check digits were stripped; "+
				"the check digits that would make this BBAN valid are %02d", expectedCheckDigits(s)))
	}
	r.Notes = append(r.Notes,
		"the BBAN is surfaced whole — the bank / branch / account split is country-specific with no single "+
			"public rule, so it is not guessed (no confidently-wrong output)")
	return r, nil
}

// Encode builds a valid IBAN from a country code and a BBAN by computing
// the ISO 7064 MOD-97-10 check digits — the inverse of Decode.
// Separators are tolerated and the inputs are upper-cased. The returned
// Result is the assembled IBAN run back through Decode, so mod97_valid is
// true by construction (the output is round-trip-verified, not asserted).
func Encode(country, bban string) (*Result, error) {
	cc := normalize(country)
	b := normalize(bban)
	if len(cc) != 2 || !isAlpha(cc[0]) || !isAlpha(cc[1]) {
		return nil, fmt.Errorf("iban: country code must be 2 letters, got %q", cc)
	}
	for i := 0; i < len(b); i++ {
		if isDigit(b[i]) || isAlpha(b[i]) {
			continue
		}
		return nil, fmt.Errorf("iban: BBAN character %q is not a letter or digit", b[i])
	}
	// The IBAN is the 2-letter country code + 2 check digits + the BBAN;
	// keep the total inside the ISO 13616 15-34 envelope.
	if total := 4 + len(b); total < 15 || total > 34 {
		return nil, fmt.Errorf(
			"iban: BBAN of %d chars yields a %d-char IBAN, outside the 15-34 range (ISO 13616)", len(b), total)
	}
	// ISO 7064: the check digits make MOD-97-10 of (BBAN + country + DD)
	// equal 1; DD = 98 - the remainder with "00" in the check positions.
	check := 98 - mod97(b+cc+"00")
	return Decode(fmt.Sprintf("%s%02d%s", cc, check, b))
}

func isAlpha(c byte) bool { return c >= 'A' && c <= 'Z' }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// rearrange moves the first four characters (country code + check
// digits) to the end, the transformation ISO 13616 / ISO 7064 applies
// before the MOD-97 computation.
func rearrange(s string) string { return s[4:] + s[:4] }

// mod97 computes the ISO 7064 MOD-97-10 remainder of s, where each
// letter expands to a two-digit number (A=10 … Z=35) and each digit to
// itself. It folds the value piece by piece so no big integer is
// needed: a letter contributes two decimal positions, a digit one.
func mod97(s string) int {
	rem := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			rem = (rem*10 + int(c-'0')) % 97
		case c >= 'A' && c <= 'Z':
			rem = (rem*100 + int(c-'A') + 10) % 97
		}
	}
	return rem
}

// expectedCheckDigits returns the two check digits that would make s
// pass the MOD-97-10 test. It substitutes "00" for the existing check
// digits, takes the remainder, and applies the ISO 7064 98 - r rule.
func expectedCheckDigits(s string) int {
	body := s[4:] + s[:2] + "00"
	return 98 - mod97(body)
}

// group4 renders an IBAN in the conventional print form: groups of four
// characters separated by spaces (the last group may be shorter).
func group4(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i += 4 {
		if i > 0 {
			b.WriteByte(' ')
		}
		end := i + 4
		if end > len(s) {
			end = len(s)
		}
		b.WriteString(s[i:end])
	}
	return b.String()
}
