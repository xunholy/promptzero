// SPDX-License-Identifier: AGPL-3.0-or-later

// Package lei decodes and validates a Legal Entity Identifier (ISO
// 17442) — the 20-character code that identifies a legally distinct
// entity in financial transactions. It is the entity-side companion to
// internal/iban (the account): an LEI turns up in regulatory filings
// (MiFID II, EMIR), SWIFT messaging, and invoice-fraud / BEC lures
// alongside the IBAN it is meant to corroborate, so decoding one off a
// paste tells an operator whether the identifier is internally
// consistent and which GLEIF unit issued it.
//
// # Wrap-vs-native judgement
//
//	Native. An LEI is a fixed character-field layout — a 4-character
//	GLEIF Local Operating Unit prefix, a 14-character entity-specific
//	part, then 2 check digits — guarded by the same ISO 7064 MOD-97-10
//	checksum that protects an IBAN. Validating it is integer arithmetic
//	over the string; no runtime dependency or hand-transcribed table is
//	justified. stdlib only, no new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The MOD-97-10 checksum is the verification anchor — it is recomputed
//	and compared, and a mismatch is reported as mod97_valid=false with
//	the expected check digits in a note (a mistyped LEI), never asserted
//	as a definitively fake entity. The 4-character LOU prefix is a fixed
//	GLEIF rule and is surfaced. The 14-character entity-specific part is
//	surfaced whole, not split — the original ISO 17442 "00" reserved
//	characters at positions 5-6 are not present in every registered LEI
//	(Apple's HWUPKR0MPOU8FGXBT394 has "KR" there), so splitting on that
//	convention would be confidently wrong; it is left combined. The
//	algorithm is verified against four real GLEIF-registered LEIs in the
//	tests (Apple, Deutsche Bank, Microsoft, GLEIF Americas).
package lei

import (
	"fmt"
	"strings"
)

// Result is the decoded view of an LEI.
type Result struct {
	LEI         string   `json:"lei"`          // normalised: separators stripped, upper-cased
	LOUPrefix   string   `json:"lou_prefix"`   // chars 1-4: issuing GLEIF Local Operating Unit
	EntityID    string   `json:"entity_id"`    // chars 5-18: entity-specific part (not split)
	CheckDigits string   `json:"check_digits"` // chars 19-20
	Mod97Valid  bool     `json:"mod97_valid"`  // ISO 17442 / ISO 7064 MOD-97-10 (the verification anchor)
	Notes       []string `json:"notes,omitempty"`
}

// leiLength is the fixed character count of an ISO 17442 LEI.
const leiLength = 20

// Decode validates and breaks down an LEI. Spaces, '-' and ':'
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
		return nil, fmt.Errorf("lei: empty input")
	}
	// ISO 17442 restricts an LEI to the upper-case Latin alphabet and the
	// digits; any other rune means this is not an LEI.
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isDigit(c) || isAlpha(c) {
			continue
		}
		return nil, fmt.Errorf("lei: invalid character %q — an LEI is letters and digits only", c)
	}
	if len(s) != leiLength {
		return nil, fmt.Errorf("lei: %d characters — an LEI is exactly %d (ISO 17442)", len(s), leiLength)
	}
	// Positions 19-20 are the check digits and are always numeric.
	if !isDigit(s[18]) || !isDigit(s[19]) {
		return nil, fmt.Errorf("lei: positions 19-20 must be 2 check digits, got %q", s[18:20])
	}

	r := &Result{
		LEI:         s,
		LOUPrefix:   s[:4],
		EntityID:    s[4:18],
		CheckDigits: s[18:20],
	}
	// ISO 17442 reuses ISO 7064 MOD-97-10: the whole LEI, read as a number
	// with each letter expanded to a two-digit value, is valid iff the
	// remainder mod 97 is 1. Unlike an IBAN the check digits are already
	// at the end, so no rearrangement is needed.
	r.Mod97Valid = mod97(s) == 1
	if !r.Mod97Valid {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"MOD-97-10 check failed — the LEI is mistyped; the check digits that would make this body valid are %02d",
			expectedCheckDigits(s)))
	}
	r.Notes = append(r.Notes,
		"the entity-specific part (chars 5-18) is surfaced whole — the ISO 17442 \"00\" reserved characters at "+
			"positions 5-6 are not present in every registered LEI, so it is not split (no confidently-wrong output)")
	return r, nil
}

func isAlpha(c byte) bool { return c >= 'A' && c <= 'Z' }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// mod97 computes the ISO 7064 MOD-97-10 remainder of s, where each
// letter expands to a two-digit number (A=10 … Z=35) and each digit to
// itself. It folds the value piece by piece so no big integer is needed:
// a letter contributes two decimal positions, a digit one.
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

// expectedCheckDigits returns the two check digits that would make s pass
// the MOD-97-10 test. It substitutes "00" for the existing check digits,
// takes the remainder, and applies the ISO 7064 98 - r rule.
func expectedCheckDigits(s string) int {
	return 98 - mod97(s[:18]+"00")
}
