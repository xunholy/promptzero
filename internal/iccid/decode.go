// SPDX-License-Identifier: AGPL-3.0-or-later

// Package iccid decodes an Integrated Circuit Card Identifier — the
// serial number printed on, and stored in, a SIM/USIM card (ITU-T
// E.118 / ISO-IEC 7812). It is the SIM-card leg of the cellular
// identifier triad: internal/imei (the device), internal/imsi (the
// subscriber) and the ICCID (the physical card). The three together
// are the identities a SIM swap / forensic seizure / IMSI-catcher
// engagement enumerates.
//
// # Wrap-vs-native judgement
//
//	Native. The ICCID structure (the "89" telecom Major Industry
//	Identifier, an E.164 country code, the issuer + account digits,
//	and a trailing Luhn check digit per ISO/IEC 7812) is a fixed
//	digit-field layout, and the Luhn algorithm + E.164 calling-code
//	table are public. Decoding is Luhn arithmetic plus a prefix-table
//	lookup — a runtime dependency is not justified. stdlib only, no
//	new go.mod dep. The E.164 calling-code → country table
//	(callingcode_table.go) is code-generated from Google
//	libphonenumber + pycountry (authoritative, machine-readable),
//	not hand-transcribed.
//
// # Verifiable / no confidently-wrong output
//
//	The Luhn check digit is the verification anchor — it is recomputed
//	and compared, and a mismatch is reported as luhn_valid=false with
//	a note (a mistyped digit, or a card whose printed form omits the
//	check digit), never asserted as definitively fake. The "89" MII
//	is a fixed prefix. The E.164 calling codes are a prefix-free set,
//	so the country code (the digits after "89") is parsed
//	unambiguously by longest-valid-prefix. The issuer identifier and
//	the individual account number are NOT split from each other — the
//	issuer-identifier length varies by operator with no public fixed
//	rule, so they are surfaced combined rather than guessed (the same
//	reason imei_decode defers the TAC→device lookup and imsi_decode
//	defers the operator name).
package iccid

import (
	"fmt"
	"strings"
)

// Result is the decoded view of an ICCID.
type Result struct {
	ICCID             string   `json:"iccid"`
	MII               string   `json:"mii"` // Major Industry Identifier (89 = telecom)
	MIIValid          bool     `json:"mii_valid"`
	CountryCode       string   `json:"country_code"` // E.164 calling code
	Country           string   `json:"country,omitempty"`
	Region            string   `json:"region,omitempty"` // ISO 3166-1 alpha-2
	SharedCountryCode bool     `json:"shared_country_code,omitempty"`
	IssuerAndAccount  string   `json:"issuer_and_account"`
	CheckDigit        string   `json:"check_digit"`
	LuhnValid         bool     `json:"luhn_valid"`
	Notes             []string `json:"notes,omitempty"`
}

// Decode validates and breaks down an ICCID. Separators (spaces, '-',
// ':') are tolerated.
func Decode(raw string) (*Result, error) {
	d := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, raw)
	if d == "" {
		return nil, fmt.Errorf("iccid: no digits in input")
	}
	if len(d) < 12 || len(d) > 22 {
		return nil, fmt.Errorf("iccid: %d digits — an ICCID is normally 19-20 digits (ITU-T E.118)", len(d))
	}
	r := &Result{ICCID: d, MII: d[:2]}
	r.MIIValid = r.MII == "89"
	if !r.MIIValid {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"Major Industry Identifier is %s, not 89 (telecommunications) — this may not be a SIM ICCID", r.MII))
	}

	// Luhn check: the last digit is the ISO/IEC 7812 check digit.
	r.CheckDigit = d[len(d)-1:]
	r.LuhnValid = luhnValid(d)
	if !r.LuhnValid {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"Luhn check digit %s does not match the computed %d — the ICCID is mistyped, or its printed form omits the check digit",
			r.CheckDigit, luhnCheckDigit(d[:len(d)-1])))
	}

	// Country code: longest valid E.164 prefix after the "89" MII.
	rest := d[2:]
	matched := false
	for l := 1; l <= 3 && l <= len(rest); l++ {
		if entry, ok := callingCodeTable[rest[:l]]; ok {
			r.CountryCode = rest[:l]
			r.Country = entry.country
			r.Region = entry.region
			r.SharedCountryCode = entry.shared
			if entry.shared {
				r.Notes = append(r.Notes, fmt.Sprintf(
					"country code +%s is shared by several territories; %s is the primary one", r.CountryCode, entry.country))
			}
			// issuer + account = between the country code and the check digit.
			r.IssuerAndAccount = rest[l : len(rest)-1]
			matched = true
			break
		}
	}
	if !matched {
		r.Notes = append(r.Notes, "no E.164 country code matched the digits after the MII; issuer and account left undetermined")
		r.IssuerAndAccount = rest[:len(rest)-1]
	}
	r.Notes = append(r.Notes,
		"the issuer identifier and individual account number are surfaced combined — the issuer-identifier length varies by operator with no public fixed rule, so they are not split (no confidently-wrong guess)")
	return r, nil
}

// luhnValid reports whether the full digit string satisfies the Luhn
// (mod-10) checksum.
func luhnValid(d string) bool {
	sum := 0
	double := false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if double {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		double = !double
	}
	return sum%10 == 0
}

// luhnCheckDigit computes the check digit that would make body+digit
// satisfy the Luhn checksum (body excludes the check digit).
func luhnCheckDigit(body string) int {
	sum := 0
	double := true // the check digit sits at position 0, so body's last digit doubles
	for i := len(body) - 1; i >= 0; i-- {
		n := int(body[i] - '0')
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
