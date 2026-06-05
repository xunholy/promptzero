// SPDX-License-Identifier: AGPL-3.0-or-later

package mrz

import (
	"strings"
	"testing"
)

// Expected fields + check digits are the `mrz` reference library's decode
// of these canonical ICAO 9303 documents.

const td3 = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<\n" +
	"L898902C36UTO7408122F1204159ZE184226B<<<<<10"

const td1 = "I<UTOD231458907<<<<<<<<<<<<<<<\n" +
	"7408122F1204159UTO<<<<<<<<<<<6\n" +
	"ERIKSSON<<ANNA<MARIA<<<<<<<<<<"

const td2 = "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<\n" +
	"D231458907UTO7408122F1204159<<<<<<<6"

func TestTD3(t *testing.T) {
	r, err := Decode(td3)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Format != "TD3" {
		t.Errorf("format = %s; want TD3", r.Format)
	}
	if r.DocumentType != "P" || r.IssuingCountry != "UTO" || r.Nationality != "UTO" {
		t.Errorf("type/country/nat = %s/%s/%s", r.DocumentType, r.IssuingCountry, r.Nationality)
	}
	if r.Surname != "ERIKSSON" || r.GivenNames != "ANNA MARIA" {
		t.Errorf("name = %q / %q; want ERIKSSON / ANNA MARIA", r.Surname, r.GivenNames)
	}
	if r.DocumentNumber != "L898902C3" || r.BirthDate != "740812" || r.Sex != "F" || r.ExpiryDate != "120415" {
		t.Errorf("docnum/birth/sex/exp = %s/%s/%s/%s", r.DocumentNumber, r.BirthDate, r.Sex, r.ExpiryDate)
	}
	if r.OptionalData != "ZE184226B" {
		t.Errorf("optional = %q; want ZE184226B", r.OptionalData)
	}
	if !r.DocumentNumberCheckOK || !r.BirthDateCheckOK || !r.ExpiryDateCheckOK || !r.CompositeCheckOK || !r.Valid {
		t.Errorf("checks docnum/birth/exp/composite/valid = %v/%v/%v/%v/%v; all want true",
			r.DocumentNumberCheckOK, r.BirthDateCheckOK, r.ExpiryDateCheckOK, r.CompositeCheckOK, r.Valid)
	}
	if r.BirthDateISO != "74-08-12" {
		t.Errorf("birth ISO = %q; want 74-08-12", r.BirthDateISO)
	}
}

func TestTD1(t *testing.T) {
	r, err := Decode(td1)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Format != "TD1" {
		t.Errorf("format = %s; want TD1", r.Format)
	}
	if r.DocumentType != "I" || r.IssuingCountry != "UTO" || r.Nationality != "UTO" {
		t.Errorf("type/country/nat = %s/%s/%s", r.DocumentType, r.IssuingCountry, r.Nationality)
	}
	if r.DocumentNumber != "D23145890" || r.BirthDate != "740812" || r.Sex != "F" || r.ExpiryDate != "120415" {
		t.Errorf("docnum/birth/sex/exp = %s/%s/%s/%s", r.DocumentNumber, r.BirthDate, r.Sex, r.ExpiryDate)
	}
	if r.Surname != "ERIKSSON" || r.GivenNames != "ANNA MARIA" {
		t.Errorf("name = %q / %q", r.Surname, r.GivenNames)
	}
	if !r.DocumentNumberCheckOK || !r.BirthDateCheckOK || !r.ExpiryDateCheckOK || !r.CompositeCheckOK || !r.Valid {
		t.Errorf("checks = %v/%v/%v/%v/%v; all want true",
			r.DocumentNumberCheckOK, r.BirthDateCheckOK, r.ExpiryDateCheckOK, r.CompositeCheckOK, r.Valid)
	}
}

func TestTD2(t *testing.T) {
	r, err := Decode(td2)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Format != "TD2" {
		t.Errorf("format = %s; want TD2", r.Format)
	}
	if r.DocumentNumber != "D23145890" || r.Nationality != "UTO" || r.BirthDate != "740812" || r.ExpiryDate != "120415" {
		t.Errorf("docnum/nat/birth/exp = %s/%s/%s/%s", r.DocumentNumber, r.Nationality, r.BirthDate, r.ExpiryDate)
	}
	if r.Surname != "ERIKSSON" || r.GivenNames != "ANNA MARIA" {
		t.Errorf("name = %q / %q", r.Surname, r.GivenNames)
	}
	if !r.DocumentNumberCheckOK || !r.BirthDateCheckOK || !r.ExpiryDateCheckOK || !r.CompositeCheckOK || !r.Valid {
		t.Errorf("checks = %v/%v/%v/%v/%v; all want true",
			r.DocumentNumberCheckOK, r.BirthDateCheckOK, r.ExpiryDateCheckOK, r.CompositeCheckOK, r.Valid)
	}
}

func TestSingleLineInput(t *testing.T) {
	// TD3 with the newline removed (88 chars) must split + decode.
	r, err := Decode(strings.ReplaceAll(td3, "\n", ""))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Format != "TD3" || r.DocumentNumber != "L898902C3" {
		t.Errorf("got format=%s docnum=%s", r.Format, r.DocumentNumber)
	}
}

func TestTamperedCheckDigitFlagged(t *testing.T) {
	// Change the document number's check digit (6 → 5) on line 2.
	bad := strings.Replace(td3, "L898902C36UTO", "L898902C35UTO", 1)
	r, err := Decode(bad)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.DocumentNumberCheckOK {
		t.Error("DocumentNumberCheckOK = true; want false for tampered check digit")
	}
	if r.Valid {
		t.Error("Valid = true; want false")
	}
	if !strings.Contains(strings.Join(r.Notes, " "), "document number") {
		t.Error("expected a note naming the failed field")
	}
}

func TestCheckDigitAlgorithm(t *testing.T) {
	// ICAO 9303 canonical worked example: check digit of "D23145890"
	// is 7, and of the date "740812" is 2.
	if got := checkDigit("D23145890"); got != 7 {
		t.Errorf("checkDigit(D23145890) = %d; want 7", got)
	}
	if got := checkDigit("740812"); got != 2 {
		t.Errorf("checkDigit(740812) = %d; want 2", got)
	}
}

func TestRejects(t *testing.T) {
	for _, c := range []string{"", "too short", "P<UTO\nL898902C3"} {
		if _, err := Decode(c); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(td3)
	f.Add(td1)
	f.Add(td2)
	f.Add(strings.ReplaceAll(td3, "\n", ""))
	f.Add("")
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s)
	})
}
