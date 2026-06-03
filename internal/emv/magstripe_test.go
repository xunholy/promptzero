// SPDX-License-Identifier: AGPL-3.0-or-later

package emv

import "testing"

// 4111111111111111 is the canonical Luhn-valid Visa test PAN — the verification
// anchor for the parse (a misframed PAN fails Luhn).
func TestDecodeMagstripe_Track1(t *testing.T) {
	m, err := DecodeMagstripe("%B4111111111111111^DOE/JOHN^25121011200000000000?2")
	if err != nil {
		t.Fatal(err)
	}
	if m.Track1 == nil {
		t.Fatal("track1 not parsed")
	}
	t1 := m.Track1
	if t1.FormatCode != "B" {
		t.Errorf("format = %q, want B", t1.FormatCode)
	}
	if t1.PAN != "4111111111111111" || !t1.LuhnValid {
		t.Errorf("PAN/luhn wrong: %q luhn=%v", t1.PAN, t1.LuhnValid)
	}
	if t1.Name != "DOE/JOHN" || t1.Surname != "DOE" || t1.GivenName != "JOHN" {
		t.Errorf("name parse: %q / %q / %q", t1.Name, t1.Surname, t1.GivenName)
	}
	if t1.Expiry != "2512" || t1.ExpiryFormatted != "12/25" {
		t.Errorf("expiry: %q %q", t1.Expiry, t1.ExpiryFormatted)
	}
	if t1.ServiceCode != "101" || t1.ServiceCodeMeaning == "" {
		t.Errorf("service: %q (%q)", t1.ServiceCode, t1.ServiceCodeMeaning)
	}
}

func TestDecodeMagstripe_Track2(t *testing.T) {
	m, err := DecodeMagstripe(";4111111111111111=25121011200000000000?")
	if err != nil {
		t.Fatal(err)
	}
	if m.Track2 == nil {
		t.Fatal("track2 not parsed")
	}
	if m.Track2.PAN != "4111111111111111" || !m.Track2.LuhnValid {
		t.Errorf("PAN/luhn: %q %v", m.Track2.PAN, m.Track2.LuhnValid)
	}
	if m.Track2.Expiry != "2512" || m.Track2.ServiceCode != "101" {
		t.Errorf("expiry/service: %q %q", m.Track2.Expiry, m.Track2.ServiceCode)
	}
}

func TestDecodeMagstripe_BothTracks(t *testing.T) {
	swipe := "%B5555555555554444^CARD/TEST^26011200000?;5555555555554444=2601120000?"
	m, err := DecodeMagstripe(swipe)
	if err != nil {
		t.Fatal(err)
	}
	if m.Track1 == nil || m.Track2 == nil {
		t.Fatalf("both tracks expected: t1=%v t2=%v", m.Track1 != nil, m.Track2 != nil)
	}
	// 5555555555554444 is the Luhn-valid Mastercard test PAN.
	if !m.Track1.LuhnValid || !m.Track2.LuhnValid {
		t.Error("Mastercard test PAN should be Luhn-valid on both tracks")
	}
}

func TestDecodeMagstripe_LuhnCatchesTamper(t *testing.T) {
	m, err := DecodeMagstripe(";4111111111111112=2512101?")
	if err != nil {
		t.Fatal(err)
	}
	if m.Track2.LuhnValid {
		t.Error("tampered PAN must fail Luhn")
	}
}

func TestDecodeMagstripe_Errors(t *testing.T) {
	if _, err := DecodeMagstripe(""); err == nil {
		t.Error("empty input should error")
	}
	if _, err := DecodeMagstripe("no sentinels here"); err == nil {
		t.Error("no track should error")
	}
	// Missing end sentinel on track 2 → note, no track2, but not a hard error
	// unless nothing parses.
	if _, err := DecodeMagstripe(";4111111111111111=2512101"); err == nil {
		t.Error("missing '?' with no other track should error")
	}
}
