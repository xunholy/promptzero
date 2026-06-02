// SPDX-License-Identifier: AGPL-3.0-or-later

package crc

import "testing"

// TestCatalogue_CheckValues is the verification gate: every model must
// reproduce its published check value (the CRC of "123456789"). A model only
// ships if its parameters match the authoritative reveng reference.
func TestCatalogue_CheckValues(t *testing.T) {
	data := []byte("123456789")
	for _, m := range Catalogue {
		if got := m.Compute(data); got != m.Check {
			t.Errorf("%s: check = 0x%X, want published 0x%X", m.Name, got, m.Check)
		}
	}
}

// TestCompute_KnownVector cross-checks CRC-32/ISO-HDLC against a second known
// vector beyond the check string: the empty input is 0x00000000.
func TestCompute_EmptyAndCheck(t *testing.T) {
	m, ok := Lookup("CRC-32/ISO-HDLC")
	if !ok {
		t.Fatal("CRC-32/ISO-HDLC missing")
	}
	if got := m.Compute(nil); got != 0x00000000 {
		t.Errorf("CRC-32 of empty = 0x%08X, want 0", got)
	}
	if got := m.Compute([]byte("123456789")); got != 0xCBF43926 {
		t.Errorf("CRC-32 check = 0x%08X, want 0xCBF43926", got)
	}
}

// TestIdentify finds the model(s) matching a known data+CRC pair.
func TestIdentify(t *testing.T) {
	data := []byte("123456789")
	matches := Identify(data, 0xCBF43926)
	found := false
	for _, m := range matches {
		if m.Model == "CRC-32/ISO-HDLC" {
			found = true
		}
	}
	if !found {
		t.Errorf("Identify(check, 0xCBF43926) did not include CRC-32/ISO-HDLC; got %+v", matches)
	}
	// A value matching nothing returns empty.
	if got := Identify(data, 0x12345678); len(got) != 0 {
		// 0x12345678 is not any model's check value — extremely unlikely to match.
		for _, m := range got {
			t.Logf("unexpected match: %s", m.Model)
		}
	}
}

// TestCRC24 covers the 24-bit width: check value, 6-hex formatting, and
// identify on the BLE model.
func TestCRC24(t *testing.T) {
	m, ok := Lookup("CRC-24/BLE")
	if !ok {
		t.Fatal("CRC-24/BLE missing")
	}
	got := m.Compute([]byte("123456789"))
	if got != 0xC25A56 {
		t.Errorf("CRC-24/BLE check = 0x%06X, want 0xC25A56", got)
	}
	if m.Format(got) != "0xC25A56" {
		t.Errorf("CRC-24 format = %s, want 0xC25A56", m.Format(got))
	}
	matches := Identify([]byte("123456789"), 0xC25A56)
	found := false
	for _, mm := range matches {
		if mm.Model == "CRC-24/BLE" {
			found = true
		}
	}
	if !found {
		t.Errorf("Identify did not include CRC-24/BLE; got %+v", matches)
	}
}

func TestFormat(t *testing.T) {
	m8, _ := Lookup("CRC-8/SMBUS")
	if m8.Format(0xF4) != "0xF4" {
		t.Errorf("CRC-8 format = %s, want 0xF4", m8.Format(0xF4))
	}
	m16, _ := Lookup("CRC-16/ARC")
	if m16.Format(0xBB3D) != "0xBB3D" {
		t.Errorf("CRC-16 format = %s, want 0xBB3D", m16.Format(0xBB3D))
	}
	m32, _ := Lookup("CRC-32/ISO-HDLC")
	if m32.Format(0xCBF43926) != "0xCBF43926" {
		t.Errorf("CRC-32 format = %s, want 0xCBF43926", m32.Format(0xCBF43926))
	}
}
