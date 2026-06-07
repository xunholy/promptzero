// SPDX-License-Identifier: AGPL-3.0-or-later

package smp

import "testing"

func TestPairingRequestAuthenticated(t *testing.T) {
	// Pairing Request (0x01): IO KeyboardDisplay (0x04), no OOB, AuthReq 0x0D
	// (bonding + MITM + SC), max key 16, init/resp key dist 0x07.
	r, err := Decode("010400" + "0d" + "10" + "0707")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.CodeName != "Pairing Request" {
		t.Errorf("CodeName = %q", r.CodeName)
	}
	if r.IOCapability != "KeyboardDisplay" {
		t.Errorf("IOCapability = %q", r.IOCapability)
	}
	if r.MITM == nil || !*r.MITM {
		t.Error("MITM should be true")
	}
	if r.SecureConnections == nil || !*r.SecureConnections {
		t.Error("SecureConnections should be true")
	}
	if r.MaxKeySize == nil || *r.MaxKeySize != 16 {
		t.Errorf("MaxKeySize = %v", r.MaxKeySize)
	}
	if len(r.InitiatorKeyDist) != 3 { // EncKey+IdKey+SignKey
		t.Errorf("InitiatorKeyDist = %v", r.InitiatorKeyDist)
	}
	if r.PairingPosture == "" || !contains(r.PairingPosture, "MITM protection requested") {
		t.Errorf("PairingPosture = %q", r.PairingPosture)
	}
}

func TestPairingRequestJustWorks(t *testing.T) {
	// AuthReq 0x01 (bonding, no MITM, no SC) → Just Works posture.
	r, err := Decode("010300" + "01" + "10" + "0000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MITM == nil || *r.MITM {
		t.Error("MITM should be false (Just Works)")
	}
	if !contains(r.PairingPosture, "Just Works") {
		t.Errorf("PairingPosture = %q, want Just Works", r.PairingPosture)
	}
	if !contains(r.PairingPosture, "LE Legacy") {
		t.Errorf("PairingPosture = %q, want LE Legacy (SC clear)", r.PairingPosture)
	}
}

func TestPairingFailed(t *testing.T) {
	// 05 (Pairing Failed) 03 (Authentication Requirements).
	r, err := Decode("0503")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.CodeName != "Pairing Failed" || r.FailReason != "Authentication Requirements" {
		t.Errorf("code/reason = %q/%q", r.CodeName, r.FailReason)
	}
}

func TestSecurityRequest(t *testing.T) {
	// 0B (Security Request) AuthReq 0x0D.
	r, err := Decode("0b0d")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.CodeName != "Security Request" {
		t.Errorf("CodeName = %q", r.CodeName)
	}
	if r.MITM == nil || !*r.MITM {
		t.Error("MITM should be true")
	}
}

func TestIdentityAddress(t *testing.T) {
	// 09 (Identity Address Information) 00 (public) + BD_ADDR LE.
	r, err := Decode("0900" + "ffeeddccbbaa")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.AddressType != "public" {
		t.Errorf("AddressType = %q", r.AddressType)
	}
	// LE bytes ff ee dd cc bb aa → MSB-first AA:BB:CC:DD:EE:FF.
	if r.Address != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("Address = %q", r.Address)
	}
}

func TestKeyMaterialRaw(t *testing.T) {
	// Encryption Information (LTK) — 16-byte key surfaced raw.
	r, err := Decode("06000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.CodeName != "Encryption Information (LTK)" {
		t.Errorf("CodeName = %q", r.CodeName)
	}
	if r.PayloadHex != "000102030405060708090A0B0C0D0E0F" {
		t.Errorf("PayloadHex = %q", r.PayloadHex)
	}
}

func TestErrors(t *testing.T) {
	for _, in := range []string{"", "zz"} {
		if _, err := Decode(in); err == nil {
			t.Errorf("Decode(%q) expected error", in)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
