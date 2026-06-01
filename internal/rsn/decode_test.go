// SPDX-License-Identifier: AGPL-3.0-or-later

package rsn

import "testing"

// TestDecode_WPA2PersonalPMFCapable: version 1, group CCMP, pairwise CCMP,
// AKM PSK, RSN caps 0x0080 (MFPC capable, not required).
func TestDecode_WPA2PersonalPMFCapable(t *testing.T) {
	// 0100 000FAC04 0100 000FAC04 0100 000FAC02 8000
	r, err := Decode("0100000FAC040100000FAC040100000FAC028000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 1 {
		t.Errorf("version = %d, want 1", r.Version)
	}
	if r.GroupCipher.Name != "CCMP-128" {
		t.Errorf("group cipher = %s, want CCMP-128", r.GroupCipher.Name)
	}
	if len(r.PairwiseCiphers) != 1 || r.PairwiseCiphers[0].Name != "CCMP-128" {
		t.Errorf("pairwise = %+v, want [CCMP-128]", r.PairwiseCiphers)
	}
	if len(r.AKMSuites) != 1 || r.AKMSuites[0].Name != "PSK" {
		t.Errorf("akm = %+v, want [PSK]", r.AKMSuites)
	}
	if !r.PMFCapable || r.PMFRequired {
		t.Errorf("pmf capable=%v required=%v, want capable=true required=false", r.PMFCapable, r.PMFRequired)
	}
	if r.Security != "WPA2-Personal (PSK)" {
		t.Errorf("security = %q, want 'WPA2-Personal (PSK)'", r.Security)
	}
}

// TestDecode_WPA3Transition: AKM SAE + PSK, RSN caps 0x00C0 (MFPC + MFPR).
func TestDecode_WPA3Transition(t *testing.T) {
	// 0100 000FAC04 0100 000FAC04 0200 000FAC08 000FAC02 C000
	r, err := Decode("0100000FAC040100000FAC040200000FAC08000FAC02C000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.AKMSuites) != 2 {
		t.Fatalf("akm count = %d, want 2", len(r.AKMSuites))
	}
	if r.AKMSuites[0].Name != "SAE" || r.AKMSuites[1].Name != "PSK" {
		t.Errorf("akm = %s,%s want SAE,PSK", r.AKMSuites[0].Name, r.AKMSuites[1].Name)
	}
	if !r.PMFRequired || !r.PMFCapable {
		t.Errorf("pmf required=%v capable=%v, want both true", r.PMFRequired, r.PMFCapable)
	}
	if r.Security != "WPA3-Personal transition (SAE + PSK)" {
		t.Errorf("security = %q", r.Security)
	}
}

// TestDecode_OWE: AKM 18 (OWE) -> Enhanced Open.
func TestDecode_OWE(t *testing.T) {
	// 0100 000FAC04 0100 000FAC04 0100 000FAC12  (0x12 = 18 OWE)
	r, err := Decode("0100000FAC040100000FAC040100000FAC12")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.AKMSuites[0].Name != "OWE" {
		t.Errorf("akm = %s, want OWE", r.AKMSuites[0].Name)
	}
	if r.Security != "Enhanced Open (OWE)" {
		t.Errorf("security = %q, want Enhanced Open (OWE)", r.Security)
	}
}

// TestDecode_FullIE strips the element ID 0x30 + length header.
func TestDecode_FullIE(t *testing.T) {
	// 30 14 <20-byte body from the WPA2 case>
	r, err := Decode("3014" + "0100000FAC040100000FAC040100000FAC028000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Security != "WPA2-Personal (PSK)" {
		t.Errorf("security = %q after IE strip", r.Security)
	}
}

// TestDecode_GroupMgmtCipher: a WPA3-SAE RSNE with PMKID count 0 and a
// group management cipher (BIP-CMAC-128) trailing.
func TestDecode_GroupMgmtCipher(t *testing.T) {
	// 0100 000FAC04 0100 000FAC04 0100 000FAC08 C000 0000 000FAC06
	r, err := Decode("0100000FAC040100000FAC040100000FAC08C0000000000FAC06")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.GroupMgmtCipher == nil || r.GroupMgmtCipher.Name != "BIP-CMAC-128" {
		t.Errorf("group mgmt cipher = %+v, want BIP-CMAC-128", r.GroupMgmtCipher)
	}
	if r.Security != "WPA3-Personal (SAE)" {
		t.Errorf("security = %q, want WPA3-Personal (SAE)", r.Security)
	}
}

// TestDecode_VendorSuiteNotGuessed: a non-standard OUI suite is surfaced
// raw, not named.
func TestDecode_VendorSuiteNotGuessed(t *testing.T) {
	// group cipher OUI 00-50-F2 type 2 (WPA1 TKIP, vendor OUI) -> raw form.
	r, err := Decode("01000050F2020100000FAC040100000FAC02")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.GroupCipher.Name != "00-50-F2-2" {
		t.Errorf("vendor group cipher = %q, want raw 00-50-F2-2", r.GroupCipher.Name)
	}
}

func TestDecode_Errors(t *testing.T) {
	if _, err := Decode(""); err == nil {
		t.Error("expected error for empty input")
	}
	if _, err := Decode("0100"); err == nil {
		t.Error("expected error for too-short element")
	}
	if _, err := Decode("zz"); err == nil {
		t.Error("expected error for non-hex")
	}
}
