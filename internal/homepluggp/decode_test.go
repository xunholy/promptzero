// SPDX-License-Identifier: AGPL-3.0-or-later

package homepluggp

import "testing"

// Vectors are built from scapy.contrib.homepluggp (HomePlug Green PHY) and
// hand-verified against the ISO 15118-3 / HomePlug GP SLAC layout.

func TestSLACParmReq(t *testing.T) {
	// CM_SLAC_PARM_REQ 0x6064: ver=1, app=0, sec=0, runid=1122334455667788
	r, err := Decode("01646000001122334455667788")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MMTypeName != "CM_SLAC_PARM_REQ" {
		t.Errorf("MMTypeName = %q, want CM_SLAC_PARM_REQ", r.MMTypeName)
	}
	if r.SubType != "Request" {
		t.Errorf("SubType = %q, want Request", r.SubType)
	}
	if r.RunID != "1122334455667788" {
		t.Errorf("RunID = %q, want 1122334455667788", r.RunID)
	}
	if r.ApplicationType == nil || *r.ApplicationType != 0 || r.ApplicationTypeName != "PEV-EVSE matching" {
		t.Errorf("ApplicationType = %v / %q", r.ApplicationType, r.ApplicationTypeName)
	}
}

func TestSLACMatchCnfCarriesNMK(t *testing.T) {
	// CM_SLAC_MATCH_CNF 0x607d — the prize: NID + NMK in the clear.
	const v = "017d60000056004556000000000000000000000000000000aabbccddeeff45565345" +
		"0000000000000000000000000011223344556601020304050607080000000000000000" +
		"aabbccddeeff0000000102030405060708090a0b0c0d0e0f"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MMTypeName != "CM_SLAC_MATCH_CNF" {
		t.Errorf("MMTypeName = %q, want CM_SLAC_MATCH_CNF", r.MMTypeName)
	}
	if r.EVID != "EV" {
		t.Errorf("EVID = %q, want EV", r.EVID)
	}
	if r.EVMAC != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("EVMAC = %q", r.EVMAC)
	}
	if r.EVSEID != "EVSE" {
		t.Errorf("EVSEID = %q, want EVSE", r.EVSEID)
	}
	if r.EVSEMAC != "11:22:33:44:55:66" {
		t.Errorf("EVSEMAC = %q", r.EVSEMAC)
	}
	if r.RunID != "0102030405060708" {
		t.Errorf("RunID = %q", r.RunID)
	}
	if r.NID != "AABBCCDDEEFF00" {
		t.Errorf("NID = %q, want AABBCCDDEEFF00", r.NID)
	}
	if r.NMK != "000102030405060708090A0B0C0D0E0F" {
		t.Errorf("NMK = %q", r.NMK)
	}
}

func TestSetKeyReq(t *testing.T) {
	// CM_SET_KEY_REQ 0x6008: keytype=1(NMK) nid=01020304050607 newkey=00..0f
	const v = "01086001aaaaaaaabbbbbbbb02000100000102030405060701000102030405060708090a0b0c0d0e0f"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MMTypeName != "CM_SET_KEY_REQ" {
		t.Errorf("MMTypeName = %q, want CM_SET_KEY_REQ", r.MMTypeName)
	}
	if r.KeyType != "NMK (Network Membership Key)" {
		t.Errorf("KeyType = %q", r.KeyType)
	}
	if r.NID != "01020304050607" {
		t.Errorf("NID = %q, want 01020304050607", r.NID)
	}
	if r.NMK != "000102030405060708090A0B0C0D0E0F" {
		t.Errorf("NMK = %q", r.NMK)
	}
}

func TestStartAttenCharInd(t *testing.T) {
	// CM_START_ATTEN_CHAR_IND 0x606a: app sec nsounds=0a timeout resptype fwd_sta runid
	const v = "016a6000000a0001112233445566aabbccddeeff0011"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MMTypeName != "CM_START_ATTEN_CHAR_IND" {
		t.Errorf("MMTypeName = %q", r.MMTypeName)
	}
	if r.NumberOfSounds == nil || *r.NumberOfSounds != 0x0a {
		t.Errorf("NumberOfSounds = %v, want 10", r.NumberOfSounds)
	}
	if r.ForwardingSTA != "11:22:33:44:55:66" {
		t.Errorf("ForwardingSTA = %q", r.ForwardingSTA)
	}
	if r.RunID != "AABBCCDDEEFF0011" {
		t.Errorf("RunID = %q", r.RunID)
	}
}

func TestSubTypeAndStep(t *testing.T) {
	cases := map[string]string{
		"01646000": "Request",      // PARM_REQ
		"01656000": "Confirmation", // PARM_CNF
		"016a6000": "Indication",   // START_ATTEN_IND
		"016f6000": "Response",     // ATTEN_CHAR_RSP
	}
	for hexPfx, want := range cases {
		r, err := Decode(hexPfx)
		if err != nil {
			t.Fatalf("Decode(%s): %v", hexPfx, err)
		}
		if r.SubType != want {
			t.Errorf("Decode(%s).SubType = %q, want %q", hexPfx, r.SubType, want)
		}
		if r.Step == "" {
			t.Errorf("Decode(%s).Step is empty", hexPfx)
		}
	}
}

func TestRejectNonSLAC(t *testing.T) {
	// 0xA050 is a HomePlug AV vendor MMTYPE (Set Encryption Key), not SLAC.
	if _, err := Decode("0150A0"); err == nil {
		t.Error("expected rejection of non-SLAC MMTYPE 0xA050")
	}
}

func TestShortBodySurfacedRaw(t *testing.T) {
	// PARM_REQ MMTYPE but a truncated 2-byte body — must not panic, surfaced raw.
	r, err := Decode("01646000ffff")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.RunID != "" {
		t.Errorf("RunID should be empty for a short body, got %q", r.RunID)
	}
	if r.BodyHex != "00FFFF" {
		t.Errorf("BodyHex = %q, want 00FFFF", r.BodyHex)
	}
}

func TestErrors(t *testing.T) {
	for _, in := range []string{"", "01", "zz", "07ffff"} { // empty, short, non-hex, bad version
		if _, err := Decode(in); err == nil {
			t.Errorf("Decode(%q) expected error", in)
		}
	}
}
