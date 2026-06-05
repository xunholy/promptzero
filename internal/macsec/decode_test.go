// SPDX-License-Identifier: AGPL-3.0-or-later

package macsec

import "testing"

// Field values are scapy's (scapy.contrib.macsec) decode of the same
// SecTAG bytes.

func TestDecodeWithSCI(t *testing.T) {
	// byte0=0x2E (SC=1,E=1,C=1,AN=2), SL=0, PN=0x539, SCI=0011223344550001,
	// then 16 octets of secure data (which here is the ICV, no data).
	r, err := Decode("2E00000005390011223344550001aabbccddeeff00112233445566778899")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 0 || r.EndStation || !r.SCIPresent || r.SingleCopyBcast || !r.Encrypted || !r.Changed {
		t.Errorf("TCI flags wrong: %+v", r)
	}
	if r.AssociationNum != 2 {
		t.Errorf("AN = %d; want 2", r.AssociationNum)
	}
	if r.ShortLength != 0 || r.PacketNumber != 0x539 {
		t.Errorf("SL/PN = %d/%d; want 0/1337", r.ShortLength, r.PacketNumber)
	}
	if r.SCI != "0011223344550001" {
		t.Errorf("SCI = %q; want 0011223344550001", r.SCI)
	}
	if r.SystemIdentifier != "00:11:22:33:44:55" || r.PortIdentifier != 1 {
		t.Errorf("system/port = %q/%d; want 00:11:22:33:44:55/1", r.SystemIdentifier, r.PortIdentifier)
	}
	if r.ICVHex != "AABBCCDDEEFF00112233445566778899" {
		t.Errorf("ICV = %q", r.ICVHex)
	}
	if r.SecureDataHex != "" {
		t.Errorf("SecureData = %q; want empty (all 16 bytes are ICV)", r.SecureDataHex)
	}
}

func TestDecodeNoSCI(t *testing.T) {
	// byte0=0x00 (all clear, AN=0), SL=6, PN=1, no SCI, 6 octets.
	r, err := Decode("000600000001aabbccddeeff")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.SCIPresent || r.SCI != "" {
		t.Errorf("SCI should be absent: %+v", r)
	}
	if r.AssociationNum != 0 || r.ShortLength != 6 || r.PacketNumber != 1 {
		t.Errorf("AN/SL/PN = %d/%d/%d; want 0/6/1", r.AssociationNum, r.ShortLength, r.PacketNumber)
	}
	if r.Encrypted {
		t.Error("Encrypted = true; want false")
	}
}

func TestDecodeSCNotEncrypted(t *testing.T) {
	// byte0=0x25 (SC=1,E=0,C=1,AN=1), PN=0xdeadbeef, SCI=aabbccddeeff1234.
	r, err := Decode("2500deadbeefaabbccddeeff123400112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.SCIPresent || r.Encrypted || !r.Changed || r.AssociationNum != 1 {
		t.Errorf("flags/AN wrong: %+v", r)
	}
	if r.PacketNumber != 0xdeadbeef {
		t.Errorf("PN = %d; want %d", r.PacketNumber, uint32(0xdeadbeef))
	}
	if r.SystemIdentifier != "AA:BB:CC:DD:EE:FF" || r.PortIdentifier != 0x1234 {
		t.Errorf("system/port = %q/%d", r.SystemIdentifier, r.PortIdentifier)
	}
}

func TestDecodeFullEthernetFrame(t *testing.T) {
	// dst + src + 0x88E5 + the SecTAG from TestDecodeNoSCI.
	frame := "001122334455" + "66778899aabb" + "88e5" + "000600000001aabbccddeeff"
	r, err := Decode(frame)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.DestMAC != "00:11:22:33:44:55" || r.SrcMAC != "66:77:88:99:AA:BB" {
		t.Errorf("MACs = %q / %q", r.DestMAC, r.SrcMAC)
	}
	if r.PacketNumber != 1 || r.ShortLength != 6 {
		t.Errorf("inner SecTAG not decoded: PN=%d SL=%d", r.PacketNumber, r.ShortLength)
	}
}

func TestDecodeRejects(t *testing.T) {
	for _, c := range []string{"", "zz", "2e00", "20000000010011"} { // empty / non-hex / too short / SC set but no room for SCI
		if _, err := Decode(c); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add("2E00000005390011223344550001aabbccddeeff00112233445566778899")
	f.Add("000600000001aabbccddeeff")
	f.Add("001122334455667788 99aabb88e5000600000001aabbccddeeff")
	f.Add("")
	f.Add("2e")
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s)
	})
}
