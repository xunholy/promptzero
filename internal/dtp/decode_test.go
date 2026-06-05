// SPDX-License-Identifier: AGPL-3.0-or-later

package dtp

import (
	"strings"
	"testing"
)

// Field values are scapy's (scapy.contrib.dtp) decode of the same PDUs.

func TestDecodeFullPDU(t *testing.T) {
	// ver=1, domain "LAB", status 0x03, type 0xA5, neighbor 00:11:22:33:44:55
	r, err := Decode("01000100084c414200000200050300030005a50004000a001122334455")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 1 {
		t.Errorf("Version = %d; want 1", r.Version)
	}
	if r.Domain != "LAB" {
		t.Errorf("Domain = %q; want LAB", r.Domain)
	}
	if r.StatusByte != 0x03 || r.StatusHex != "0x03" {
		t.Errorf("Status = %d/%s; want 3/0x03", r.StatusByte, r.StatusHex)
	}
	if r.TrunkType != 0xA5 || r.TrunkTypeHex != "0xA5" {
		t.Errorf("TrunkType = %d/%s; want 165/0xA5", r.TrunkType, r.TrunkTypeHex)
	}
	if r.NeighborMAC != "00:11:22:33:44:55" {
		t.Errorf("NeighborMAC = %q", r.NeighborMAC)
	}
	if !strings.Contains(strings.Join(r.Notes, " "), "VLAN-hopping") {
		t.Error("expected a VLAN-hopping note")
	}
}

func TestDecodeEmptyDomain(t *testing.T) {
	// ver=1, empty domain, status 0x81, type 0x42, neighbor aa:bb:cc:dd:ee:ff
	r, err := Decode("0100010004000200058100030005420004000aaabbccddeeff")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Domain != "" {
		t.Errorf("Domain = %q; want empty", r.Domain)
	}
	if r.StatusByte != 0x81 || r.TrunkType != 0x42 {
		t.Errorf("status/type = %d/%d; want 129/66", r.StatusByte, r.TrunkType)
	}
	if r.NeighborMAC != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("NeighborMAC = %q", r.NeighborMAC)
	}
}

func TestDecodeWithSNAPWrapper(t *testing.T) {
	// LLC (AA AA 03) + SNAP (OUI 00000C, PID 2004) + the PDU.
	pdu := "01000100084c414200000200050300030005a50004000a001122334455"
	r, err := Decode("aaaa03" + "00000c2004" + pdu)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Domain != "LAB" || r.NeighborMAC != "00:11:22:33:44:55" {
		t.Errorf("SNAP-wrapped decode wrong: domain=%q mac=%q", r.Domain, r.NeighborMAC)
	}
}

func TestDecodeRejects(t *testing.T) {
	for _, c := range []string{"", "zz", "01"} { // empty / non-hex / version only, no TLVs
		if _, err := Decode(c); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add("01000100084c414200000200050300030005a50004000a001122334455")
	f.Add("aaaa0300000c200401000100084c414200000200050300030005a50004000a001122334455")
	f.Add("")
	f.Add("01")
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s)
	})
}
