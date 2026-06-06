// SPDX-License-Identifier: AGPL-3.0-or-later

package carp

import (
	"math"
	"strings"
	"testing"
)

// Field values are scapy's (scapy.contrib.carp) decode of the same PDUs.

func TestDecodeAdvertisement(t *testing.T) {
	// version 2, type 1, vhid 5, advskew 10, authlen 7, demotion 0, advbase 1
	r, err := Decode("21050a07000127f81122334455667788a1a2a3a4b1b2b3b4c1c2c3c4d1d2d3d4e1e2e3e4")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 2 || r.Type != 1 || r.TypeName != "advertisement" {
		t.Errorf("version/type = %d/%d(%q)", r.Version, r.Type, r.TypeName)
	}
	if r.VHID != 5 || r.AdvSkew != 10 || r.AuthLen != 7 || r.Demotion != 0 || r.AdvBase != 1 {
		t.Errorf("fields wrong: %+v", r)
	}
	if math.Abs(r.AdvIntervalSec-(1+10.0/256)) > 1e-9 {
		t.Errorf("AdvIntervalSec = %v; want %v", r.AdvIntervalSec, 1+10.0/256)
	}
	if r.CounterHex != "1122334455667788" {
		t.Errorf("CounterHex = %q", r.CounterHex)
	}
	if r.HMACSHA1Hex != "A1A2A3A4B1B2B3B4C1C2C3C4D1D2D3D4E1E2E3E4" {
		t.Errorf("HMAC = %q", r.HMACSHA1Hex)
	}
}

func TestDecodeHijackSignal(t *testing.T) {
	// advskew 0 (the strongest preemption / hijack signal), vhid 200.
	r, err := Decode("21c800070003de2c00000000000000010000000000000000000000000000000000000000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.VHID != 200 || r.AdvSkew != 0 || r.AdvBase != 3 {
		t.Errorf("vhid/skew/base = %d/%d/%d; want 200/0/3", r.VHID, r.AdvSkew, r.AdvBase)
	}
	if !strings.Contains(strings.Join(r.Notes, " "), "hijack") {
		t.Error("expected the hijack/MITM note")
	}
}

func TestDecodeStripsIPv4Header(t *testing.T) {
	// A minimal 20-byte IPv4 header (proto 112 at offset 9) + the CARP PDU.
	ip := "45000038000000004070000ac0a80101e0000012" // proto 0x70=112 at byte 9
	carp := "21050a07000127f81122334455667788a1a2a3a4b1b2b3b4c1c2c3c4d1d2d3d4e1e2e3e4"
	r, err := Decode(ip + carp)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.VHID != 5 || r.AdvSkew != 10 {
		t.Errorf("IP-stripped decode wrong: vhid=%d skew=%d", r.VHID, r.AdvSkew)
	}
}

func TestDecodeRejects(t *testing.T) {
	for _, c := range []string{"", "zz", "21050a07"} { // empty / non-hex / too short
		if _, err := Decode(c); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add("21050a07000127f81122334455667788a1a2a3a4b1b2b3b4c1c2c3c4d1d2d3d4e1e2e3e4")
	f.Add("45000038000000004070000ac0a80101e000001221050a07000127f81122334455667788a1a2a3a4b1b2b3b4c1c2c3c4d1d2d3d4e1e2e3e4")
	f.Add("")
	f.Add("21")
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s)
	})
}
