// SPDX-License-Identifier: AGPL-3.0-or-later

package macaddr

import (
	"fmt"
	"testing"
)

// TestRecoverMAC_HandVector: the canonical example — MAC 00:1A:2B:3C:4D:5E
// becomes interface identifier 021a:2bff:fe3c:4d5e (U/L bit flipped, FF:FE
// inserted), so fe80::21a:2bff:fe3c:4d5e recovers it.
func TestRecoverMAC_HandVector(t *testing.T) {
	r, err := RecoverMAC("fe80::21a:2bff:fe3c:4d5e")
	if err != nil {
		t.Fatal(err)
	}
	if !r.EUI64Derived {
		t.Fatal("should be recognised as EUI-64-derived")
	}
	if r.RecoveredMAC != "00:1A:2B:3C:4D:5E" {
		t.Errorf("recovered MAC = %s, want 00:1A:2B:3C:4D:5E", r.RecoveredMAC)
	}
}

// TestRecoverMAC_RoundTrip builds the IID from a MAC and confirms recovery,
// across universal and locally-administered MACs.
func TestRecoverMAC_RoundTrip(t *testing.T) {
	macs := []string{"00:1A:2B:3C:4D:5E", "DE:AD:BE:EF:00:01", "FFFFFFFFFFFE", "00:00:00:00:00:00"}
	for _, m := range macs {
		iid, err := MACToEUI64IID(m)
		if err != nil {
			t.Fatalf("%s: %v", m, err)
		}
		// Form a link-local address fe80:: + IID.
		v6 := fmt.Sprintf("fe80::%02x%02x:%02x%02x:%02x%02x:%02x%02x",
			iid[0], iid[1], iid[2], iid[3], iid[4], iid[5], iid[6], iid[7])
		r, err := RecoverMAC(v6)
		if err != nil {
			t.Fatalf("%s -> %s: %v", m, v6, err)
		}
		if !r.EUI64Derived {
			t.Errorf("%s: round-trip lost the EUI-64 marker", m)
			continue
		}
		// Classify the recovered MAC to confirm it parses back cleanly.
		if _, err := Classify(r.RecoveredMAC); err != nil {
			t.Errorf("%s: recovered MAC %s does not classify: %v", m, r.RecoveredMAC, err)
		}
	}
}

func TestRecoverMAC_NotEUI64(t *testing.T) {
	// A privacy / random IID with no FF:FE marker.
	r, err := RecoverMAC("2001:db8::dead:beef:cafe:0001")
	if err != nil {
		t.Fatal(err)
	}
	if r.EUI64Derived || r.RecoveredMAC != "" {
		t.Errorf("non-EUI-64 address should not recover a MAC: %+v", r)
	}
	if len(r.Notes) == 0 {
		t.Error("expected an explanatory note")
	}
}

// TestRecoverMAC_RandomizedRecovered: a locally-administered MAC's SLAAC
// address recovers the MAC, which then classifies as randomized.
func TestRecoverMAC_RandomizedRecovered(t *testing.T) {
	r, err := RecoverMAC("fe80::dcad:beff:feef:1")
	if err != nil {
		t.Fatal(err)
	}
	if r.RecoveredMAC != "DE:AD:BE:EF:00:01" { // 0xDC ^ 0x02 = 0xDE
		t.Fatalf("recovered MAC = %s, want DE:AD:BE:EF:00:01", r.RecoveredMAC)
	}
	c, err := Classify(r.RecoveredMAC)
	if err != nil {
		t.Fatal(err)
	}
	if !c.RandomizedLikely {
		t.Error("recovered locally-administered MAC should classify as randomized")
	}
}

func TestRecoverMAC_Errors(t *testing.T) {
	for _, s := range []string{"", "not-an-ip", "192.168.1.1", "10.0.0.1"} {
		if _, err := RecoverMAC(s); err == nil {
			t.Errorf("%q: expected error", s)
		}
	}
}
