// SPDX-License-Identifier: AGPL-3.0-or-later

package icmpext

import "testing"

// Vectors are built from scapy.contrib.icmp_extensions + scapy.contrib.mpls
// and hand-verified against RFC 4884 / RFC 4950.

func TestMPLSSingleLabel(t *testing.T) {
	// ext header v2 + MPLS object: label=16000 tc=0 s=1 ttl=64
	// + an Interface Information object (surfaced raw).
	const v = "2000dfff0008010103e801400014020d0000000700010000c0000201000005dc"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 2 {
		t.Errorf("Version = %d, want 2", r.Version)
	}
	if r.Checksum != "0xDFFF" {
		t.Errorf("Checksum = %q", r.Checksum)
	}
	if len(r.Objects) != 2 {
		t.Fatalf("got %d objects, want 2", len(r.Objects))
	}
	o := r.Objects[0]
	if o.ClassNum != 1 || o.ClassName != "MPLS Label Stack (RFC 4950)" {
		t.Errorf("obj0 class = %d/%q", o.ClassNum, o.ClassName)
	}
	if len(o.MPLSStack) != 1 {
		t.Fatalf("obj0 stack len = %d, want 1", len(o.MPLSStack))
	}
	l := o.MPLSStack[0]
	if l.Label != 16000 || l.TrafficClass != 0 || !l.BottomOfStack || l.TTL != 64 {
		t.Errorf("label = %+v, want {16000 0 true 64}", l)
	}
	// Interface Information surfaced raw, not field-decoded.
	o2 := r.Objects[1]
	if o2.ClassNum != 2 || o2.ClassName != "Interface Information (RFC 5837)" {
		t.Errorf("obj1 class = %d/%q", o2.ClassNum, o2.ClassName)
	}
	if o2.PayloadHex == "" || len(o2.MPLSStack) != 0 {
		t.Errorf("obj1 should be raw payload, got %+v", o2)
	}
}

func TestMPLSTwoLabelStack(t *testing.T) {
	// outer label=100 tc=5 s=0 ttl=255; inner label=200 tc=0 s=1 ttl=10
	const v = "2000dfff000c010100064aff000c810a"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.Objects) != 1 || len(r.Objects[0].MPLSStack) != 2 {
		t.Fatalf("got objects=%d stack=%v", len(r.Objects), r.Objects)
	}
	st := r.Objects[0].MPLSStack
	if st[0].Label != 100 || st[0].TrafficClass != 5 || st[0].BottomOfStack || st[0].TTL != 255 {
		t.Errorf("outer = %+v, want {100 5 false 255}", st[0])
	}
	if st[1].Label != 200 || st[1].TrafficClass != 0 || !st[1].BottomOfStack || st[1].TTL != 10 {
		t.Errorf("inner = %+v, want {200 0 true 10}", st[1])
	}
}

func TestMalformedObjectLengthSurfacedRaw(t *testing.T) {
	// ext header + an object claiming length 0xFFFF (overruns) — remainder raw.
	const v = "2000dfffffff0101deadbeef"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.Objects) != 1 {
		t.Fatalf("got %d objects, want 1", len(r.Objects))
	}
	if r.Objects[0].PayloadHex == "" {
		t.Error("expected the overrunning object surfaced raw")
	}
}

func TestErrors(t *testing.T) {
	for _, in := range []string{"", "200012", "zz", "20001234"} {
		// empty, 3 bytes, non-hex, header-only-no-objects
		if _, err := Decode(in); err == nil {
			t.Errorf("Decode(%q) expected error", in)
		}
	}
}
