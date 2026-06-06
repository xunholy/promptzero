// SPDX-License-Identifier: AGPL-3.0-or-later

package ripng

import (
	"strings"
	"testing"
)

// Vectors produced with scapy's RIPng layer (scapy.contrib.ripng) and
// verified field-for-field.

func TestDecodeResponse(t *testing.T) {
	// RIPng(cmd=2)/RIPngEntry(fe80::1, metric=0xff)  (next-hop)
	//   /RIPngEntry(2001:db8:1::, routetag=10, prefixlen=48, metric=2)
	//   /RIPngEntry(2001:db8:2::, prefixlen=64, metric=16)  (infinity)
	const v = "02010000fe800000000000000000000000000001000000ff20010db8000100000000000000000000000a300220010db800020000000000000000000000004010"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.CommandName != "response" || r.Version != 1 {
		t.Fatalf("cmd/ver = %q/%d", r.CommandName, r.Version)
	}
	if len(r.Entries) != 3 {
		t.Fatalf("entries = %d, want 3", len(r.Entries))
	}
	if !r.Entries[0].IsNextHop || r.Entries[0].NextHop != "fe80::1" {
		t.Errorf("entry0 next-hop = %+v", r.Entries[0])
	}
	e := r.Entries[1]
	if e.Prefix != "2001:db8:1::" || e.PrefixLength != 48 || e.RouteTag != 10 || e.Metric != 2 {
		t.Errorf("entry1 = %+v", e)
	}
	if r.Entries[2].Metric != 16 || r.Entries[2].MetricName == "" {
		t.Errorf("entry2 should be infinity: %+v", r.Entries[2])
	}
}

func TestDecodeWholeTableRequest(t *testing.T) {
	// RIPng(cmd=1)/RIPngEntry(::, prefixlen=0, metric=16)
	const v = "010100000000000000000000000000000000000000000010"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.CommandName != "request" {
		t.Fatalf("cmd = %q", r.CommandName)
	}
	if !r.WholeTableRequest {
		t.Error("expected whole-table request detection")
	}
}

func TestDecodeRejectsBadCommand(t *testing.T) {
	if _, err := Decode("03010000"); err == nil {
		t.Fatal("expected rejection of command 3")
	}
}

func TestDecodeTrailingBytesNoted(t *testing.T) {
	// header + 10 stray bytes (not a full RTE)
	const v = "0201000000112233445566778899"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.Entries) != 0 {
		t.Errorf("entries = %d, want 0", len(r.Entries))
	}
	var noted bool
	for _, n := range r.Notes {
		if strings.Contains(n, "trailing") {
			noted = true
		}
	}
	if !noted {
		t.Error("expected a trailing-bytes note")
	}
}

func TestDecodeTruncated(t *testing.T) {
	if _, err := Decode("0201"); err == nil {
		t.Fatal("expected error on short header")
	}
}
