// SPDX-License-Identifier: AGPL-3.0-or-later

package geneve

import (
	"encoding/json"
	"strings"
	"testing"
)

const (
	innerIPv4UDP = "4500001C00000000401100000A0000010A00000204D2003500080000"
	innerIPv6UDP = "60000000000811400000000000000000000000000000000100000000000000000000000000000002" + "04D2003500080000"
)

// geneveHdr builds an 8-byte Geneve header (version 0, no options, VNI 100)
// with the given protocol type.
func geneveHdr(ptypeHex string) string { return "0000" + ptypeHex + "00006400" }

func mustContain(t *testing.T, v any, wants ...string) {
	t.Helper()
	js, _ := json.Marshal(v)
	for _, w := range wants {
		if !strings.Contains(string(js), w) {
			t.Errorf("missing %q in %s", w, js)
		}
	}
}

func TestDecode_Geneve_DirectIPv4(t *testing.T) {
	// Protocol Type 0x0800 — inner payload is an IP packet directly.
	r, err := Decode(geneveHdr("0800") + innerIPv4UDP)
	if err != nil {
		t.Fatal(err)
	}
	if r.InnerDecodeError != "" || r.InnerPacket == nil {
		t.Fatalf("direct IPv4 not decoded (err=%q)", r.InnerDecodeError)
	}
	mustContain(t, r.InnerPacket, "10.0.0.1", "10.0.0.2", "1234", "53")
}

func TestDecode_Geneve_DirectIPv6(t *testing.T) {
	r, err := Decode(geneveHdr("86DD") + innerIPv6UDP)
	if err != nil {
		t.Fatal(err)
	}
	if r.InnerPacket == nil {
		t.Fatalf("direct IPv6 not decoded (err=%q)", r.InnerDecodeError)
	}
	mustContain(t, r.InnerPacket, "::1", "::2", "1234", "53")
}

func TestDecode_Geneve_TEBInnerIPv4(t *testing.T) {
	// Protocol Type 0x6558 (Transparent Ethernet Bridging) — inner Ethernet
	// frame whose EtherType (0x0800) marks an IPv4 payload.
	frame := geneveHdr("6558") + "AABBCCDDEEFF112233445566" + "0800" + innerIPv4UDP
	r, err := Decode(frame)
	if err != nil {
		t.Fatal(err)
	}
	if r.InnerEthernet == nil || r.InnerEthernet.InnerPacket == nil {
		t.Fatalf("TEB inner IPv4 not decoded: %+v", r.InnerEthernet)
	}
	mustContain(t, r.InnerEthernet.InnerPacket, "10.0.0.1", "10.0.0.2", "1234", "53")
}

func TestDecode_Geneve_DirectIPGarbageSurfacesError(t *testing.T) {
	r, err := Decode(geneveHdr("0800") + "AABB")
	if err != nil {
		t.Fatal(err)
	}
	if r.InnerDecodeError == "" || r.InnerPacket != nil {
		t.Errorf("IP-typed garbage should surface inner_decode_error + no packet: %+v", r)
	}
}

func TestDecode_Geneve_NonIPNotDecoded(t *testing.T) {
	// Protocol Type 0x8847 (MPLS) — not IP, not TEB, left as hex.
	r, err := Decode(geneveHdr("8847") + "AABBCCDD")
	if err != nil {
		t.Fatal(err)
	}
	if r.InnerPacket != nil || r.InnerDecodeError != "" || r.InnerEthernet != nil {
		t.Errorf("MPLS payload should not be IP/Ethernet-decoded: %+v", r)
	}
	if r.PayloadHex == "" {
		t.Errorf("payload should be surfaced as hex")
	}
}
