// SPDX-License-Identifier: AGPL-3.0-or-later

package gre

import (
	"encoding/json"
	"strings"
	"testing"
)

// Minimal inner packets (IP header + 8-byte L4), same as an ICMP quote.
const (
	innerIPv4UDP = "4500001C00000000401100000A0000010A00000204D2003500080000"
	innerIPv6UDP = "60000000000811400000000000000000000000000000000100000000000000000000000000000002" + "04D2003500080000"
)

func TestDecode_GRE_InnerIPv4(t *testing.T) {
	// GRE: flags 0x0000, protocol_type 0x0800 (IPv4) + inner IPv4/UDP.
	r, err := Decode("00000800" + innerIPv4UDP)
	if err != nil {
		t.Fatal(err)
	}
	if r.InnerDecodeError != "" {
		t.Fatalf("inner decode error: %q", r.InnerDecodeError)
	}
	if r.InnerPacket == nil {
		t.Fatal("inner IPv4 packet not decoded")
	}
	js, _ := json.Marshal(r.InnerPacket)
	for _, want := range []string{"10.0.0.1", "10.0.0.2", "1234", "53"} {
		if !strings.Contains(string(js), want) {
			t.Errorf("inner decode missing %q in %s", want, js)
		}
	}
}

func TestDecode_GRE_InnerIPv6(t *testing.T) {
	r, err := Decode("000086DD" + innerIPv6UDP)
	if err != nil {
		t.Fatal(err)
	}
	if r.InnerPacket == nil {
		t.Fatalf("inner IPv6 packet not decoded (err=%q)", r.InnerDecodeError)
	}
	js, _ := json.Marshal(r.InnerPacket)
	for _, want := range []string{"::1", "::2", "1234", "53"} {
		if !strings.Contains(string(js), want) {
			t.Errorf("inner v6 decode missing %q in %s", want, js)
		}
	}
}

func TestDecode_GRE_NonIPNotDecoded(t *testing.T) {
	// Protocol type 0x6558 (Transparent Ethernet Bridging) — not IP, so the
	// payload must NOT be run through the IP decoder.
	r, err := Decode("00006558" + "AABBCCDDEEFF")
	if err != nil {
		t.Fatal(err)
	}
	if r.InnerPacket != nil || r.InnerDecodeError != "" {
		t.Errorf("non-IP payload should not be IP-decoded: %+v", r.InnerPacket)
	}
	if r.PayloadHex == "" {
		t.Errorf("payload should still be surfaced as hex")
	}
}

func TestDecode_GRE_IPTypedGarbageSurfacesError(t *testing.T) {
	// Protocol type says IPv4 but the payload is not a valid IP packet.
	r, err := Decode("00000800" + "AABB")
	if err != nil {
		t.Fatal(err)
	}
	if r.InnerDecodeError == "" {
		t.Errorf("IP-typed garbage should surface an inner_decode_error")
	}
	if r.InnerPacket != nil {
		t.Errorf("garbage should not produce a decoded inner packet")
	}
}
