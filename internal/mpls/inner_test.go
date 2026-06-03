// SPDX-License-Identifier: AGPL-3.0-or-later

package mpls

import (
	"encoding/json"
	"strings"
	"testing"
)

const (
	innerIPv4UDP = "4500001C00000000401100000A0000010A00000204D2003500080000"
	innerIPv6UDP = "60000000000811400000000000000000000000000000000100000000000000000000000000000002" + "04D2003500080000"
)

// labelBOS is a single bottom-of-stack MPLS label (label 100, TC 0, TTL 64):
// word = (100<<12)|(1<<8)|64 = 0x00064140.
const labelBOS = "00064140"

func mustContain(t *testing.T, v any, wants ...string) {
	t.Helper()
	js, _ := json.Marshal(v)
	for _, w := range wants {
		if !strings.Contains(string(js), w) {
			t.Errorf("missing %q in %s", w, js)
		}
	}
}

func TestDecode_MPLS_InnerIPv4(t *testing.T) {
	r, err := Decode(labelBOS + innerIPv4UDP)
	if err != nil {
		t.Fatal(err)
	}
	if r.InnerDecodeError != "" || r.InnerPacket == nil {
		t.Fatalf("inner IPv4 not decoded (err=%q)", r.InnerDecodeError)
	}
	mustContain(t, r.InnerPacket, "10.0.0.1", "10.0.0.2", "1234", "53")
}

func TestDecode_MPLS_InnerIPv6(t *testing.T) {
	r, err := Decode(labelBOS + innerIPv6UDP)
	if err != nil {
		t.Fatal(err)
	}
	if r.InnerPacket == nil {
		t.Fatalf("inner IPv6 not decoded (err=%q)", r.InnerDecodeError)
	}
	mustContain(t, r.InnerPacket, "::1", "::2", "1234", "53")
}

func TestDecode_MPLS_IPv4ExplicitNull(t *testing.T) {
	// Bottom label 0 (IPv4 Explicit NULL): word = (0<<12)|(1<<8)|64 = 0x00000140.
	r, err := Decode("00000140" + innerIPv4UDP)
	if err != nil {
		t.Fatal(err)
	}
	if r.InnerPacket == nil {
		t.Fatalf("explicit-NULL inner IPv4 not decoded: %+v", r)
	}
	mustContain(t, r.InnerPacket, "10.0.0.1", "10.0.0.2")
}

func TestDecode_MPLS_EoMPLSNotDecoded(t *testing.T) {
	// First nibble 0x0 (EoMPLS / pseudowire control word) — not IP.
	r, err := Decode(labelBOS + "00000000AABBCCDD")
	if err != nil {
		t.Fatal(err)
	}
	if r.InnerPacket != nil || r.InnerDecodeError != "" {
		t.Errorf("EoMPLS payload should not be IP-decoded: %+v", r.InnerPacket)
	}
}

func TestDecode_MPLS_IPTypedGarbageSurfacesError(t *testing.T) {
	// First nibble 0x4 (looks like IPv4) but not a valid packet.
	r, err := Decode(labelBOS + "45AB")
	if err != nil {
		t.Fatal(err)
	}
	if r.InnerDecodeError == "" {
		t.Errorf("IP-typed garbage should surface inner_decode_error")
	}
	if r.InnerPacket != nil {
		t.Errorf("garbage should not produce a decoded inner packet")
	}
}
