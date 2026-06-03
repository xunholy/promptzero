// SPDX-License-Identifier: AGPL-3.0-or-later

package pppoe

import (
	"encoding/json"
	"strings"
	"testing"
)

const (
	innerIPv4UDP = "4500001C00000000401100000A0000010A00000204D2003500080000"
	innerIPv6UDP = "60000000000811400000000000000000000000000000000100000000000000000000000000000002" + "04D2003500080000"
)

func u16(n int) string {
	const h = "0123456789ABCDEF"
	return string([]byte{h[(n>>12)&0xF], h[(n>>8)&0xF], h[(n>>4)&0xF], h[n&0xF]})
}

// session builds a PPPoE Session-Data frame (ver1/type1, code 0x00, session 1)
// carrying a PPP frame with the given protocol + payload.
func session(pppProtoHex, payloadHex string) string {
	ppp := pppProtoHex + payloadHex
	length := len(ppp) / 2
	return "1100" + "0001" + u16(length) + ppp
}

func has(t *testing.T, v any, wants ...string) {
	t.Helper()
	js, _ := json.Marshal(v)
	for _, w := range wants {
		if !strings.Contains(string(js), w) {
			t.Errorf("missing %q in %s", w, js)
		}
	}
}

func TestDecode_PPPoE_InnerIPv4(t *testing.T) {
	r, err := Decode(session("0021", innerIPv4UDP))
	if err != nil {
		t.Fatal(err)
	}
	if r.InnerDecodeError != "" || r.InnerPacket == nil {
		t.Fatalf("inner IPv4 not decoded (err=%q)", r.InnerDecodeError)
	}
	has(t, r.InnerPacket, "10.0.0.1", "10.0.0.2", "1234", "53")
}

func TestDecode_PPPoE_InnerIPv6(t *testing.T) {
	r, err := Decode(session("0057", innerIPv6UDP))
	if err != nil {
		t.Fatal(err)
	}
	if r.InnerPacket == nil {
		t.Fatalf("inner IPv6 not decoded (err=%q)", r.InnerDecodeError)
	}
	has(t, r.InnerPacket, "::1", "::2", "1234", "53")
}

func TestDecode_PPPoE_LCPNotDecoded(t *testing.T) {
	// PPP protocol 0xC021 (LCP) — control protocol, not IP.
	r, err := Decode(session("C021", "01010004"))
	if err != nil {
		t.Fatal(err)
	}
	if r.InnerPacket != nil || r.InnerDecodeError != "" {
		t.Errorf("LCP should not be IP-decoded: %+v", r.InnerPacket)
	}
}

func TestDecode_PPPoE_IPTypedGarbageSurfacesError(t *testing.T) {
	r, err := Decode(session("0021", "45AB"))
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
