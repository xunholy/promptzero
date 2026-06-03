// SPDX-License-Identifier: AGPL-3.0-or-later

package vxlan

import (
	"encoding/json"
	"strings"
	"testing"
)

const (
	innerIPv4UDP = "4500001C00000000401100000A0000010A00000204D2003500080000"
	innerIPv6UDP = "60000000000811400000000000000000000000000000000100000000000000000000000000000002" + "04D2003500080000"
)

// vxlanFrame builds a standard VXLAN packet (I-flag set, VNI 100) wrapping an
// inner Ethernet frame with the given ethertype + L3 payload.
func vxlanFrame(etherTypeHex, l3Hex string) string {
	const hdr = "0800000000006400"          // flags 0x08, VNI 0x000064
	const macs = "AABBCCDDEEFF112233445566" // dst + src MAC
	return hdr + macs + etherTypeHex + l3Hex
}

func TestDecode_VXLAN_InnerIPv4(t *testing.T) {
	r, err := Decode(vxlanFrame("0800", innerIPv4UDP))
	if err != nil {
		t.Fatal(err)
	}
	if r.InnerEthernet == nil {
		t.Fatal("inner ethernet not parsed")
	}
	ie := r.InnerEthernet
	if ie.InnerDecodeError != "" {
		t.Fatalf("inner decode error: %q", ie.InnerDecodeError)
	}
	if ie.InnerPacket == nil {
		t.Fatal("inner IPv4 packet not decoded")
	}
	js, _ := json.Marshal(ie.InnerPacket)
	for _, want := range []string{"10.0.0.1", "10.0.0.2", "1234", "53"} {
		if !strings.Contains(string(js), want) {
			t.Errorf("inner decode missing %q in %s", want, js)
		}
	}
}

func TestDecode_VXLAN_InnerIPv6(t *testing.T) {
	r, err := Decode(vxlanFrame("86DD", innerIPv6UDP))
	if err != nil {
		t.Fatal(err)
	}
	if r.InnerEthernet == nil || r.InnerEthernet.InnerPacket == nil {
		t.Fatalf("inner IPv6 not decoded: %+v", r.InnerEthernet)
	}
	js, _ := json.Marshal(r.InnerEthernet.InnerPacket)
	for _, want := range []string{"::1", "::2", "1234", "53"} {
		if !strings.Contains(string(js), want) {
			t.Errorf("inner v6 decode missing %q in %s", want, js)
		}
	}
}

func TestDecode_VXLAN_NonIPNotDecoded(t *testing.T) {
	// Inner ethertype 0x0806 (ARP) — not IP, so no inner-IP decode.
	r, err := Decode(vxlanFrame("0806", "0001080006040001"))
	if err != nil {
		t.Fatal(err)
	}
	if r.InnerEthernet.InnerPacket != nil || r.InnerEthernet.InnerDecodeError != "" {
		t.Errorf("ARP inner frame should not be IP-decoded: %+v", r.InnerEthernet.InnerPacket)
	}
}

func TestDecode_VXLAN_IPTypedGarbageSurfacesError(t *testing.T) {
	r, err := Decode(vxlanFrame("0800", "AABB"))
	if err != nil {
		t.Fatal(err)
	}
	if r.InnerEthernet.InnerDecodeError == "" {
		t.Errorf("IP-typed garbage should surface an inner_decode_error")
	}
	if r.InnerEthernet.InnerPacket != nil {
		t.Errorf("garbage should not produce a decoded inner packet")
	}
}
