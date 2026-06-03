// SPDX-License-Identifier: AGPL-3.0-or-later

package gtp

import (
	"encoding/json"
	"strings"
	"testing"
)

const (
	innerIPv4UDP = "4500001C00000000401100000A0000010A00000204D2003500080000"
	innerIPv6UDP = "60000000000811400000000000000000000000000000000100000000000000000000000000000002" + "04D2003500080000"
)

// gtpuGPDU builds a minimal GTP-U v1 G-PDU (flags 0x30, msg 0xFF, no
// optional fields) carrying the given inner payload.
func gtpuGPDU(innerHex string) string {
	n := len(innerHex) / 2
	return "30FF" + fmtU16(n) + "00000001" + innerHex
}

func fmtU16(n int) string {
	const hexd = "0123456789ABCDEF"
	return string([]byte{hexd[(n>>12)&0xF], hexd[(n>>8)&0xF], hexd[(n>>4)&0xF], hexd[n&0xF]})
}

func TestDecode_GTPU_InnerIPv4(t *testing.T) {
	r, err := Decode(gtpuGPDU(innerIPv4UDP))
	if err != nil {
		t.Fatal(err)
	}
	if r.MessageType != 0xFF {
		t.Fatalf("message type = 0x%02X, want 0xFF", r.MessageType)
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

func TestDecode_GTPU_InnerIPv6(t *testing.T) {
	r, err := Decode(gtpuGPDU(innerIPv6UDP))
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

func TestDecode_GTPU_NonGPDUNotDecoded(t *testing.T) {
	// Echo Request (0x01) carries no subscriber IP packet.
	r, err := Decode("3001" + "0004" + "00000001" + "AABBCCDD")
	if err != nil {
		t.Fatal(err)
	}
	if r.InnerPacket != nil || r.InnerDecodeError != "" {
		t.Errorf("non-G-PDU should not be IP-decoded: %+v", r.InnerPacket)
	}
}

func TestDecode_GTPU_GPDUGarbageSurfacesError(t *testing.T) {
	r, err := Decode(gtpuGPDU("AABB"))
	if err != nil {
		t.Fatal(err)
	}
	if r.InnerDecodeError == "" {
		t.Errorf("G-PDU garbage payload should surface inner_decode_error")
	}
	if r.InnerPacket != nil {
		t.Errorf("garbage should not produce a decoded inner packet")
	}
}
