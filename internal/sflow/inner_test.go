// SPDX-License-Identifier: AGPL-3.0-or-later

package sflow

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

const (
	innerIPv4UDP = "4500001C00000000401100000A0000010A00000204D2003500080000"
	innerIPv6UDP = "60000000000811400000000000000000000000000000000100000000000000000000000000000002" + "04D2003500080000"
)

func u32(n int) string {
	const h = "0123456789ABCDEF"
	return string([]byte{
		h[(n>>28)&0xF], h[(n>>24)&0xF], h[(n>>20)&0xF], h[(n>>16)&0xF],
		h[(n>>12)&0xF], h[(n>>8)&0xF], h[(n>>4)&0xF], h[n&0xF],
	})
}

// rawHdr builds a Raw Packet Header record body: protocol + framelen +
// stripped + sampledHeaderLen + the captured header hex.
func rawHdr(proto int, headerHex string) []byte {
	hdrBytes := len(headerHex) / 2
	s := u32(proto) + u32(100) + u32(0) + u32(hdrBytes) + headerHex
	b, _ := hex.DecodeString(s)
	return b
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

func TestRawPacketHeader_EthernetInnerIPv4(t *testing.T) {
	eth := "AABBCCDDEEFF112233445566" + "0800" + innerIPv4UDP
	h := decodeRawPacketHeader(rawHdr(1, eth), DecodeOpts{MaxHeaderBytes: 128})
	if h == nil || h.InnerDecodeError != "" || h.InnerPacket == nil {
		t.Fatalf("ethernet inner IPv4 not decoded: %+v", h)
	}
	has(t, h.InnerPacket, "10.0.0.1", "10.0.0.2", "1234", "53")
}

func TestRawPacketHeader_DirectIPv4(t *testing.T) {
	h := decodeRawPacketHeader(rawHdr(11, innerIPv4UDP), DecodeOpts{MaxHeaderBytes: 128})
	if h == nil || h.InnerPacket == nil {
		t.Fatalf("direct IPv4 not decoded: %+v", h)
	}
	has(t, h.InnerPacket, "10.0.0.1", "10.0.0.2")
}

func TestRawPacketHeader_DirectIPv6(t *testing.T) {
	h := decodeRawPacketHeader(rawHdr(12, innerIPv6UDP), DecodeOpts{MaxHeaderBytes: 128})
	if h == nil || h.InnerPacket == nil {
		t.Fatalf("direct IPv6 not decoded: %+v", h)
	}
	has(t, h.InnerPacket, "::1", "::2")
}

func TestRawPacketHeader_NonIPEthernetNotDecoded(t *testing.T) {
	// Ethernet carrying ARP (0x0806) — no inner-IP decode.
	eth := "AABBCCDDEEFF112233445566" + "0806" + "0001080006040001"
	h := decodeRawPacketHeader(rawHdr(1, eth), DecodeOpts{MaxHeaderBytes: 128})
	if h.InnerPacket != nil || h.InnerDecodeError != "" {
		t.Errorf("ARP-over-Ethernet should not be IP-decoded: %+v", h.InnerPacket)
	}
}

func TestRawPacketHeader_DirectIPGarbageSurfacesError(t *testing.T) {
	h := decodeRawPacketHeader(rawHdr(11, "45AB"), DecodeOpts{MaxHeaderBytes: 128})
	if h.InnerDecodeError == "" || h.InnerPacket != nil {
		t.Errorf("IP-typed garbage should surface inner_decode_error + no packet: %+v", h)
	}
}
