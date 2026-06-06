// SPDX-License-Identifier: AGPL-3.0-or-later

package nsh

import "testing"

// Vectors produced with scapy's NSH layer (scapy.contrib.nsh); the base +
// service-path header was verified field-for-field.

func TestDecodeMD1IPv4(t *testing.T) {
	// NSH(mdtype=1, nextproto=1, spi=0x123456, si=255)/IP(10.0.0.1->10.0.0.2)/UDP(53).
	const v = "0fc60101123456ff00000000000000000000000000000000" +
		"4500001c00010000401166ce0a0000010a000002003500350008eb71"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 0 || r.TTL != 63 || r.LengthWords != 6 {
		t.Fatalf("ver/ttl/len = %d/%d/%d", r.Version, r.TTL, r.LengthWords)
	}
	if r.MDType != 1 || r.NextProtoName != "IPv4" {
		t.Errorf("mdtype/nextproto = %d/%q", r.MDType, r.NextProtoName)
	}
	if r.ServicePathID != 0x123456 || r.ServiceIndex != 255 {
		t.Errorf("spi/si = %#x/%d", r.ServicePathID, r.ServiceIndex)
	}
	if r.InnerDecodeError != "" || r.InnerPacket == nil {
		t.Fatalf("inner decode failed: %s / %+v", r.InnerDecodeError, r.InnerPacket)
	}
	if r.InnerPacket.Version != 4 || r.InnerPacket.ProtocolNumber != 17 {
		t.Errorf("inner = v%d proto %d", r.InnerPacket.Version, r.InnerPacket.ProtocolNumber)
	}
}

func TestDecodeEthernetInner(t *testing.T) {
	// MD type 1, next protocol 3 (Ethernet): base+sp + 16 ctx + Ethernet(IPv4).
	const v = "0fc6" + "01" + "03" + "000001" + "ff" +
		"00000000000000000000000000000000" +
		"00112233445566778899aabb0800" +
		"4500001400010000400166f70a0000010a000002"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.NextProtoName != "Ethernet" {
		t.Fatalf("nextproto = %q", r.NextProtoName)
	}
	if r.InnerDstMAC != "00:11:22:33:44:55" || r.InnerEtherType != "0x0800" {
		t.Errorf("inner L2 = %q / %q", r.InnerDstMAC, r.InnerEtherType)
	}
	if r.InnerPacket == nil || r.InnerPacket.Version != 4 {
		t.Errorf("inner IP not chained: %+v", r.InnerPacket)
	}
}

func TestDecodeContextSurfacedRaw(t *testing.T) {
	// MD type 1 context is 16 bytes; surfaced as raw hex (32 hex chars).
	const v = "0fc60101123456ffaabbccdd000000000000000000000000" +
		"4500001400010000400166f70a0000010a000002"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.ContextHeadersHex) != 32 {
		t.Errorf("context hex len = %d, want 32 (16 bytes)", len(r.ContextHeadersHex))
	}
	if r.ContextHeadersHex[:8] != "AABBCCDD" {
		t.Errorf("context prefix = %q", r.ContextHeadersHex[:8])
	}
}

func TestDecodeTruncated(t *testing.T) {
	if _, err := Decode("0fc60101"); err == nil {
		t.Fatal("expected error on short header")
	}
}
