// SPDX-License-Identifier: AGPL-3.0-or-later

package etherip

import "testing"

// Vector produced with scapy's EtherIP layer (scapy.contrib.etherip):
// EtherIP()/Ether(dst=00:11:22:33:44:55, src=66:77:88:99:aa:bb)
//   /IP(10.0.0.1 -> 10.0.0.2)/UDP(1234 -> 53). Verified field-for-field.

func TestDecodeIPv4Inner(t *testing.T) {
	const v = "300000112233445566778899aabb08004500001c00010000401166ce0a0000010a00000204d200350008e6d4"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 3 || r.Reserved != 0 {
		t.Fatalf("version/reserved = %d/%d", r.Version, r.Reserved)
	}
	if r.InnerDstMAC != "00:11:22:33:44:55" || r.InnerSrcMAC != "66:77:88:99:aa:bb" {
		t.Errorf("MACs = %q / %q", r.InnerDstMAC, r.InnerSrcMAC)
	}
	if r.EtherType != 0x0800 || r.EtherTypeName != "IPv4" {
		t.Errorf("ethertype = %#x/%q", r.EtherType, r.EtherTypeName)
	}
	if r.InnerDecodeError != "" {
		t.Fatalf("inner decode error: %s", r.InnerDecodeError)
	}
	if r.InnerPacket == nil || r.InnerPacket.Version != 4 {
		t.Fatalf("inner packet = %+v", r.InnerPacket)
	}
	if r.InnerPacket.ProtocolNumber != 17 { // UDP
		t.Errorf("inner proto = %d, want 17 (UDP)", r.InnerPacket.ProtocolNumber)
	}
	if r.InnerPacket.UDP == nil {
		t.Error("inner UDP not decoded")
	}
}

func TestDecodeNonIPInner(t *testing.T) {
	// EtherIP with an ARP inner (EtherType 0x0806) — frame surfaced raw, no IP decode.
	const v = "3000" + "ffffffffffff" + "001122334455" + "0806" + "0001080006040001"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.EtherTypeName != "ARP" {
		t.Errorf("ethertype = %q, want ARP", r.EtherTypeName)
	}
	if r.InnerPacket != nil {
		t.Error("ARP inner must not be IP-decoded")
	}
	if r.InnerFrameHex == "" {
		t.Error("non-IP inner frame should be surfaced raw")
	}
}

func TestDecodeRejectsBadVersion(t *testing.T) {
	// version nibble 4 (not 3) -> rejected.
	if _, err := Decode("4000" + "00112233445566778899aabb0800"); err == nil {
		t.Fatal("expected rejection of version != 3")
	}
}

func TestDecodeTruncated(t *testing.T) {
	if _, err := Decode("30"); err == nil {
		t.Fatal("expected error on short header")
	}
	// header ok but inner frame truncated -> noted, not panicked.
	r, err := Decode("3000aabbcc")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.InnerDstMAC != "" {
		t.Error("truncated inner frame should not yield a MAC")
	}
}
