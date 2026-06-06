// SPDX-License-Identifier: AGPL-3.0-or-later

package tzsp

import "testing"

// Vectors produced with scapy's TZSP layer (scapy.contrib.tzsp) and
// verified field-for-field.

func TestDecodeRXPacket(t *testing.T) {
	// TZSP(type=RX, encap=802.11)/RawRSSI(0xd6)/SNR(40)/DataRate(0x6c)
	//   /RXChannel(6)/Error(fcs=1)/End()/Ether(...)
	const v = "010000120a01d60b01280c016c1201061101010166778899aabb0011223344550800"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.PacketTypeName != "RX_PACKET" {
		t.Errorf("type = %q", r.PacketTypeName)
	}
	if r.EncapProtocolName != "IEEE 802.11" {
		t.Errorf("encap = %q", r.EncapProtocolName)
	}
	if r.RawRSSI == nil || *r.RawRSSI != -42 {
		t.Errorf("rssi = %v, want -42", r.RawRSSI)
	}
	if r.SNR == nil || *r.SNR != 40 {
		t.Errorf("snr = %v, want 40", r.SNR)
	}
	if r.DataRate != "54 Mb/s" {
		t.Errorf("data rate = %q", r.DataRate)
	}
	if r.RXChannel == nil || *r.RXChannel != 6 {
		t.Errorf("channel = %v, want 6", r.RXChannel)
	}
	if r.FCSError == nil || !*r.FCSError {
		t.Errorf("fcs = %v, want true", r.FCSError)
	}
	if r.EncapsulatedFrameHex != "66778899AABB0011223344550800" {
		t.Errorf("frame = %q", r.EncapsulatedFrameHex)
	}
}

func TestDecodeKeepalive(t *testing.T) {
	// TZSP(type=KEEPALIVE, encap=ETHERNET)/End()
	const v = "0104000101"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.PacketTypeName != "KEEPALIVE/NULL" {
		t.Errorf("type = %q", r.PacketTypeName)
	}
	if r.EncapProtocolName != "ETHERNET" {
		t.Errorf("encap = %q", r.EncapProtocolName)
	}
	if r.EncapsulatedFrameHex != "" {
		t.Errorf("keepalive should carry no frame, got %q", r.EncapsulatedFrameHex)
	}
}

func TestDecodeShortRSSI(t *testing.T) {
	// RAW_RSSI as a 2-byte signed value (0xffd6 = -42).
	const v = "010000120a02ffd601"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.RawRSSI == nil || *r.RawRSSI != -42 {
		t.Errorf("short rssi = %v, want -42", r.RawRSSI)
	}
}

func TestDecodeRejectsNonTZSP(t *testing.T) {
	if _, err := Decode("02000012"); err == nil {
		t.Fatal("expected rejection of version != 1")
	}
}

func TestDecodeTruncated(t *testing.T) {
	if _, err := Decode("0100"); err == nil {
		t.Fatal("expected error on short header")
	}
}

func TestDataRateNames(t *testing.T) {
	for code, want := range map[byte]string{0x6c: "54 Mb/s", 0x02: "1 Mb/s", 0x6e: "11 Mb/s", 0x00: "unknown"} {
		if got := dataRateName(code); got != want {
			t.Errorf("dataRateName(0x%02x) = %q, want %q", code, got, want)
		}
	}
}
