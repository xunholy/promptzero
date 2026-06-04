// SPDX-License-Identifier: AGPL-3.0-or-later

package ipdecode

import "testing"

// TestJA4T anchors the JA4T TCP-SYN fingerprint byte-for-byte against the FoxIO
// macos_tcp_flags snapshot (ja4t: 65535_2-1-3-1-1-8-4-0-0_1460_6). The IP
// packet hex is the first SYN extracted directly from FoxIO's pcap.
func TestJA4T(t *testing.T) {
	const ipHex = "45000040000040004006c50dac100510ac431847ef7f01bbc6a29cd200000000" +
		"b0c2ffffd2280000020405b4010303060101080a780321b50000000004020000"
	p, err := Decode(ipHex)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if p.TCP == nil {
		t.Fatal("no TCP layer")
	}
	const want = "65535_2-1-3-1-1-8-4-0-0_1460_6"
	if p.TCP.JA4T != want {
		t.Errorf("JA4T = %q, want %q", p.TCP.JA4T, want)
	}
}

// JA4T is only emitted for SYN packets (the options are negotiated at setup).
func TestJA4TNonSYN(t *testing.T) {
	// Same packet with the SYN flag cleared (flags byte 0xc2 -> 0xc0).
	const ipHex = "45000040000040004006c50dac100510ac431847ef7f01bbc6a29cd200000000" +
		"b0c0ffffd2280000020405b4010303060101080a780321b50000000004020000"
	p, err := Decode(ipHex)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if p.TCP != nil && p.TCP.JA4T != "" {
		t.Errorf("JA4T = %q on a non-SYN packet, want empty", p.TCP.JA4T)
	}
}
