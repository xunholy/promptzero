// SPDX-License-Identifier: AGPL-3.0-or-later

package sflow

import "testing"

func FuzzDecodeRawPacketHeader(f *testing.F) {
	seeds := [][]byte{
		rawHdr(1, "AABBCCDDEEFF112233445566"+"0800"+innerIPv4UDP), // Ethernet -> IPv4
		rawHdr(11, innerIPv4UDP),                                  // direct IPv4
		rawHdr(12, innerIPv6UDP),                                  // direct IPv6
		rawHdr(11, "45AB"),                                        // IP-typed garbage
		rawHdr(1, "AABBCCDDEEFF1122334455660806"+"0001"),          // ARP (non-IP)
		{},
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, b []byte) {
		// Must never panic for any input, including malformed sampled headers
		// routed into the IP decoder.
		_ = decodeRawPacketHeader(b, DecodeOpts{MaxHeaderBytes: 128})
	})
}
