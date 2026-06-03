// SPDX-License-Identifier: AGPL-3.0-or-later

package dcerpc

import (
	"encoding/hex"
	"testing"
)

// FuzzDecode asserts the decoder never panics on arbitrary frame bytes — a
// hand-written length-prefixed binary parser must reject malformed/truncated
// input with an error, not crash (the untrusted pcap-and-paste DoS surface).
func FuzzDecode(f *testing.F) {
	for _, n := range []int{0, 1, 2, 4, 8, 12, 20, 40, 64, 128} {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(i*7 + 1)
		}
		f.Add(b)
	}
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})

	// sec_trailer seeds: NTLMSSP auth_value, and an auth_length larger than
	// the fragment — both route through decodeAuthTrailer and must not panic.
	uuid := uuidBytes(0x12345678, 0x1234, 0xabcd,
		[8]byte{0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0xcf, 0xfb})
	body := bindBody(uuid, 1, 0)
	av := ntlmChallenge()
	tr := secTrailer(0x0A, 0x06, av)
	f.Add(append(append(dcerpcHeader(12, 0x03,
		uint16(headerSize+len(body)+len(tr)), uint16(len(av)), 7), body...), tr...))
	f.Add(dcerpcHeader(12, 0x03, 16, 0xFFFF, 1)) // auth_length > fragment

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Decode(hex.EncodeToString(data)) // must not panic
	})
}
