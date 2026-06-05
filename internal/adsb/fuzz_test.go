// SPDX-License-Identifier: AGPL-3.0-or-later

package adsb

import (
	"encoding/hex"
	"testing"
)

// FuzzDecode asserts the parser never panics on arbitrary input. The
// fuzzer's raw bytes are hex-encoded so every input reaches the binary
// parser itself (not the hex-reject path) — the untrusted paste-and-decode
// surface. Length/count fields, nesting, and offsets must be bounds-checked.
func FuzzDecode(f *testing.F) {
	for _, s := range [][]byte{{}, {0x00}, {0x01, 0x02, 0x03, 0x04}, {0xff, 0xff, 0xff, 0xff}} {
		f.Add(s)
	}
	// DF20 Comm-B frames exercise the BDS register inference + decode path.
	for _, h := range []string{
		"A000029C85E42F313000007047D3", // BDS40
		"A000139381951536E024D4CCF6B5", // BDS50
		"A00004128F39F91A7E27C46ADC21", // BDS60
		"A000083E202CC371C31DE0AA1CCF", // BDS20
		"28000AAA000000",               // DF5 squawk 7700 (emergency)
		"20000C83000000",               // DF4 altitude 38000 (Gillham)
		"200003B0000000",               // DF4 altitude 5000 (25-ft)
	} {
		if b, err := hex.DecodeString(h); err == nil {
			f.Add(b)
		}
	}
	f.Fuzz(func(_ *testing.T, b []byte) {
		_, _ = Decode(hex.EncodeToString(b)) // must not panic
	})
}
