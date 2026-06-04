// SPDX-License-Identifier: AGPL-3.0-or-later

package estransport

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
	f.Fuzz(func(_ *testing.T, b []byte) {
		_, _ = Decode(hex.EncodeToString(b)) // must not panic
	})
}
