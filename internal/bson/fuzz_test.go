// SPDX-License-Identifier: AGPL-3.0-or-later

package bson

import (
	"encoding/hex"
	"testing"
)

// FuzzDecode asserts the decoder never panics or hangs on arbitrary bytes — a
// recursive length-prefixed binary parser must reject truncated / hostile
// length fields (document length, string length, binary length, deep nesting)
// with an error, not crash (the untrusted paste-and-decode surface for
// mongodump .bson loot).
func FuzzDecode(f *testing.F) {
	seeds := []string{
		"160000000268656c6c6f0006000000776f726c640000",
		"0c0000001061000500000000",
		"2900000003646f63000e000000026b000200000076000004617272000c000000083000010a31000000",
		"16000000075f696400507f1f77bcf86cd79943901100",
		"0f0000000b720061622e2a00690000",
		"0500000000", "04000000", "", "ff0000001061",
	}
	for _, s := range seeds {
		if b, err := hex.DecodeString(s); err == nil {
			f.Add(b)
		}
	}
	f.Fuzz(func(_ *testing.T, b []byte) {
		_, _ = DecodeBytes(b) // must not panic or hang
	})
}
