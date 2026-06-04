// SPDX-License-Identifier: AGPL-3.0-or-later

package ccache

import (
	"encoding/hex"
	"testing"
)

// FuzzDecode asserts the ccache parser never panics on arbitrary bytes — a
// recursive length-prefixed walker over untrusted ccache loot must reject
// truncated / hostile counted-length and count fields with an error, not crash
// (the sibling class of the keytab MinInt32 panic).
func FuzzDecode(f *testing.F) {
	for _, s := range []string{ccHex, "0504", "0504ffff", "0501deadbeef", "", "050400000000"} {
		if b, err := hex.DecodeString(s); err == nil {
			f.Add(b)
		}
	}
	f.Fuzz(func(_ *testing.T, b []byte) {
		_, _ = DecodeBytes(b) // must not panic
	})
}
