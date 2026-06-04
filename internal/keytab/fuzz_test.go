// SPDX-License-Identifier: AGPL-3.0-or-later

package keytab

import (
	"encoding/hex"
	"testing"
)

// FuzzDecode asserts the keytab parser never panics on arbitrary bytes — a
// length-prefixed binary walker over untrusted .keytab loot must reject
// truncated / hostile size + counted-octet-string lengths with an error, not
// crash.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{ktHex, "0502", "0501deadbeef", "0502ffffffff", "", "050200000000"} {
		if b, err := hex.DecodeString(s); err == nil {
			f.Add(b)
		}
	}
	f.Fuzz(func(_ *testing.T, b []byte) {
		_, _ = DecodeBytes(b) // must not panic
	})
}
