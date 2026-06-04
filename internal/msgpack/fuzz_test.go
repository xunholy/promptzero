// SPDX-License-Identifier: AGPL-3.0-or-later

package msgpack

import (
	"encoding/hex"
	"testing"
)

// FuzzDecode asserts the decoder never panics on arbitrary bytes — a
// recursive length-prefixed binary parser must reject truncated / hostile
// length fields (huge array/map/str counts, deep nesting) with an error, not
// crash or hang (the untrusted paste-and-decode surface).
func FuzzDecode(f *testing.F) {
	seeds := []string{
		"c0", "c3", "7f", "ff", "ccff", "cb3ff8000000000000",
		"a26869", "93010203", "82a16101a16202", "82a1789301c3c0a179a17a",
		"d60501020304", "c403010203", "dcffff", "c1", "",
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
