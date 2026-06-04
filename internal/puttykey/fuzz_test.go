// SPDX-License-Identifier: AGPL-3.0-or-later

package puttykey

import "testing"

// FuzzDecode asserts the parser never panics on arbitrary input — the line scan,
// block-count consumption, base64 decode, and SSH-wire read must reject
// truncated / hostile counts and lengths with an error, not crash or hang.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		ppk3EdUnenc, ppk3EdEnc, ppk2RSAUnenc,
		"", "PuTTY-User-Key-File-3: x\nPublic-Lines: 999999999\n", "notppk@@@",
	} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s) // must not panic
	})
}
