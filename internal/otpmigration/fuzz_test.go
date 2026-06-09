// SPDX-License-Identifier: AGPL-3.0-or-later

package otpmigration

import "testing"

// FuzzDecode confirms Decode never panics on arbitrary input — the URI parse,
// the base64 decode, and the protobuf wire walk must always return cleanly with
// either a result or an error.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		"",
		"otpauth-migration://offline?data=",
		"otpauth-migration://offline?data=CjEKCkhlbGxv",
		"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP",
		"CgA=",
		"!!!!",
	} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s)
	})
}
