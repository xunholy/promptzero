// SPDX-License-Identifier: AGPL-3.0-or-later

package netntlm

import "testing"

// FuzzCrackLine asserts CrackLine never panics on arbitrary AUTHENTICATE +
// server-challenge inputs (NTLMSSP parse via internal/ntlm, then the
// length-split / format).
func FuzzCrackLine(f *testing.F) {
	f.Add(authV2Hex, serverChalV2)
	f.Add("4e544c4d535350000200000000000000", "08ca45b7d7ea58ee")
	f.Add("", "")
	f.Add("notntlm", "zz")
	f.Fuzz(func(_ *testing.T, auth, sc string) {
		_, _ = CrackLine(auth, sc) // must not panic
	})
}
