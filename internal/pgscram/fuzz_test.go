// SPDX-License-Identifier: AGPL-3.0-or-later

package pgscram

import "testing"

// FuzzVerify asserts Verify never panics while parsing an arbitrary verifier
// string (prefix strip, $/: field splits, base64 decode, length checks). The
// iteration count is clamped (maxIterations) so a hostile value cannot wedge
// PBKDF2; seeds stay at the parse layer.
func FuzzVerify(f *testing.F) {
	seeds := []string{
		rfc7677Verifier,
		"SCRAM-SHA-256$4096:" + rfc7677Salt,
		"SCRAM-SHA-256$",
		"md5deadbeef",
		"",
		"SCRAM-SHA-256$1:YWJj$YWJj:YWJj",
	}
	for _, s := range seeds {
		f.Add("pencil", s)
	}
	f.Fuzz(func(_ *testing.T, password, verifier string) {
		_, _ = Verify(password, verifier) // must not panic
	})
}
