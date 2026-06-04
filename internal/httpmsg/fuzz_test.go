// SPDX-License-Identifier: AGPL-3.0-or-later

package httpmsg

import "testing"

// FuzzDecode asserts the text-protocol parser never panics on arbitrary
// input — field splitting, index math, and length handling over untrusted
// pasted text must stay in bounds.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		"", "\n", ":", "a:b:c", "0", "\x00\x01\x02",
		// JA4H request seeds (exercise the fingerprint path).
		"GET / HTTP/1.0\r\nUser-Agent:\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: x\r\nCookie: a=1; b=2\r\nReferer: y\r\nAccept-Language: en-US,en;q=0.9\r\n\r\n",
	} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s) // must not panic
	})
}
