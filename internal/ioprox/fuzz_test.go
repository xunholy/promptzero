// SPDX-License-Identifier: AGPL-3.0-or-later

package ioprox

import "testing"

// FuzzDecode exercises the IO Prox block decoder on arbitrary input; it must
// never panic (a malformed / wrong-length / non-ioProx block returns an error
// or a Result).
func FuzzDecode(f *testing.F) {
	f.Add("007840603059cf3f")
	f.Add("007859605339ece3")
	f.Add("00787fe07ffffc3f")
	f.Add("007840603079cf3f")
	f.Add("")
	f.Fuzz(func(_ *testing.T, s string) { _, _ = Decode(s) })
}
