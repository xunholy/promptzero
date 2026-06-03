// SPDX-License-Identifier: AGPL-3.0-or-later

package emv

import "testing"

// FuzzDecodeMagstripe asserts the swipe parser never panics on arbitrary input
// (it parses an untrusted reader/skimmer string with sentinel/field splitting).
func FuzzDecodeMagstripe(f *testing.F) {
	seeds := []string{
		"%B4111111111111111^DOE/JOHN^25121011200000?2",
		";4111111111111111=25121011200000?",
		"%B^^?;=?",
		"%", ";", "%?", ";?", "%B?", ";=?", "",
		"%Bonly-track-1-no-end-sentinel",
		"%B^/^?", // empty PAN, name with bare slash
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = DecodeMagstripe(s) // must not panic
	})
}
