// SPDX-License-Identifier: AGPL-3.0-or-later

package discordtoken_test

import (
	"testing"

	"github.com/xunholy/promptzero/internal/discordtoken"
)

// FuzzDecode confirms Decode never panics — the segment split, the Base64
// decode, and the snowflake chain must always return cleanly.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		"", "mfa.aaa", "MTc1OTI4ODQ3Mjk5MTE3MDYz.x.y",
		"eyJ.eyJ.x", "no dots here", "....",
	} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = discordtoken.Decode(s)
	})
}
