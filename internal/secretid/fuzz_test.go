// SPDX-License-Identifier: AGPL-3.0-or-later

package secretid_test

import (
	"testing"

	"github.com/xunholy/promptzero/internal/secretid"
)

// FuzzIdentify confirms Identify never panics — the prefix dispatch and the
// routed decoders must always return cleanly.
func FuzzIdentify(f *testing.F) {
	for _, s := range []string{
		"", "ASIAY34FZKBOKMUTVV7A", "ghp_xxx", "eyJ.eyJ.x",
		"-----BEGIN CERTIFICATE-----", "sk_live_x", "?sv=&sig=",
		"abandon abandon about", "deadbeef",
	} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		_ = secretid.Identify(s)
	})
}
