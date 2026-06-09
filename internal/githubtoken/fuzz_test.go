// SPDX-License-Identifier: AGPL-3.0-or-later

package githubtoken_test

import (
	"testing"

	"github.com/xunholy/promptzero/internal/githubtoken"
)

// FuzzDecode confirms Decode never panics — the prefix dispatch, the Base62
// decode, and the CRC32 compare must always return cleanly.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		"",
		"ghp_" + canonEntropy + canonChecksum, // assembled from parts (see decode_test.go)
		"github_pat_11A",
		"ghp_",
		"not a token",
	} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = githubtoken.Decode(s)
	})
}
