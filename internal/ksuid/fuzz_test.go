// SPDX-License-Identifier: AGPL-3.0-or-later

package ksuid_test

import (
	"testing"

	"github.com/xunholy/promptzero/internal/ksuid"
)

// FuzzDecode confirms Decode never panics on arbitrary input — it must always
// return cleanly with either a result or an error.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		"",
		"0ujtsYcgvSTl8PAuAdqWYSMnLOv",
		"000000000000000000000000000",
		"aWgEPTl1tmebfsQzFP4bxwgy80V",
		"zzzzzzzzzzzzzzzzzzzzzzzzzzz",
		"not a ksuid",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = ksuid.Decode(s)
	})
}
