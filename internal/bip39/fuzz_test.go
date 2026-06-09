// SPDX-License-Identifier: AGPL-3.0-or-later

package bip39_test

import (
	"testing"

	"github.com/xunholy/promptzero/internal/bip39"
)

// FuzzDecode confirms Decode never panics on arbitrary input — the wordlist
// lookup, the bit packing, the checksum, and the PBKDF2 seed must always return
// cleanly with a result or an error.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		"",
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		"zoo zoo zoo",
		"not a real mnemonic at all",
		"abandon",
	} {
		f.Add(s, "")
	}
	f.Fuzz(func(_ *testing.T, mnemonic, passphrase string) {
		_, _ = bip39.Decode(mnemonic, passphrase)
	})
}
