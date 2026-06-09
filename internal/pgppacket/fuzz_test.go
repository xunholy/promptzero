// SPDX-License-Identifier: AGPL-3.0-or-later

package pgppacket_test

import (
	"testing"

	"github.com/xunholy/promptzero/internal/pgppacket"
)

// FuzzDecode confirms Decode never panics on arbitrary input — the armor strip,
// the base64/hex sniff, and the packet-framing walk (old/new headers, partial
// lengths, MPI skips) must always return cleanly with a result or an error, even
// on truncated or adversarial packet lengths.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		"",
		"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nzzz\n-----END PGP PUBLIC KEY BLOCK-----",
		string([]byte{0xc6, 0x05, 0x04, 0x00, 0x00, 0x00, 0x01}),
		string([]byte{0x99, 0x01, 0x00}),
		"not pgp",
	} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = pgppacket.Decode(s)
	})
}
