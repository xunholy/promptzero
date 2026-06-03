// SPDX-License-Identifier: AGPL-3.0-or-later

package dtls

import (
	"encoding/hex"
	"testing"
)

func FuzzDecode(f *testing.F) {
	seeds := []string{
		"",
		"16fefd0000000000000000",
		// A small unfragmented Certificate handshake record (msg_type 11),
		// exercising the cert-list walk + x509decode chaining path.
		hex.EncodeToString([]byte{
			0x16, 0xFE, 0xFD, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0x00, 0x0a,
			0x0b, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x06,
			0x00, 0x00, 0x03, 0x00, 0x00, 0x01,
		}),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		// Must never panic for any input, including malformed Certificate
		// messages routed into the x509 decoder.
		_, _ = Decode(s)
	})
}
