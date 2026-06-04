// SPDX-License-Identifier: AGPL-3.0-or-later

package saml

import (
	"encoding/base64"
	"testing"
)

// FuzzDecode asserts the decoder never panics or hangs on an arbitrary input
// string — the base64 decode, DEFLATE inflate (LimitReader-bounded) and XML
// token scan must reject malformed input with an error, not crash.
func FuzzDecode(f *testing.F) {
	f.Add(redirectVector)
	f.Add(base64.StdEncoding.EncodeToString([]byte(responseXML)))
	f.Add("")
	f.Add("not base64")
	f.Add(base64.StdEncoding.EncodeToString([]byte("<a><b/></a>")))
	f.Add(base64.StdEncoding.EncodeToString([]byte{0x78, 0x9c, 0x00})) // zlib-ish header
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s) // must not panic or hang
	})
}
