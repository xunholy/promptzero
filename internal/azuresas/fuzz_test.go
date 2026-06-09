// SPDX-License-Identifier: AGPL-3.0-or-later

package azuresas_test

import (
	"testing"

	"github.com/xunholy/promptzero/internal/azuresas"
)

// FuzzDecode confirms Decode never panics — the URL/query split, the query
// parse, and the field/permission expansion must always return cleanly.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		"",
		"?sp=rw&sv=2022-11-02&sr=b&se=2024-01-01T00:00:00Z&sig=z",
		"?ss=bfqt&srt=sco&sp=rwdlacup&sig=z",
		"https://x/y?foo=bar",
		"?sv=%zz",
	} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = azuresas.Decode(s)
	})
}
