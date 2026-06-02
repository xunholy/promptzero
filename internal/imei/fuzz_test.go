// SPDX-License-Identifier: AGPL-3.0-or-later

package imei

import "testing"

// FuzzDecode exercises the IMEI/IMEISV decoder — the digit validation, length
// switch, and fixed-offset slicing must never panic.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		"", "490154203237518", "4901542032375103", "49-015420-323751-8",
		"49015420323751", "490154203237518123", "abc", "0000000000000000",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { _, _ = Decode(s) })
}
