// SPDX-License-Identifier: AGPL-3.0-or-later

package otp

import "testing"

// FuzzParseURI asserts the otpauth:// parser never panics on arbitrary input
// (it parses untrusted QR / loot strings; it must return an error, not crash).
func FuzzParseURI(f *testing.F) {
	seeds := []string{
		"otpauth://totp/Example:alice@acme.com?secret=GEZDGNBVGY3TQOJQ&issuer=Example&algorithm=SHA256&digits=8&period=60",
		"otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQ&counter=5",
		"otpauth://totp/?secret=",
		"otpauth://",
		"otpauth://totp/x?secret=AA&digits=999999999999999999999",
		"otpauth://totp/" + "a:b:c:d" + "?secret=AA",
		"OTPAUTH://TOTP/X?SECRET=GEZDGNBVGY3TQOJQ",
		"",
		"not a uri at all",
		"otpauth://totp/x?secret=AA&period=-1&counter=-9",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		// Must not panic. A returned *URIParams (when err==nil) must be usable.
		if p, err := ParseURI(s); err == nil && p != nil {
			_ = p.Secret
			_ = p.Digits
		}
	})
}
