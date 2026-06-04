// SPDX-License-Identifier: AGPL-3.0-or-later

package pemkey

import "testing"

// FuzzDecode asserts the parser never panics on arbitrary input — the PEM
// decode, x509 parse, and ASN.1 walk of the encrypted-key parameters must reject
// malformed / hostile DER with an error, not crash.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		ecSEC1, edPKCS8, rsa1024PKCS1, ecTradEnc, ecPBKDF2, ecScrypt,
		"", "notpem", "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----",
	} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s) // must not panic
	})
}
