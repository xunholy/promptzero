// SPDX-License-Identifier: AGPL-3.0-or-later

package ethkeystore_test

import (
	"testing"

	"github.com/xunholy/promptzero/internal/ethkeystore"
)

// FuzzDecrypt confirms Decrypt never panics on arbitrary input — the JSON
// parse, the hex decodes, the KDF parameter handling, and the cipher path must
// always return cleanly with a result or an error. Iterations are kept tiny by
// the inputs so the fuzzer is not dominated by KDF cost.
func FuzzDecrypt(f *testing.F) {
	for _, s := range []string{
		"",
		"{}",
		`{"version":3,"crypto":{"cipher":"aes-128-ctr","ciphertext":"00","cipherparams":{"iv":"00000000000000000000000000000000"},"kdf":"pbkdf2","kdfparams":{"c":1,"dklen":32,"prf":"hmac-sha256","salt":"00"},"mac":"0000000000000000000000000000000000000000000000000000000000000000"}}`,
		`{"crypto":{"cipher":"aes-128-ctr","kdf":"scrypt","kdfparams":{"n":2,"r":1,"p":1,"dklen":32,"salt":"00"}}}`,
	} {
		f.Add(s, "pw")
	}
	f.Fuzz(func(_ *testing.T, jsonStr, passphrase string) {
		_, _ = ethkeystore.Decrypt(jsonStr, passphrase)
	})
}
