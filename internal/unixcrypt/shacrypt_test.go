// SPDX-License-Identifier: AGPL-3.0-or-later

package unixcrypt

import "testing"

// TestSHA512Crypt gates sha512crypt against the OpenSSL `passwd -6` oracle.
func TestSHA512Crypt(t *testing.T) {
	cases := []struct{ pw, salt, want string }{
		{"password", "abcdefgh", "$6$abcdefgh$yVfUwsw5T.JApa8POvClA1pQ5peiq97DUNyXCZN5IrF.BMSkiaLQ5kvpuEm/VQ1Tvh/KV2TcaWh8qinoW5dhA1"},
		{"hello", "salt", "$6$salt$ghQ6Rhatj/sug12c6v8Ao/bXUoyJ1O1SqdumufgGEO3b3NYPvm/dSWDKWfNm1VxFoFiy/cw9eRaY0xu4GDQSU/"},
		{"abcdefghijklmnop", "12345678", "$6$12345678$gkrcNyJAQCYF38KZr/NTRVwxMCixDNpSnckoltxEZabgRGDRHb1s8ayE5euiIw5q/Z2hxDIks8zoh24MIWSeo0"},
	}
	for _, c := range cases {
		if got := SHA512Crypt(c.pw, c.salt, 0); got != c.want {
			t.Errorf("SHA512Crypt(%q,%q) =\n  %s\nwant\n  %s", c.pw, c.salt, got, c.want)
		}
	}
}

// TestSHA256Crypt gates sha256crypt against the OpenSSL `passwd -5` oracle.
func TestSHA256Crypt(t *testing.T) {
	cases := []struct{ pw, salt, want string }{
		{"password", "abcdefgh", "$5$abcdefgh$ZLdkj8mkc2XVSrPVjskDAgZPGjtj1VGVaa1aUkrMTU/"},
		{"test", "1234", "$5$1234$Sb3udSfNjsY0SFl2GJHrtnasgSZ6J8T9meLXNjn2NfD"},
	}
	for _, c := range cases {
		if got := SHA256Crypt(c.pw, c.salt, 0); got != c.want {
			t.Errorf("SHA256Crypt(%q,%q) = %s, want %s", c.pw, c.salt, got, c.want)
		}
	}
}

// TestSHA512Crypt_Rounds gates the explicit-rounds form (rounds=N$) against
// `openssl passwd -6 -salt 'rounds=1000$abcdefgh'`.
func TestSHA512Crypt_Rounds(t *testing.T) {
	const want = "$6$rounds=1000$abcdefgh$wuAp2XWwaaguzVxZjeM2bd1yLSqbC/I9sr9DFeOfIPoAZiIj3ecL6rf9ibuAg8RDmh1vqbaeL0NSLJtGPF7b60"
	if got := SHA512Crypt("password", "abcdefgh", 1000); got != want {
		t.Errorf("SHA512Crypt rounds=1000 =\n  %s\nwant\n  %s", got, want)
	}
}

func TestSHACrypt_Verify(t *testing.T) {
	h6 := "$6$abcdefgh$yVfUwsw5T.JApa8POvClA1pQ5peiq97DUNyXCZN5IrF.BMSkiaLQ5kvpuEm/VQ1Tvh/KV2TcaWh8qinoW5dhA1"
	if ok, err := Verify("password", h6); err != nil || !ok {
		t.Errorf("sha512 verify: ok=%v err=%v", ok, err)
	}
	if ok, _ := Verify("wrong", h6); ok {
		t.Error("wrong password must not verify (sha512)")
	}
	// rounds-carrying hash must round-trip through verify.
	hr := "$6$rounds=1000$abcdefgh$wuAp2XWwaaguzVxZjeM2bd1yLSqbC/I9sr9DFeOfIPoAZiIj3ecL6rf9ibuAg8RDmh1vqbaeL0NSLJtGPF7b60"
	if ok, err := Verify("password", hr); err != nil || !ok {
		t.Errorf("sha512 rounds verify: ok=%v err=%v", ok, err)
	}
	h5 := "$5$abcdefgh$ZLdkj8mkc2XVSrPVjskDAgZPGjtj1VGVaa1aUkrMTU/"
	if ok, err := Verify("password", h5); err != nil || !ok {
		t.Errorf("sha256 verify: ok=%v err=%v", ok, err)
	}
	if Scheme(h6) != "sha512crypt" || Scheme(h5) != "sha256crypt" {
		t.Errorf("scheme labels: %s %s", Scheme(h6), Scheme(h5))
	}
}

// TestSHACrypt_RoundsClamp confirms out-of-range rounds clamp to the spec bounds.
func TestSHACrypt_RoundsClamp(t *testing.T) {
	// rounds below the minimum clamp to 1000 — same as the explicit 1000 vector.
	if SHA512Crypt("password", "abcdefgh", 500) != SHA512Crypt("password", "abcdefgh", 1000) {
		t.Error("rounds below minimum should clamp to 1000")
	}
}
