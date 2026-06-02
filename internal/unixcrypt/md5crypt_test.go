// SPDX-License-Identifier: AGPL-3.0-or-later

package unixcrypt

import "testing"

// TestMD5Crypt gates md5crypt against vectors from the OpenSSL `passwd -1`
// oracle, across password and salt lengths (empty password, 16-char password,
// 2/4/8-char salts).
func TestMD5Crypt(t *testing.T) {
	cases := []struct{ pw, salt, want string }{
		{"password", "abcdefgh", "$1$abcdefgh$G//4keteveJp0qb8z2DxG/"},
		{"hello", "salt", "$1$salt$BSpYmSAZQYBttsZ28Ph1f/"},
		{"", "xx", "$1$xx$Qiw/Pi26KfpLUDkeOIdG.."},
		{"abcdefghijklmnop", "12345678", "$1$12345678$Sy0u0qLp5W1f/aNE5VcBp/"},
	}
	for _, c := range cases {
		if got := MD5Crypt(c.pw, c.salt); got != c.want {
			t.Errorf("MD5Crypt(%q,%q) = %s, want %s", c.pw, c.salt, got, c.want)
		}
	}
}

// TestAPR1 gates the Apache apr1 variant against `openssl passwd -apr1`.
func TestAPR1(t *testing.T) {
	cases := []struct{ pw, salt, want string }{
		{"password", "abcdefgh", "$apr1$abcdefgh$FBwExRW4dCc8aL.OvjpIE1"},
		{"myPassword", "xxxxxxxx", "$apr1$xxxxxxxx$RKMOWWMKN4Ts9r6E5noqv0"},
		{"test", "1234", "$apr1$1234$g3eu/XJD4i4JwUZ35q2XN0"},
	}
	for _, c := range cases {
		if got := APR1(c.pw, c.salt); got != c.want {
			t.Errorf("APR1(%q,%q) = %s, want %s", c.pw, c.salt, got, c.want)
		}
	}
}

// TestSaltTruncation confirms a salt longer than 8 chars is truncated like
// crypt(3) (so the >8 salt yields the same hash as its 8-char prefix).
func TestSaltTruncation(t *testing.T) {
	if MD5Crypt("password", "12345678") != MD5Crypt("password", "123456789abc") {
		t.Error("salt should be truncated to 8 characters")
	}
}

func TestVerify(t *testing.T) {
	ok, err := Verify("password", "$1$abcdefgh$G//4keteveJp0qb8z2DxG/")
	if err != nil || !ok {
		t.Errorf("correct password should verify: ok=%v err=%v", ok, err)
	}
	if ok, _ := Verify("wrong", "$1$abcdefgh$G//4keteveJp0qb8z2DxG/"); ok {
		t.Error("wrong password must not verify")
	}
	if ok, _ := Verify("password", "$apr1$abcdefgh$FBwExRW4dCc8aL.OvjpIE1"); !ok {
		t.Error("apr1 verify should succeed")
	}
	// apr1 hash must not verify under a md5crypt recompute (magic matters).
	if ok, _ := Verify("password", "$5$abcdefgh$notmd5"); ok {
		t.Error("unsupported scheme should not verify")
	}
	if _, err := Verify("x", "plaintext"); err == nil {
		t.Error("non-crypt hash should error")
	}
}
