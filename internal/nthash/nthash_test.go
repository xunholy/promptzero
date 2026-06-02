// SPDX-License-Identifier: AGPL-3.0-or-later

package nthash

import (
	"encoding/hex"
	"testing"
)

// TestMD4_RFC1320 gates the MD4 core against the complete RFC 1320 Appendix A.5
// test suite — the authoritative reference.
func TestMD4_RFC1320(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "31d6cfe0d16ae931b73c59d7e0c089c0"},
		{"a", "bde52cb31de33e46245e05fbdbd6fb24"},
		{"abc", "a448017aaf21d8525fc10ae87aa6729d"},
		{"message digest", "d9130a8164549fe818874806e1c7014b"},
		{"abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"},
		{"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "043f8582f241db351ce627e153e7f0e4"},
		{"12345678901234567890123456789012345678901234567890123456789012345678901234567890", "e33b4ddc9c38f2199c3e7b164fcc0536"},
	}
	for _, c := range cases {
		if got := hex.EncodeToString(MD4([]byte(c.in))); got != c.want {
			t.Errorf("MD4(%q) = %s, want %s", c.in, got, c.want)
		}
	}
}

// TestNTHash gates the NT hash against the universally published NTLM vectors.
func TestNTHash(t *testing.T) {
	cases := []struct{ pw, want string }{
		{"password", "8846f7eaee8fb117ad06bdd830b7586c"},
		{"", "31d6cfe0d16ae931b73c59d7e0c089c0"}, // MD4 of empty UTF-16LE == MD4 of empty
	}
	for _, c := range cases {
		if got := hex.EncodeToString(NTHash(c.pw)); got != c.want {
			t.Errorf("NTHash(%q) = %s, want %s", c.pw, got, c.want)
		}
	}
}

// TestLMHash gates the LM hash against three cross-confirming references — the
// universal empty-LM, the published LM("password") pair, and the hashcat -m 3000
// example (password "HASHCAT" -> first half 299bd128c1101fd6) — every value
// independently reproduced via an OpenSSL DES oracle.
func TestLMHash(t *testing.T) {
	cases := []struct{ pw, want string }{
		{"", "aad3b435b51404eeaad3b435b51404ee"},
		{"password", "e52cac67419a9a224a3b108f3fa6cb6d"},
		{"ADMIN", "f0d412bd764ffe81aad3b435b51404ee"},
		{"hashcat", "299bd128c1101fd6aad3b435b51404ee"},  // -> HASHCAT
		{"PASSWORD", "e52cac67419a9a224a3b108f3fa6cb6d"}, // uppercasing: same as "password"
	}
	for _, c := range cases {
		got, err := LMHash(c.pw)
		if err != nil {
			t.Fatalf("LMHash(%q): %v", c.pw, err)
		}
		if hex.EncodeToString(got) != c.want {
			t.Errorf("LMHash(%q) = %s, want %s", c.pw, hex.EncodeToString(got), c.want)
		}
	}
}

func TestLMHash_NonASCII(t *testing.T) {
	if _, err := LMHash("pässwörd"); err == nil {
		t.Error("non-ASCII password should be rejected (OEM-codepage dependent)")
	}
}

// TestMD4_NoMutate confirms MD4 does not mutate the caller's slice via padding.
func TestMD4_NoMutate(t *testing.T) {
	in := make([]byte, 3, 128) // spare capacity: a naive append would overwrite
	copy(in, "abc")
	_ = MD4(in)
	if string(in) != "abc" {
		t.Errorf("MD4 mutated caller slice: %q", in)
	}
}
