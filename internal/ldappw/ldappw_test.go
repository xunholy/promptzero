// SPDX-License-Identifier: AGPL-3.0-or-later

package ldappw

import (
	"strings"
	"testing"
)

// Oracle vectors. The unsalted {SHA}/{MD5} values are produced byte-for-byte by
// OpenLDAP `slappasswd -h {SHA} -s secret` (cross-checked against hashlib). The
// salted values were produced by slappasswd (variable-length salt). The SHA-2
// variants use the definitional digest+base64 construction (the exact pw-sha2 /
// Dovecot output), computed with `python3 -c "hashlib + base64"`.
const (
	// password = "secret"
	shaSecret  = "{SHA}5en6G6MezRroT3XKqkdPOmY/BfQ="
	md5Secret  = "{MD5}Xr4ilOzQ4PCOq3aQ0qbuaQ=="
	sshaSecret = "{SSHA}62HRJo0CfHyf/Ymk2vJlQ/awb0ohXDmZ" // slappasswd, 4-byte salt

	// definitional SHA-2 vectors, password = "secret", salt = "1234"
	sha256Secret  = "{SHA256}K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols="
	ssha512Secret = "{SSHA512}xmfsDcoyHSITKqCiwudodTWhzJABDhwcLHJ/3UPnqxMy4WjoZujZKrvgRW70/mlQJ1F5JqtoQcH1SxWhpgm69DEyMzQ="
)

// TestComputeUnsaltedMatchesOracle pins {SHA}/{MD5}/{SHA256} compute against the
// independent oracle output byte-for-byte.
func TestComputeUnsaltedMatchesOracle(t *testing.T) {
	cases := []struct {
		scheme, want string
	}{
		{"{SHA}", shaSecret},
		{"{MD5}", md5Secret},
	}
	for _, c := range cases {
		got, err := Compute(c.scheme, "secret", "")
		if err != nil {
			t.Fatalf("Compute(%s): %v", c.scheme, err)
		}
		if got != c.want {
			t.Errorf("Compute(%s) = %q, want %q", c.scheme, got, c.want)
		}
	}
}

// TestComputeSHA256Definitional pins the SHA-256 unsalted vector.
func TestComputeSHA256Definitional(t *testing.T) {
	got, err := Compute("{SHA256}", "secret", "")
	if err != nil {
		t.Fatal(err)
	}
	if got != sha256Secret {
		t.Errorf("Compute({SHA256}) = %q, want %q", got, sha256Secret)
	}
}

// TestComputeSaltedDeterministic pins a fixed-salt salted vector against the
// definitional construction (salt recovered + recomputed).
func TestComputeSaltedDeterministic(t *testing.T) {
	got, err := Compute("{SSHA512}", "secret", "1234")
	if err != nil {
		t.Fatal(err)
	}
	if got != ssha512Secret {
		t.Errorf("Compute({SSHA512}, salt=1234) = %q, want %q", got, ssha512Secret)
	}
}

// TestVerifyOracleVectors confirms verification against oracle-produced stored
// values, including the variable-length-salt {SSHA}.
func TestVerifyOracleVectors(t *testing.T) {
	cases := []struct {
		stored, scheme string
		saltLen        int
	}{
		{shaSecret, "{SHA}", 0},
		{md5Secret, "{MD5}", 0},
		{sshaSecret, "{SSHA}", 4},
		{sha256Secret, "{SHA256}", 0},
		{ssha512Secret, "{SSHA512}", 4},
	}
	for _, c := range cases {
		r, err := Verify("secret", c.stored)
		if err != nil {
			t.Fatalf("Verify(%s): %v", c.scheme, err)
		}
		if !r.Matched {
			t.Errorf("Verify(%s): correct password not matched", c.scheme)
		}
		if r.Scheme != c.scheme {
			t.Errorf("Verify scheme = %q, want %q", r.Scheme, c.scheme)
		}
		if r.SaltLen != c.saltLen {
			t.Errorf("Verify(%s) salt_len = %d, want %d", c.scheme, r.SaltLen, c.saltLen)
		}
	}
}

// TestVerifyRejectsWrongPassword ensures a near-miss does not match.
func TestVerifyRejectsWrongPassword(t *testing.T) {
	for _, stored := range []string{shaSecret, sshaSecret, ssha512Secret} {
		r, err := Verify("Secret", stored) // wrong case
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if r.Matched {
			t.Errorf("Verify(%s): wrong password matched", stored)
		}
	}
}

// TestComputeVerifyRoundTrip round-trips every scheme through compute → verify
// with both auto and explicit salts.
func TestComputeVerifyRoundTrip(t *testing.T) {
	for _, sc := range Schemes() {
		h, err := Compute(sc, "hunter2", "") // auto salt for salted schemes
		if err != nil {
			t.Fatalf("Compute(%s): %v", sc, err)
		}
		r, err := Verify("hunter2", h)
		if err != nil {
			t.Fatalf("Verify(%s): %v", sc, err)
		}
		if !r.Matched {
			t.Errorf("round-trip %s: not matched", sc)
		}
		if r.Scheme != sc {
			t.Errorf("round-trip scheme = %q, want %q", r.Scheme, sc)
		}
		// A different password must not verify.
		r2, err := Verify("wrong", h)
		if err != nil {
			t.Fatalf("Verify(%s) wrong: %v", sc, err)
		}
		if r2.Matched {
			t.Errorf("round-trip %s: wrong password matched", sc)
		}
	}
}

// TestComputeSchemeAliases accepts case-insensitive / brace-less scheme names.
func TestComputeSchemeAliases(t *testing.T) {
	for _, alias := range []string{"ssha", "SSHA", "{ssha}", "{SSHA}"} {
		h, err := Compute(alias, "x", "salt")
		if err != nil {
			t.Fatalf("Compute(%q): %v", alias, err)
		}
		if !strings.HasPrefix(h, "{SSHA}") {
			t.Errorf("Compute(%q) prefix = %q, want {SSHA}", alias, h)
		}
	}
}

func TestComputeRejectsSaltOnUnsalted(t *testing.T) {
	if _, err := Compute("{SHA}", "x", "salt"); err == nil {
		t.Fatal("want error supplying a salt to an unsalted scheme")
	}
}

func TestComputeRejectsUnknownScheme(t *testing.T) {
	if _, err := Compute("{CRYPT}", "x", ""); err == nil {
		t.Fatal("want error for {CRYPT} (delegated to crypt(3))")
	}
	if _, err := Compute("{BOGUS}", "x", ""); err == nil {
		t.Fatal("want error for unknown scheme")
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	cases := []string{
		"",                       // empty
		"noscheme",               // no prefix
		"{SHA",                   // unterminated prefix
		"{SHA}not!base64!",       // bad base64
		"{SHA}YWJj",              // too-short digest (3 bytes < 20)
		"{SHA}" + sshaSecret[6:], // unsalted scheme with trailing salt bytes
	}
	for _, c := range cases {
		if _, err := Verify("x", c); err == nil {
			t.Errorf("Verify(%q): want error, got nil", c)
		}
	}
}

func TestIdentify(t *testing.T) {
	if got := Identify(sshaSecret); got != "{SSHA}" {
		t.Errorf("Identify(SSHA) = %q", got)
	}
	if got := Identify("$1$abc"); got != "" {
		t.Errorf("Identify(non-LDAP) = %q, want empty", got)
	}
}
