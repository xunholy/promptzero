package htpasswd

import (
	"strings"
	"testing"
)

// sampleFile is a real htpasswd file with one entry per recognised scheme.
// Vectors are ground-truth: openssl passwd (-apr1/-1/-5/-6), x/crypto/bcrypt,
// Python hashlib ({SHA}/{SSHA}), and hashcat's published -m 1500 example
// (DES crypt) — all for the password "pass" except the published DES example.
const sampleFile = `# users for the admin area
alice:$2a$05$Pq/4wsFLob39UQSWA/3EBuTMGuBfQsHGM0IaLzRDGDM4dza.ZKXZC
bob:$apr1$abcdefgh$rK/lObuciIG5ziaV8BdHR/
carol:$1$abcdefgh$1s0bv7.OjNizlrMAOIQD7.
dave:$5$abcdefgh$HzzE/l7JTvo/KwUuQ1gnXciE10UWdO477E3KxyYElr4
eve:$6$abcdefgh$.Wd8gKGVv/NncIZyKrLIzwkMBRaL8yZnKz4uttpMUnlKvNdwooVmeCTgyWEOW0Smhyp/TUAtWmcz4ptHHh/u1/
frank:{SHA}nU4eI71bcnBGqeO0t9tXvY1u5oQ=
grace:{SSHA}3+BeCKBamBE44X4wBIdKmUChyd5zYWx0MTIzNA==
heidi:48c/R8JAv757A
ivan:supersecretplaintext

malformed_no_colon_line
`

func TestDecode_AllSchemes(t *testing.T) {
	r, err := Decode([]byte(sampleFile))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.EntryCount != 9 {
		t.Fatalf("entry count = %d, want 9", r.EntryCount)
	}
	if r.Malformed != 1 {
		t.Errorf("malformed = %d, want 1", r.Malformed)
	}
	want := []struct {
		user, scheme, mode, strength string
	}{
		{"alice", "bcrypt", "3200", strong},
		{"bob", "apache-md5 (apr1)", "1600", weak},
		{"carol", "md5-crypt", "500", weak},
		{"dave", "sha256-crypt", "7400", strong},
		{"eve", "sha512-crypt", "1800", strong},
		{"frank", "sha1-base64", "", weak},
		{"grace", "salted-sha1 (ssha)", "111", weak},
		{"heidi", "des-crypt", "1500", veryWeak},
		{"ivan", "plaintext / unknown", "", critical},
	}
	for i, w := range want {
		e := r.Entries[i]
		if e.Username != w.user || e.Scheme != w.scheme || e.HashcatMode != w.mode || e.Strength != w.strength {
			t.Errorf("entry %d = {%q %q m=%q %q}, want {%q %q m=%q %q}",
				i, e.Username, e.Scheme, e.HashcatMode, e.Strength, w.user, w.scheme, w.mode, w.strength)
		}
	}
	if !r.PlaintextHit {
		t.Errorf("expected plaintext_present=true")
	}
	for _, u := range []string{"bob", "carol", "frank", "grace", "heidi", "ivan"} {
		if !contains(r.WeakUsers, u) {
			t.Errorf("weak_users missing %q: %v", u, r.WeakUsers)
		}
	}
	for _, u := range []string{"alice", "dave", "eve"} {
		if contains(r.WeakUsers, u) {
			t.Errorf("strong user %q wrongly flagged weak", u)
		}
	}
	if !strings.Contains(r.Note, "CRITICAL") {
		t.Errorf("note = %q, want CRITICAL", r.Note)
	}
}

func TestDecode_AllStrong(t *testing.T) {
	r, err := Decode([]byte("a:$2b$12$" + strings.Repeat("a", 53) + "\nb:$6$salt$hash\n"))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.WeakUsers) != 0 || r.PlaintextHit {
		t.Errorf("expected no weak/plaintext, got weak=%v plain=%v", r.WeakUsers, r.PlaintextHit)
	}
	if !strings.Contains(r.Note, "strong schemes") {
		t.Errorf("note = %q", r.Note)
	}
}

func TestDecode_Empty(t *testing.T) {
	r, err := Decode([]byte("# only a comment\n\n"))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.EntryCount != 0 {
		t.Errorf("entry count = %d, want 0", r.EntryCount)
	}
	if !strings.Contains(r.Note, "No htpasswd entries") {
		t.Errorf("note = %q", r.Note)
	}
}

func TestIsDESCrypt(t *testing.T) {
	if !isDESCrypt("48c/R8JAv757A") {
		t.Errorf("valid DES crypt not recognised")
	}
	for _, bad := range []string{"", "tooshort", "waytoolongforDEScrypt", "48c/R8JAv757!", "48c/R8JAv757"} {
		if isDESCrypt(bad) {
			t.Errorf("%q wrongly classified as DES crypt", bad)
		}
	}
}

func TestHasBcryptPrefix(t *testing.T) {
	for _, ok := range []string{"$2a$05$x", "$2b$12$x", "$2x$05$x", "$2y$05$x"} {
		if !hasBcryptPrefix(ok) {
			t.Errorf("%q should be bcrypt", ok)
		}
	}
	for _, no := range []string{"", "$2", "$2c$05$x", "$1$abc$d", "$2a05$x", "plain"} {
		if hasBcryptPrefix(no) {
			t.Errorf("%q should not be bcrypt", no)
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte(sampleFile))
	f.Add([]byte(""))
	f.Add([]byte("nocolon"))
	f.Add([]byte("u:$2a$"))
	f.Add([]byte(":"))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = Decode(data) // must never panic
	})
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
