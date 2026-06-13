package rcloneconfig

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"testing"
)

// obscureWithIV mirrors rclone's Obscure with a caller-chosen IV (rclone uses a
// random IV; pinning it makes the output deterministic for tests). Same key,
// same AES-256-CTR, same RawURL encoding — so Reveal(obscureWithIV(p)) == p.
func obscureWithIV(t *testing.T, plain string, iv []byte) string {
	t.Helper()
	if len(iv) != aes.BlockSize {
		t.Fatalf("iv must be %d bytes, got %d", aes.BlockSize, len(iv))
	}
	block, err := aes.NewCipher(cryptKey)
	if err != nil {
		t.Fatal(err)
	}
	ct := make([]byte, aes.BlockSize+len(plain))
	copy(ct, iv)
	cipher.NewCTR(block, iv).XORKeyStream(ct[aes.BlockSize:], []byte(plain))
	return base64.RawURLEncoding.EncodeToString(ct)
}

var ivA = []byte("aaaaaaaaaaaaaaaa")

// TestReveal_AuthoritativeVectors anchors the key + algorithm to rclone's own
// published reveal vectors (fs/config/obscure/obscure_test.go). If these pass,
// the hardcoded key and the AES-256-CTR / IV-prepend / RawURL-base64 transform
// are provably correct.
func TestReveal_AuthoritativeVectors(t *testing.T) {
	cases := []struct{ in, want string }{
		{"YWFhYWFhYWFhYWFhYWFhYQ", ""},
		{"YWFhYWFhYWFhYWFhYWFhYXMaGgIlEQ", "potato"},
		{"YmJiYmJiYmJiYmJiYmJiYp3gcEWbAw", "potato"},
	}
	for _, c := range cases {
		got, err := Reveal(c.in)
		if err != nil || got != c.want {
			t.Errorf("Reveal(%q) = %q, %v; want %q, nil", c.in, got, err, c.want)
		}
	}
}

func TestReveal_Errors(t *testing.T) {
	for name, in := range map[string]string{
		"not base64":  "!!!not-base64!!!",
		"too short":   base64.RawURLEncoding.EncodeToString([]byte("short")),
		"empty input": "",
	} {
		if _, err := Reveal(in); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestReveal_RoundTrip(t *testing.T) {
	for _, p := range []string{"x", "hunter2", "a longer pass phrase with spaces!", "ünïcödé-pø"} {
		if got, err := Reveal(obscureWithIV(t, p, ivA)); err != nil || got != p {
			t.Errorf("round-trip %q: got %q, %v", p, got, err)
		}
	}
}

func TestDecode_RevealsObscuredPasswords(t *testing.T) {
	conf := "[myftp]\n" +
		"type = sftp\n" +
		"host = ftp.example.com\n" +
		"user = admin\n" +
		"pass = " + obscureWithIV(t, "s3cr3t-p@ss", ivA) + "\n" +
		"\n" +
		"[enc]\n" +
		"type = crypt\n" +
		"remote = mys3:bucket\n" +
		"password = " + obscureWithIV(t, "cryptpw", ivA) + "\n" +
		"password2 = " + obscureWithIV(t, "salt99", ivA) + "\n"

	r, err := Decode(conf)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.HasCredential {
		t.Fatal("HasCredential = false, want true")
	}
	want := map[string]map[string]string{
		"myftp": {"pass": "s3cr3t-p@ss"},
		"enc":   {"password": "cryptpw", "password2": "salt99"},
	}
	for _, rem := range r.Remotes {
		for _, c := range rem.Credentials {
			exp, ok := want[rem.Name][c.Field]
			if !ok {
				continue
			}
			if c.Kind != KindRevealedPassword || c.Value != exp {
				t.Errorf("%s.%s = (%s,%q), want (%s,%q)", rem.Name, c.Field, c.Kind, c.Value, KindRevealedPassword, exp)
			}
			if c.Obscured == "" {
				t.Errorf("%s.%s: obscured raw not surfaced", rem.Name, c.Field)
			}
		}
	}
}

func TestDecode_PlaintextSecretsAndType(t *testing.T) {
	conf := "[mys3]\n" +
		"type = s3\n" +
		"provider = AWS\n" +
		"access_key_id = AKIAIOSFODNN7EXAMPLE\n" +
		"secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"

	r, err := Decode(conf)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.Remotes) != 1 || r.Remotes[0].Type != "s3" {
		t.Fatalf("remotes=%+v", r.Remotes)
	}
	got := map[string]Cred{}
	for _, c := range r.Remotes[0].Credentials {
		got[c.Field] = c
	}
	for _, f := range []string{"access_key_id", "secret_access_key"} {
		if got[f].Kind != KindPlaintextSecret || got[f].Value == "" {
			t.Errorf("%s = %+v, want plaintext-secret with value", f, got[f])
		}
	}
}

// A non-printable decode must NOT be presented as a recovered password.
func TestDecode_NonPrintableNotClaimed(t *testing.T) {
	conf := "[weird]\ntype = sftp\npass = " + obscureWithIV(t, "\x01\x02\x03\x04\x05", ivA) + "\n"
	r, err := Decode(conf)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	c := r.Remotes[0].Credentials[0]
	if c.Kind != KindObscuredUnrevealable || c.Value != "" || c.Obscured == "" {
		t.Errorf("got %+v, want obscured-unrevealable with empty value + raw obscured surfaced", c)
	}
}

// A hand-edited plaintext password (not a valid obscure blob) is surfaced as
// plaintext, not silently dropped or mis-revealed.
func TestDecode_PlaintextPasswordDowngrade(t *testing.T) {
	conf := "[hand]\ntype = sftp\npass = plainshort\n"
	r, err := Decode(conf)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	c := r.Remotes[0].Credentials[0]
	if c.Kind != KindPlaintextSecret || c.Value != "plainshort" {
		t.Errorf("got %+v, want plaintext-secret value=plainshort", c)
	}
}

func TestDecode_Rejects(t *testing.T) {
	for name, in := range map[string]string{
		"empty":      "",
		"prose":      "just some notes\nno ini structure here\n",
		"no keys":    "[onlysection]\n[another]\n",
		"key no sec": "type = s3\npass = whatever\n",
	} {
		if _, err := Decode(in); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestDecode_CommentsAndBlankLines(t *testing.T) {
	conf := "; a comment\n# another\n\n[r]\ntype = webdav\npass = " + obscureWithIV(t, "ok", ivA) + "\n"
	r, err := Decode(conf)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.Remotes) != 1 || len(r.Remotes[0].Credentials) != 1 || r.Remotes[0].Credentials[0].Value != "ok" {
		t.Fatalf("unexpected: %+v", r.Remotes)
	}
}

func FuzzDecode(f *testing.F) {
	f.Add("[r]\ntype = sftp\npass = YWFhYWFhYWFhYWFhYWFhYXMaGgIlEQ\n")
	f.Add("[s3]\ntype = s3\nsecret_access_key = abc\n")
	f.Add("")
	f.Add("[x]")
	f.Fuzz(func(_ *testing.T, in string) {
		_, _ = Decode(in)
	})
}
