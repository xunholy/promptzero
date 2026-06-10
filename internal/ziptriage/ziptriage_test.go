package ziptriage

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"testing"
)

// Real reference archives of a "plain.txt" file (password "testpass"):
//
//	zcB64  — `zip -P testpass` (PKWARE ZipCrypto, stored)
//	aesB64 — `7z a -mem=AES256` (WinZip AES-256, AE-2)
const (
	zcB64  = "UEsDBAoACQAAAIYoy1x/lmRKGAAAAAwAAAAJABwAcGxhaW4udHh0VVQJAAMrtSlqK7UpanV4CwABBOgDAAAE6AMAAOwBjcHkzb7fq+6w9ifOEcdvRn9lR6b081BLBwh/lmRKGAAAAAwAAABQSwECHgMKAAkAAACGKMtcf5ZkShgAAAAMAAAACQAYAAAAAAABAAAApIEAAAAAcGxhaW4udHh0VVQFAAMrtSlqdXgLAAEE6AMAAAToAwAAUEsFBgAAAAABAAEATwAAAGsAAAAAAA=="
	aesB64 = "UEsDBDMDAQBjAIYoy1wAAAAAKAAAAAwAAAAJAAsAcGxhaW4udHh0AZkHAAIAQUUDAAB+gmCvXR3iJPDGXCSQ0tD9NB8Cekz2jQu2R2V9ixR60MqXIxthIMn6UEsBAj8DMwMBAGMAhijLXAAAAAAoAAAADAAAAAkALwAAAAAAAAAggKSBAAAAAHBsYWluLnR4dAoAIAAAAAAAAQAYAIBHyOsL+dwBgEfI6wv53AGAR8jrC/ncAQGZBwACAEFFAwAAUEsFBgAAAAABAAEAZgAAAFoAAAAAAA=="
)

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	return b
}

func TestDecode_ZipCrypto(t *testing.T) {
	r, err := Decode(mustB64(t, zcB64))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Encryption != "ZipCrypto" {
		t.Errorf("encryption = %q, want ZipCrypto", r.Encryption)
	}
	if r.TotalEntries != 1 || r.EncryptedEntries != 1 {
		t.Errorf("entries total/enc = %d/%d, want 1/1", r.TotalEntries, r.EncryptedEntries)
	}
	if r.FirstEncryptedName != "plain.txt" {
		t.Errorf("first encrypted = %q", r.FirstEncryptedName)
	}
	if r.HashcatMode != 17210 { // stored
		t.Errorf("hashcat mode = %d, want 17210", r.HashcatMode)
	}
}

func TestDecode_WinZipAES(t *testing.T) {
	r, err := Decode(mustB64(t, aesB64))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Encryption != "WinZip-AES" {
		t.Errorf("encryption = %q, want WinZip-AES", r.Encryption)
	}
	if r.AESVersion != "AE-2" || r.AESStrengthBits != 256 {
		t.Errorf("AES = %s/%d-bit, want AE-2/256", r.AESVersion, r.AESStrengthBits)
	}
	if r.HashcatMode != 13600 {
		t.Errorf("hashcat mode = %d, want 13600", r.HashcatMode)
	}
	if r.FirstEncryptedName != "plain.txt" {
		t.Errorf("first encrypted = %q", r.FirstEncryptedName)
	}
}

// An unencrypted archive (built with the stdlib) must report no encryption and
// no hashcat target — there is nothing to crack.
func TestDecode_Unencrypted(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("hello.txt")
	_, _ = w.Write([]byte("not a secret"))
	if err := zw.Close(); err != nil {
		t.Fatalf("zip build: %v", err)
	}
	r, err := Decode(buf.Bytes())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Encryption != "none" || r.EncryptedEntries != 0 {
		t.Errorf("encryption = %q enc=%d, want none/0", r.Encryption, r.EncryptedEntries)
	}
	if r.HashcatMode != 0 {
		t.Errorf("hashcat mode = %d, want 0 (nothing to crack)", r.HashcatMode)
	}
	if r.TotalEntries != 1 {
		t.Errorf("total entries = %d, want 1", r.TotalEntries)
	}
}

func TestDecode_Errors(t *testing.T) {
	cases := map[string][]byte{
		"empty":   {},
		"short":   {0x50, 0x4b},
		"not zip": bytes.Repeat([]byte("not a zip file at all "), 4),
	}
	for name, raw := range cases {
		if _, err := Decode(raw); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(mustB64NoT(zcB64))
	f.Add(mustB64NoT(aesB64))
	f.Add([]byte("PK\x03\x04"))
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, raw []byte) {
		_, _ = Decode(raw)
	})
}

func mustB64NoT(s string) []byte { b, _ := base64.StdEncoding.DecodeString(s); return b }
