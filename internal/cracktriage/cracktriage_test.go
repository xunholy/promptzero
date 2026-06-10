package cracktriage

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// Reused real vectors: a KDBX4 header (internal/kdbx) and a ZipCrypto archive
// (internal/ziptriage). The PDF route is exercised with a minimal unencrypted
// PDF (the pdftriage decoder's no-/Encrypt path).
const kdbx4HeaderHex = "03d9a29a67fb4bb500000400021000000031c1f2e6bf714350be5805216afc5aff030400" +
	"0000010000000420000000b52178a734d0b577423679d02ab37dd17cb6781861d216c7d3" +
	"2d52c354ab2123071000000090ba3750281556cb96fea4c43545a9760b8b000000000142" +
	"05000000245555494410000000ef636ddf8c29444b91f7a9a403e30a0c05010000004908" +
	"0000000e0000000000000005010000004d08000000000000040000000004010000005004" +
	"00000002000000420100000053200000007839e86543e0449b3d6cc46b95b4bbab7d519c" +
	"7eb01d9cf59d64d82f6ab1a15f04010000005604000000130000000000040000000d0a0d" +
	"0a"

const zipCryptoB64 = "UEsDBAoACQAAAIYoy1x/lmRKGAAAAAwAAAAJABwAcGxhaW4udHh0VVQJAAMrtSlqK7UpanV4" +
	"CwABBOgDAAAE6AMAAOwBjcHkzb7fq+6w9ifOEcdvRn9lR6b081BLBwh/lmRKGAAAAAwAAABQ" +
	"SwECHgMKAAkAAACGKMtcf5ZkShgAAAAMAAAACQAYAAAAAAABAAAApIEAAAAAcGxhaW4udHh0" +
	"VVQFAAMrtSlqdXgLAAEE6AMAAAToAwAAUEsFBgAAAAABAAEATwAAAGsAAAAAAA=="

func TestDetect(t *testing.T) {
	cases := map[string]string{
		"kdbx":    "kdbx",
		"zip304":  "zip",
		"zip506":  "zip",
		"pdf":     "pdf",
		"garbage": "",
	}
	inputs := map[string][]byte{
		"kdbx":    {0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5, 0, 0, 4, 0},
		"zip304":  []byte("PK\x03\x04rest"),
		"zip506":  []byte("PK\x05\x06rest"),
		"pdf":     []byte("%PDF-1.7\nrest"),
		"garbage": []byte("not an artifact"),
	}
	for name, want := range cases {
		if got := Detect(inputs[name]); got != want {
			t.Errorf("Detect(%s) = %q, want %q", name, got, want)
		}
	}
}

func TestDecode_RoutesKDBX(t *testing.T) {
	raw, _ := hex.DecodeString(kdbx4HeaderHex)
	r, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Artifact != "KeePass KDBX" || r.HashcatMode != 13400 {
		t.Errorf("artifact=%q mode=%d, want KeePass KDBX / 13400", r.Artifact, r.HashcatMode)
	}
}

func TestDecode_RoutesZIP(t *testing.T) {
	raw, _ := base64.StdEncoding.DecodeString(zipCryptoB64)
	r, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Artifact != "ZIP archive" || r.HashcatMode != 17210 {
		t.Errorf("artifact=%q mode=%d, want ZIP archive / 17210", r.Artifact, r.HashcatMode)
	}
}

func TestDecode_RoutesPDF(t *testing.T) {
	pdf := []byte("%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF")
	r, err := Decode(pdf)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Artifact != "PDF document" {
		t.Errorf("artifact = %q, want PDF document", r.Artifact)
	}
	if r.HashcatMode != 0 { // unencrypted
		t.Errorf("hashcat mode = %d, want 0 (unencrypted PDF)", r.HashcatMode)
	}
}

func TestDecode_Unrecognised(t *testing.T) {
	for name, raw := range map[string][]byte{
		"empty":   {},
		"garbage": []byte("just some bytes"),
	} {
		if _, err := Decode(raw); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func FuzzDecode(f *testing.F) {
	raw, _ := hex.DecodeString(kdbx4HeaderHex)
	f.Add(raw)
	zb, _ := base64.StdEncoding.DecodeString(zipCryptoB64)
	f.Add(zb)
	f.Add([]byte("%PDF-1.7"))
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, raw []byte) {
		_, _ = Decode(raw)
	})
}
