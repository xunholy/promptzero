package dkim

import (
	"strings"
	"testing"
)

// The RSA p= values were generated with openssl (openssl genrsa N | openssl rsa
// -pubout -outform DER | base64); the key-bits + modulus prefix are openssl's
// own output. The Ed25519 vector is the RFC 8463 §3 published example.
const (
	rsa1024P = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC3Hjb8Op39GmMzJe24RjyFdkuqKZPqTsVZjmjth9ueE/6eguK27DpnnZ4S3e9dyxfFmTdylcS2YiCPpwV4JtshkSXJk0st3kxynhmazzclnsuNS5HEmH/Ibh0EuBpmf9oToP3M03xjDds1YP+8nKiu+IdJyexkUnHNKTOW7VYLjQIDAQAB"
	rsa512P  = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMxGJBUFs97+MbswlOOoHtBg5/8XgVyYTkYuKxBPjhkOy+0yZRdN8q1IDGYy1LDNnHIjCEnRckjiN5hk2yfkDk0CAwEAAQ=="
	ed25519P = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
)

func TestDKIM_RSA1024(t *testing.T) {
	rec := "v=DKIM1; k=rsa; h=sha256; t=s; p=" + rsa1024P
	res, err := Decode(rec)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if res.Version != "DKIM1" {
		t.Errorf("version = %q", res.Version)
	}
	if res.KeyType != "rsa" {
		t.Errorf("key type = %q, want rsa", res.KeyType)
	}
	if res.KeyBits != 1024 {
		t.Errorf("key bits = %d, want 1024", res.KeyBits)
	}
	if !strings.HasPrefix(res.ModulusHex, "b71e36fc") {
		t.Errorf("modulus = %q, want b71e36fc… prefix", res.ModulusHex[:16])
	}
	if !res.StrictDomain {
		t.Error("expected t=s strict_domain")
	}
	if len(res.HashAlgs) != 1 || res.HashAlgs[0] != "sha256" {
		t.Errorf("hash algs = %v", res.HashAlgs)
	}
	// 1024-bit → advisory (meets RFC 8301 min, but 2048 recommended).
	if !hasWarning(res.Warnings, "advisory") {
		t.Errorf("expected 1024-bit advisory warning, got %v", res.Warnings)
	}
}

// TestDKIM_RSA512Weak is the classic forgeable-DKIM finding: a sub-1024-bit key.
func TestDKIM_RSA512Weak(t *testing.T) {
	res, err := Decode("k=rsa; p=" + rsa512P)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if res.KeyBits != 512 {
		t.Errorf("key bits = %d, want 512", res.KeyBits)
	}
	if !hasWarning(res.Warnings, "WEAK") {
		t.Errorf("expected WEAK warning for 512-bit key, got %v", res.Warnings)
	}
	if res.ModulusHex == "" {
		t.Error("expected modulus to be surfaced for roca chaining")
	}
}

// TestDKIM_Ed25519 covers the RFC 8463 Ed25519 key (32 raw bytes, not SPKI).
func TestDKIM_Ed25519(t *testing.T) {
	res, err := Decode("v=DKIM1; k=ed25519; p=" + ed25519P)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if res.KeyType != "ed25519" {
		t.Errorf("key type = %q, want ed25519", res.KeyType)
	}
	if res.KeyBits != 256 {
		t.Errorf("key bits = %d, want 256", res.KeyBits)
	}
	if res.ModulusHex != "" {
		t.Error("ed25519 should have no RSA modulus")
	}
}

func TestDKIM_Revoked(t *testing.T) {
	res, err := Decode("v=DKIM1; k=rsa; p=")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !res.Revoked {
		t.Error("expected revoked for empty p=")
	}
}

// TestDKIM_FoldedKey confirms whitespace inside p= (DNS string folding) is
// stripped before decode.
func TestDKIM_FoldedKey(t *testing.T) {
	folded := rsa1024P[:40] + " " + rsa1024P[40:80] + "\t" + rsa1024P[80:]
	res, err := Decode("v=DKIM1; k=rsa; p=" + folded)
	if err != nil {
		t.Fatalf("Decode folded: %v", err)
	}
	if res.KeyBits != 1024 {
		t.Errorf("key bits = %d, want 1024", res.KeyBits)
	}
}

func TestDKIM_DefaultKeyType(t *testing.T) {
	// No k= → default rsa.
	res, err := Decode("p=" + rsa1024P)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if res.KeyType != "rsa" {
		t.Errorf("default key type = %q, want rsa", res.KeyType)
	}
}

func TestDKIM_Errors(t *testing.T) {
	cases := []string{"", "v=DKIM1; k=rsa", "p=!!!notbase64!!!"}
	for _, c := range cases {
		if _, err := Decode(c); err == nil {
			t.Errorf("Decode(%q): want error", c)
		}
	}
}

func TestDKIM_TestingFlag(t *testing.T) {
	res, err := Decode("v=DKIM1; t=y; p=" + rsa1024P)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Testing {
		t.Error("expected t=y testing flag")
	}
}

func hasWarning(warnings []string, substr string) bool {
	for _, w := range warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}
