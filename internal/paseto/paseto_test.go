// SPDX-License-Identifier: AGPL-3.0-or-later

package paseto

import (
	"strings"
	"testing"
)

// Official PASETO test vectors (github.com/paseto-standard/test-vectors, v4.json).
const (
	pubKey = "1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"

	// 4-S-1: signed message, no footer.
	tokS1   = "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9bg_XBBzds8lTZShVlwwKSgeKpLT3yukTw6JUz3W4h_ExsQV-P0V54zemZDcAxFaSeef1QlXEFtkqxT1ciiQEDA"
	claimsS = `{"data":"this is a signed message","exp":"2022-01-01T00:00:00+00:00"}`

	// 4-S-2: signed message, with footer.
	tokS2    = "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9v3Jt8mx_TdM2ceTGoqwrh4yDFn0XsHvvV_D0DtwQxVrJEBMl0F2caAdgnpKlt4p7xBnx1HcO-SPo8FPp214HDw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9"
	footerS2 = `{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}`

	// 4-E-1: encrypted (local).
	tokE1 = "v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAr68PS4AXe7If_ZgesdkUMvSwscFlAl1pk5HC0e8kApeaqMfGo_7OpBnwJOAbY9V7WU6abu74MmcUE8YWAiaArVI8XJ5hOb_4v9RmDkneN0S92dx0OW4pgy7omxgf3S8c3LlQg"
)

func TestDecodePublic(t *testing.T) {
	r, err := Decode(tokS1)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != "v4" || r.Purpose != "public" {
		t.Errorf("version/purpose: %s.%s", r.Version, r.Purpose)
	}
	if r.Message != claimsS {
		t.Errorf("message = %q, want %q", r.Message, claimsS)
	}
	if len(r.SignatureHex) != 128 { // 64-byte Ed25519 signature
		t.Errorf("signature hex len = %d, want 128", len(r.SignatureHex))
	}
	if r.HasFooter {
		t.Error("4-S-1 has no footer")
	}
}

func TestDecodePublicWithFooter(t *testing.T) {
	r, err := Decode(tokS2)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Message != claimsS {
		t.Errorf("message = %q", r.Message)
	}
	if !r.HasFooter || r.Footer != footerS2 {
		t.Errorf("footer = %q, want %q", r.Footer, footerS2)
	}
}

func TestVerifyValid(t *testing.T) {
	ok, err := Verify(tokS1, pubKey, "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Error("4-S-1 should verify true with its published public key")
	}
	// With footer.
	ok, err = Verify(tokS2, pubKey, "")
	if err != nil || !ok {
		t.Errorf("4-S-2 should verify true: %v %v", ok, err)
	}
}

func TestVerifyTampered(t *testing.T) {
	// Flip a base64url character within the signature region (a mid-payload
	// byte, not the last char whose trailing bits the decoder ignores).
	b := []byte(tokS1)
	i := len(b) - 20
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	ok, err := Verify(string(b), pubKey, "")
	if err != nil {
		t.Fatalf("Verify(tampered): %v", err)
	}
	if ok {
		t.Error("tampered token must NOT verify")
	}
	// Wrong implicit assertion → fail.
	ok, _ = Verify(tokS1, pubKey, "extra")
	if ok {
		t.Error("wrong implicit assertion must NOT verify")
	}
}

func TestDecodeLocal(t *testing.T) {
	r, err := Decode(tokE1)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != "v4" || r.Purpose != "local" {
		t.Errorf("version/purpose: %s.%s", r.Version, r.Purpose)
	}
	if r.Message != "" {
		t.Errorf("local token must not expose a cleartext message, got %q", r.Message)
	}
	if r.EncryptedBytes == 0 || r.EncryptedHex == "" || r.Note == "" {
		t.Errorf("local token should surface encrypted payload + note: %+v", r)
	}
}

func TestVerifyRejectsNonEd25519(t *testing.T) {
	if _, err := Verify(tokE1, pubKey, ""); err == nil {
		t.Error("Verify on a local token should error")
	}
	// v3 public is ECDSA — verification not supported.
	v3 := "v3.public." + strings.Repeat("A", 200)
	if _, err := Verify(v3, pubKey, ""); err == nil {
		t.Error("Verify on v3 should error (unsupported)")
	}
}

func TestDecodeRejectsMalformed(t *testing.T) {
	for _, c := range []string{
		"",
		"v4.public",             // too few parts
		"v9.public.AAAA",        // unknown version
		"v4.bogus.AAAA",         // unknown purpose
		"v4.public.@@@@",        // bad base64url
		"v4.public.AAAA",        // payload (3 bytes) shorter than 64-byte sig
		"v4.public.AA.BB.CC.DD", // too many parts
	} {
		if _, err := Decode(c); err == nil {
			t.Errorf("Decode(%q): want error, got nil", c)
		}
	}
}
