package pkcs12

import (
	"encoding/base64"
	"strings"
	"testing"
)

// All three vectors are real openssl-generated PKCS#12 files over one
// self-signed RSA cert (CN=tls.example.com). Properties below were read from
// `openssl pkcs12 -info` and are the ground truth this package is checked against:
//
//	plainP12 (-certpbe NONE):           plaintext certBag + shrouded key
//	encP12   (default):                 encrypted certBag (PBES2) + shrouded key
//	nokeyP12 (-certpbe NONE -keypbe NONE): plaintext certBag + UNSHROUDED key
//
// All: MAC SHA-256, salt 16 bytes, 2048 iterations, version 3.
const plainP12 = "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"
const encP12 = "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"
const nokeyP12 = "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"

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	return b
}

func checkMAC(t *testing.T, r *Result) {
	t.Helper()
	if r.Version != 3 || !r.MacPresent || r.MacAlgorithm != "SHA-256" || r.MacSaltBytes != 16 || r.MacIterations != 2048 {
		t.Errorf("MAC/version: v=%d present=%v alg=%q salt=%d iter=%d", r.Version, r.MacPresent, r.MacAlgorithm, r.MacSaltBytes, r.MacIterations)
	}
	if r.JohnTool != "pfx2john" {
		t.Errorf("john_tool=%q", r.JohnTool)
	}
}

func TestDecode_PlaintextCertBag(t *testing.T) {
	r, err := Decode(mustB64(t, plainP12))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	checkMAC(t, r)
	if len(r.Certificates) != 1 || !strings.Contains(r.Certificates[0].Subject, "CN=tls.example.com") || !r.Certificates[0].SelfSigned {
		t.Errorf("certs=%+v", r.Certificates)
	}
	if r.Certificates[0].ParseError != "" {
		t.Errorf("cert parse error: %s", r.Certificates[0].ParseError)
	}
	if r.ShroudedKeys != 1 || r.PlaintextKeys != 0 {
		t.Errorf("keys shrouded=%d plaintext=%d, want 1/0", r.ShroudedKeys, r.PlaintextKeys)
	}
	for _, s := range r.Safes {
		if s.Encrypted {
			t.Errorf("plaintext keystore should have no encrypted safe: %+v", s)
		}
	}
}

func TestDecode_EncryptedCertBag(t *testing.T) {
	r, err := Decode(mustB64(t, encP12))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	checkMAC(t, r)
	// Cert is in an encrypted safe — no identity is claimed.
	if len(r.Certificates) != 0 {
		t.Errorf("encrypted certBag must not yield a cert identity: %+v", r.Certificates)
	}
	var enc *Safe
	for i := range r.Safes {
		if r.Safes[i].Encrypted {
			enc = &r.Safes[i]
		}
	}
	if enc == nil || enc.Type != "encrypted-data" || enc.Algorithm != "PBES2" {
		t.Errorf("expected an encrypted-data PBES2 safe, got %+v", r.Safes)
	}
	if r.ShroudedKeys != 1 {
		t.Errorf("shrouded_keys=%d, want 1", r.ShroudedKeys)
	}
}

func TestDecode_UnshroudedKeyWarning(t *testing.T) {
	r, err := Decode(mustB64(t, nokeyP12))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	checkMAC(t, r)
	if r.PlaintextKeys != 1 || r.ShroudedKeys != 0 {
		t.Errorf("plaintext=%d shrouded=%d, want 1/0", r.PlaintextKeys, r.ShroudedKeys)
	}
	if !strings.Contains(r.Note, "UNSHROUDED") {
		t.Errorf("note should warn about the unshrouded key: %q", r.Note)
	}
	if len(r.Certificates) != 1 {
		t.Errorf("plaintext cert should still be extracted: %+v", r.Certificates)
	}
}

func TestDecode_Errors(t *testing.T) {
	good := mustB64(t, plainP12)
	cases := map[string][]byte{
		"empty":     {},
		"not asn1":  []byte("this is not a PFX"),
		"truncated": good[:len(good)-200],
		"trailing":  append(append([]byte{}, good...), 0x00, 0x01, 0x02),
	}
	for name, in := range cases {
		if _, err := Decode(in); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func FuzzDecode(f *testing.F) {
	if b, err := base64.StdEncoding.DecodeString(plainP12); err == nil {
		f.Add(b)
	}
	if b, err := base64.StdEncoding.DecodeString(encP12); err == nil {
		f.Add(b)
	}
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x03})
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, in []byte) {
		_, _ = Decode(in)
	})
}
