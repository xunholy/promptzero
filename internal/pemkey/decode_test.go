// SPDX-License-Identifier: AGPL-3.0-or-later

package pemkey

import "testing"

// All vectors are openssl-generated. The unencrypted keys' public_sha256 equals
// `openssl pkey -in KEY -pubout -outform DER | sha256sum`; the encrypted keys'
// cipher/KDF/salt/iter/N,r,p/IV match `openssl asn1parse -in KEY`.

const ecSEC1 = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIaYVcQnGE9uhO3q3slN+Z1RwM7eLRZZ6xPe1kppJ6feoAoGCCqGSM49
AwEHoUQDQgAE4vQ4u1mxx/taKgBaA4XJtgFJlJTYv6KY0bhfcJJGPsAy+I4r8PoQ
gwnkan/HyTtRKCSpEy1AC1Z2+LJrepL2Pw==
-----END EC PRIVATE KEY-----`

const edPKCS8 = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIGgUan7sbTVHfqZ+T5UpUfkUOmzBsn3O0ggktGXc7x08
-----END PRIVATE KEY-----`

const rsa1024PKCS1 = `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQD0lGHR3D9A8wxLVzgNvxn7i/Mf6V8h63t58OpXPM4ZlIYT1c+i
oWTeZGFV/+C1QM4TaPJBv0Q1EawZIUiYuk5Q1MmdqfNpIXfPeN9ZzU9xwVcArA+s
tBnXvvEdkmv9aAs7x095ysL9Y56GfwuVO11miT8hw3uz+ncauK6mSINnuwIDAQAB
AoGACW47Q1tJuRhmDfWj/Ku0tcVUr5NRDr7EuRP4BTsb+1KFxPgGlI/Ckuyt8CH4
qSSBjbALP0u/togi6akl4nW0lUgCuA19bhwAGL2X+ZUaaB4bOjPoFP7PbzYcqtpW
1jbm127BTxOEyDAuYCgF+nib2X5u0H6a4nOuvsGEy6oArFECQQD9rQ0lXdFmgWj9
RMTeoTPU5KRBFuYBGX4cxT/KFBv99WKqLZ2EHbfJAHeuqREIavNACAi/IBPjdD/D
Bfr5ghWZAkEA9tH/OV3QURO0N0BM5VyRJSSgyShMbxU3ihKlDPV010mU395OdxWM
a6fZsHW25M7HvxqjW78aGyUNYhoDD1nUcwJAZBPkbsxvczA0uk5qGKaiKyg0wNUG
0oI7JaCPxOpgDLXFQfwS+2859Vtw3AApDxgadTV2Neiyz/YpvYfbdpniaQJBAPP3
MEp4428whcLTKO7RZ5qKMO+EiMCH/UTaFxDPEjW2wpPhvjdRMmI7IB6ezDAwABpy
byRBqcFJB4h/Y6TpyucCQQCHuMIkq+IZxrY7zj9PHx5GK5Djc4/A0h73EPdaPtI9
gQ6Dt69eBTbdZwhYxRiusEgIBMQRrH+51h8QThp+lV0p
-----END RSA PRIVATE KEY-----`

const ecTradEnc = `-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,6D72AE66A0066810229AEAFDE2995101

A3c00UKNMcIlYzLQiBW9yAJirWw8a9U1fqY5BfHiBatw+hhNLH9JtNW/KiGqM/vw
J0uNW5fvmp8oGHzo10ZOKPIFagXHsHj+xmyqbfUBN6cAxKc5JV+5OvdwUNtYX/Fs
VPKYNG2vqk/NlVX0wy+/rZuQZBJU4gzhrAlaT1Z7Vcw=
-----END EC PRIVATE KEY-----`

const ecPBKDF2 = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIH0MF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBA+ySNslsNaJYOFa7N6
HlKrAgJOIDAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQmhtiog/oAECWHyOP
fnPuUwSBkJS5DOXwaKGVU65DoY6NtwbhtIrhN7lJZQ6cMkq4mqKW+uw1qe9XfYjH
NOdnfc6GLPydrrzxDY17mTX8gpro6dtHPzM/cjhFCcVwLMVGNUpJuJhub0czYMu8
D51QdToJzDWoPMVsExeRQO6Sg0PQ56VPlb1uGJS/JLMw1YORuwofWg7Pm/yT5aUg
W8fQ8wK2sA==
-----END ENCRYPTED PRIVATE KEY-----`

const ecScrypt = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHsMFcGCSqGSIb3DQEFDTBKMCkGCSsGAQQB2kcECzAcBBD1xf7GSQ8WTu8Nubz9
qYE3AgJAAAIBCAIBATAdBglghkgBZQMEASoEEIQdURqd6BHHo6yDUuyIfusEgZBM
BgBlAjIlA705j1U6fc0vkRDW+PuNyvL55qw9DDtjO6nrHH9kfzPUFD9wSJZJNiNo
/fJ1//oks8e26ymrUS37pynSsburHm+UnQmw6ciELV2irFKgLHxLrTcgrzkiEPp7
YlHVxj3ZwqP7phE3ZXAI4t1FDPmxrIBjbvh3UtJz1O1X5RTQ1/GtiB7tcU85V34=
-----END ENCRYPTED PRIVATE KEY-----`

func TestECSEC1Unencrypted(t *testing.T) {
	r, err := Decode(ecSEC1)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Format != "pem-sec1" || r.Algorithm != "ECDSA" || r.Curve != "P-256" || r.Bits != 256 {
		t.Errorf("got format=%q algo=%q curve=%q bits=%d", r.Format, r.Algorithm, r.Curve, r.Bits)
	}
	if r.Encrypted {
		t.Error("encrypted = true, want false")
	}
	const want = "535d736bd80c95e9ba570e09db17a73de6d2a88e174cc6890f18b70102611ec7"
	if r.PublicSHA256 != want {
		t.Errorf("public_sha256 = %q, want %q", r.PublicSHA256, want)
	}
}

func TestEd25519PKCS8Unencrypted(t *testing.T) {
	r, err := Decode(edPKCS8)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Format != "pem-pkcs8" || r.Algorithm != "Ed25519" || r.Bits != 256 {
		t.Errorf("got format=%q algo=%q bits=%d", r.Format, r.Algorithm, r.Bits)
	}
	const want = "ae34dd3b22a575971f7cf57f958a26ecb96280063eb03589c2e1ab9880371b32"
	if r.PublicSHA256 != want {
		t.Errorf("public_sha256 = %q, want %q", r.PublicSHA256, want)
	}
}

func TestRSA1024PKCS1Unencrypted(t *testing.T) {
	r, err := Decode(rsa1024PKCS1)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Format != "pem-pkcs1" || r.Algorithm != "RSA" || r.Bits != 1024 {
		t.Errorf("got format=%q algo=%q bits=%d", r.Format, r.Algorithm, r.Bits)
	}
	const want = "55116c99a77934b9848a21790f9eaf28eb891a90daa0f45cdb4653e3f87e5985"
	if r.PublicSHA256 != want {
		t.Errorf("public_sha256 = %q, want %q", r.PublicSHA256, want)
	}
	// RSA-1024 is below the 2048-bit minimum — must be flagged.
	if !contains(r.Note, "weak") {
		t.Errorf("note = %q, want a weak-key warning", r.Note)
	}
}

func TestTraditionalEncrypted(t *testing.T) {
	r, err := Decode(ecTradEnc)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Format != "pem-traditional-encrypted" || !r.Encrypted {
		t.Errorf("format=%q encrypted=%v", r.Format, r.Encrypted)
	}
	if r.Algorithm != "ECDSA" {
		t.Errorf("algorithm = %q, want ECDSA (from the block label)", r.Algorithm)
	}
	if r.Cipher != "AES-256-CBC" || r.IVLen != 16 {
		t.Errorf("cipher=%q iv_len=%d, want AES-256-CBC/16", r.Cipher, r.IVLen)
	}
	if r.KDF != "EVP_BytesToKey(MD5)" {
		t.Errorf("kdf = %q, want EVP_BytesToKey(MD5)", r.KDF)
	}
	if r.PublicSHA256 != "" {
		t.Errorf("public_sha256 = %q, want empty (encrypted)", r.PublicSHA256)
	}
}

func TestPKCS8PBKDF2(t *testing.T) {
	r, err := Decode(ecPBKDF2)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Format != "pem-pkcs8-encrypted" || !r.Encrypted {
		t.Errorf("format=%q encrypted=%v", r.Format, r.Encrypted)
	}
	if r.KDF != "PBKDF2" || r.KDFSaltLen != 16 || r.KDFIterations != 20000 || r.KDFPRF != "hmacWithSHA256" {
		t.Errorf("kdf=%q saltlen=%d iter=%d prf=%q, want PBKDF2/16/20000/hmacWithSHA256",
			r.KDF, r.KDFSaltLen, r.KDFIterations, r.KDFPRF)
	}
	if r.Cipher != "aes-256-cbc" || r.IVLen != 16 {
		t.Errorf("cipher=%q iv_len=%d, want aes-256-cbc/16", r.Cipher, r.IVLen)
	}
}

func TestPKCS8Scrypt(t *testing.T) {
	r, err := Decode(ecScrypt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.KDF != "scrypt" || r.KDFSaltLen != 16 {
		t.Errorf("kdf=%q saltlen=%d, want scrypt/16", r.KDF, r.KDFSaltLen)
	}
	if r.ScryptN != 16384 || r.ScryptR != 8 || r.ScryptP != 1 {
		t.Errorf("scrypt N/r/p = %d/%d/%d, want 16384/8/1", r.ScryptN, r.ScryptR, r.ScryptP)
	}
	if r.Cipher != "aes-256-cbc" {
		t.Errorf("cipher = %q, want aes-256-cbc", r.Cipher)
	}
}

func TestRejects(t *testing.T) {
	for _, in := range []string{
		"",
		"not a pem",
		"-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----",
		"-----BEGIN PRIVATE KEY-----\nbm90REVS\n-----END PRIVATE KEY-----", // valid b64, bad DER
	} {
		if _, err := Decode(in); err == nil {
			t.Errorf("Decode(%q) = nil error, want rejection", in)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
