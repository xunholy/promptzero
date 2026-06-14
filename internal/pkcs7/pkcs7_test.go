package pkcs7

import (
	"encoding/base64"
	"strings"
	"testing"
)

// All vectors are real openssl-generated CMS over a self-signed
// CN=cms-test/O=PromptZero certificate (RSA-2048):
//
//	p7b      — crl2pkcs7 cert-only SignedData (a .p7b cert bundle)
//	p7s      — smime -sign -md sha256 (SignedData with 1 signer, embedded content)
//	p7sSHA1  — smime -sign -md sha1   (exercises the weak-digest flag)
//	env      — smime -encrypt -aes256 (EnvelopedData, 1 recipient)
const p7b = "MIIDYAYJKoZIhvcNAQcCoIIDUTCCA00CAQExADALBgkqhkiG9w0BBwGgggM1MIIDMTCCAhmgAwIBAgIUMk74O2uwlD2P8nx4ALA1+el/imQwDQYJKoZIhvcNAQELBQAwKDERMA8GA1UEAwwIY21zLXRlc3QxEzARBgNVBAoMClByb21wdFplcm8wHhcNMjYwNjE0MDUyNjQ0WhcNMjYwNjE1MDUyNjQ0WjAoMREwDwYDVQQDDAhjbXMtdGVzdDETMBEGA1UECgwKUHJvbXB0WmVybzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANopc4ensLRApvuLYUc+mst5cz+Sst0l0WOhwoeqxZEeiML3szi31nDOStnYu6iCsK4uMeJ6oTs4W0M3LiKkQ+YWNTqSDpA+QNLBjCbSKKAgUIu9EdwrGdi1yyJAICoXFe/jZcZ7QSf0lIMETLetuqv9r0DsCcbYcBoYi2X1ePh7J7x2AHSHlmI9Y0VRckw40q2gtV2aDjMoQQtYU4lWVXb6xeQwAr2a/MfFE2ajNqTqxKRUyCbstVzqOub/8T/5Z4W2q85ggJXB8ngV+HbuE5buD6CUcEUnv+kOO6fjp3Ae2UW09PrBoMSKpKSVfInVtAHE1sep+E7YTY2qvdHedCcCAwEAAaNTMFEwHQYDVR0OBBYEFPHjEukPJCs2XzqhZwT/wCXOW41uMB8GA1UdIwQYMBaAFPHjEukPJCs2XzqhZwT/wCXOW41uMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBACzd2mHvk5VtZrZGn8nq+Ut/4qW5mv8MlYXzI8a+M6LRKlmJb3M2plL6h3kauJFQCv95r/FOqmIPYSzBl07w1c9njBgKH1l+pZ8NjwlUiQKJpilCoI5OMJUmiT+59vZSfy6BfY1JFZJOTZJtlLuvYesowzUy3GXgeJBvnGZqddwTWH8Zz+q5ewt/P25GrZYkYy32ujwf5E+RN3/sJbzOB1kRVHD8+2pnDKkk48SS/J+6A/stx8G9R/rF9ZcYdX0EXMFSRr5UiLDMPMOOp85GIace4i+k4LTi/v9vyeSm/UHBRlZbuGsye955gVLhxT4xgslMGtpY73qUQLWU36I0wLExAA=="
const p7s = "MIIF0gYJKoZIhvcNAQcCoIIFwzCCBb8CAQExDzANBglghkgBZQMEAgEFADAaBgkqhkiG9w0BBwGgDQQLaGVsbG8gY21zDQqgggM1MIIDMTCCAhmgAwIBAgIUMk74O2uwlD2P8nx4ALA1+el/imQwDQYJKoZIhvcNAQELBQAwKDERMA8GA1UEAwwIY21zLXRlc3QxEzARBgNVBAoMClByb21wdFplcm8wHhcNMjYwNjE0MDUyNjQ0WhcNMjYwNjE1MDUyNjQ0WjAoMREwDwYDVQQDDAhjbXMtdGVzdDETMBEGA1UECgwKUHJvbXB0WmVybzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANopc4ensLRApvuLYUc+mst5cz+Sst0l0WOhwoeqxZEeiML3szi31nDOStnYu6iCsK4uMeJ6oTs4W0M3LiKkQ+YWNTqSDpA+QNLBjCbSKKAgUIu9EdwrGdi1yyJAICoXFe/jZcZ7QSf0lIMETLetuqv9r0DsCcbYcBoYi2X1ePh7J7x2AHSHlmI9Y0VRckw40q2gtV2aDjMoQQtYU4lWVXb6xeQwAr2a/MfFE2ajNqTqxKRUyCbstVzqOub/8T/5Z4W2q85ggJXB8ngV+HbuE5buD6CUcEUnv+kOO6fjp3Ae2UW09PrBoMSKpKSVfInVtAHE1sep+E7YTY2qvdHedCcCAwEAAaNTMFEwHQYDVR0OBBYEFPHjEukPJCs2XzqhZwT/wCXOW41uMB8GA1UdIwQYMBaAFPHjEukPJCs2XzqhZwT/wCXOW41uMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBACzd2mHvk5VtZrZGn8nq+Ut/4qW5mv8MlYXzI8a+M6LRKlmJb3M2plL6h3kauJFQCv95r/FOqmIPYSzBl07w1c9njBgKH1l+pZ8NjwlUiQKJpilCoI5OMJUmiT+59vZSfy6BfY1JFZJOTZJtlLuvYesowzUy3GXgeJBvnGZqddwTWH8Zz+q5ewt/P25GrZYkYy32ujwf5E+RN3/sJbzOB1kRVHD8+2pnDKkk48SS/J+6A/stx8G9R/rF9ZcYdX0EXMFSRr5UiLDMPMOOp85GIace4i+k4LTi/v9vyeSm/UHBRlZbuGsye955gVLhxT4xgslMGtpY73qUQLWU36I0wLExggJSMIICTgIBATBAMCgxETAPBgNVBAMMCGNtcy10ZXN0MRMwEQYDVQQKDApQcm9tcHRaZXJvAhQyTvg7a7CUPY/yfHgAsDX56X+KZDANBglghkgBZQMEAgEFAKCB5DAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA2MTQwNTI2NDRaMC8GCSqGSIb3DQEJBDEiBCBdfgarUBJ4L9cBwGqK9lk303tXBKhEBB42ZNi0Kj3mRDB5BgkqhkiG9w0BCQ8xbDBqMAsGCWCGSAFlAwQBKjALBglghkgBZQMEARYwCwYJYIZIAWUDBAECMAoGCCqGSIb3DQMHMA4GCCqGSIb3DQMCAgIAgDANBggqhkiG9w0DAgIBQDAHBgUrDgMCBzANBggqhkiG9w0DAgIBKDANBgkqhkiG9w0BAQEFAASCAQAVBbNOZO2IVj16J80n+XvmuigOlXreCgVfbqYb8RQcD+d1gGvbo1Sn9bZ0avsGTJSVOvJo+r539KCO2PdGT0d6M8sDx4UsxHMB5pX3n0oQJq8gncvUiSt+3V8iJxSx51wl6If+umEv7Dij8GaN+tymYhFIDMAwyFJrFDGnuJUvSnXBQD+z9jn10ghL2GrGd+9BRLAqTSfgf1UHnPoEx7qCtVHHo+7nHsGN/9qTji3uJ+3uwcCZmraOUc+4GQY2Qz4BOw7gqGc95v4H/Ec6LaIy025WjUDG2wYONHqMRAauWRw7QXGveLVMhmTZ/UJ5Pj2d4eMsYVi1gBWhQBWJ5IH4"
const p7sSHA1 = "MIIFvgYJKoZIhvcNAQcCoIIFrzCCBasCAQExCzAJBgUrDgMCGgUAMBoGCSqGSIb3DQEHAaANBAtoZWxsbyBjbXMNCqCCAzUwggMxMIICGaADAgECAhQyTvg7a7CUPY/yfHgAsDX56X+KZDANBgkqhkiG9w0BAQsFADAoMREwDwYDVQQDDAhjbXMtdGVzdDETMBEGA1UECgwKUHJvbXB0WmVybzAeFw0yNjA2MTQwNTI2NDRaFw0yNjA2MTUwNTI2NDRaMCgxETAPBgNVBAMMCGNtcy10ZXN0MRMwEQYDVQQKDApQcm9tcHRaZXJvMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2ilzh6ewtECm+4thRz6ay3lzP5Ky3SXRY6HCh6rFkR6IwvezOLfWcM5K2di7qIKwri4x4nqhOzhbQzcuIqRD5hY1OpIOkD5A0sGMJtIooCBQi70R3CsZ2LXLIkAgKhcV7+NlxntBJ/SUgwRMt626q/2vQOwJxthwGhiLZfV4+HsnvHYAdIeWYj1jRVFyTDjSraC1XZoOMyhBC1hTiVZVdvrF5DACvZr8x8UTZqM2pOrEpFTIJuy1XOo65v/xP/lnhbarzmCAlcHyeBX4du4Tlu4PoJRwRSe/6Q47p+OncB7ZRbT0+sGgxIqkpJV8idW0AcTWx6n4TthNjaq90d50JwIDAQABo1MwUTAdBgNVHQ4EFgQU8eMS6Q8kKzZfOqFnBP/AJc5bjW4wHwYDVR0jBBgwFoAU8eMS6Q8kKzZfOqFnBP/AJc5bjW4wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEALN3aYe+TlW1mtkafyer5S3/ipbma/wyVhfMjxr4zotEqWYlvczamUvqHeRq4kVAK/3mv8U6qYg9hLMGXTvDVz2eMGAofWX6lnw2PCVSJAommKUKgjk4wlSaJP7n29lJ/LoF9jUkVkk5Nkm2Uu69h6yjDNTLcZeB4kG+cZmp13BNYfxnP6rl7C38/bkatliRjLfa6PB/kT5E3f+wlvM4HWRFUcPz7amcMqSTjxJL8n7oD+y3Hwb1H+sX1lxh1fQRcwVJGvlSIsMw8w46nzkYhpx7iL6TgtOL+/2/J5Kb9QcFGVlu4azJ73nmBUuHFPjGCyUwa2ljvepRAtZTfojTAsTGCAkIwggI+AgEBMEAwKDERMA8GA1UEAwwIY21zLXRlc3QxEzARBgNVBAoMClByb21wdFplcm8CFDJO+DtrsJQ9j/J8eACwNfnpf4pkMAkGBSsOAwIaBQCggdgwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYwNjE0MDUyOTM1WjAjBgkqhkiG9w0BCQQxFgQUYr+sAebeiWnotAoXGVJCLJdj2ycweQYJKoZIhvcNAQkPMWwwajALBglghkgBZQMEASowCwYJYIZIAWUDBAEWMAsGCWCGSAFlAwQBAjAKBggqhkiG9w0DBzAOBggqhkiG9w0DAgICAIAwDQYIKoZIhvcNAwICAUAwBwYFKw4DAgcwDQYIKoZIhvcNAwICASgwDQYJKoZIhvcNAQEBBQAEggEAJjRytSdmunWAR0m+iFrqAyRZfa58DRe7V6ijINfJQlHEcVBYpyof6Jj6ThIIr8K6zy9jViJMWwGJrq1fYTBsiQruTf0xQMCraCNt2E3ExHYNsCpGcbQKAMXoPvBYo+A+21l7KQGVuuoxYIJoamOX4t7PEIei/vLPV4LW5in/GWvL8vLybeH9CNlZpu3gaP0I17TqCiSD8NwTnoke5ylrul6SAtVZcs+NvcqcVXvJrpHLkH+nqgCqQZu+87uOtp67yJf9TelWL+2nNe7jqC0hJySpwaFFROec0fZaxyOblzPmIxAweo6eEenWpqjI7k9g0/ZJIxDNCuZtYs8qDhVuiw=="
const env = "MIIBtAYJKoZIhvcNAQcDoIIBpTCCAaECAQAxggFcMIIBWAIBADBAMCgxETAPBgNVBAMMCGNtcy10ZXN0MRMwEQYDVQQKDApQcm9tcHRaZXJvAhQyTvg7a7CUPY/yfHgAsDX56X+KZDANBgkqhkiG9w0BAQEFAASCAQA7Wr6+Y5FNEdobB4/ktJmUkmOkLZghHlvjGuDB+IdGRT4Ek9vUk7lcvQGV1Wv1qkxfqH7IS4h0iFuj8NDL8NaXFI2+R+Wdt+6qjLVUMZDL4K/76ntqK0RJ1FUPrA0WSvQbIb+ZI6wRo1l94eA4FQKZO+vYS3hlYdrNxL83/b6GWq2cDfFS1Jr62YRCcbvbkTS6TrF0q8oyfx1bAiX4qZpJBVOpiyE0YnKeoo2Rc4qeK3PXK5bIoTe6MupmHXgVS/Rp5x/xuxHSdjJtukn0yFNy84QdPtW9+sggxgzT9qb/v0vJIEL5UYuR3tuTqFgVv3IXepEmNRk3YCzAf6vy1vRtMDwGCSqGSIb3DQEHATAdBglghkgBZQMEASoEELKFyLnzvOlTaUe8/g1ADaiAEFAzBrVFJUz4sRpXLunD2QU="

func decode(t *testing.T, b64 string) *Result {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	r, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	return r
}

func TestDecode_CertBundle(t *testing.T) {
	r := decode(t, p7b)
	if !strings.HasPrefix(r.ContentType, "signedData") {
		t.Fatalf("content type = %q", r.ContentType)
	}
	if r.SignedData == nil {
		t.Fatal("no signed_data")
	}
	if len(r.SignedData.Certificates) != 1 {
		t.Fatalf("certs = %d, want 1", len(r.SignedData.Certificates))
	}
	c := r.SignedData.Certificates[0]
	if !strings.Contains(c.Subject, "cms-test") || !strings.Contains(c.Subject, "PromptZero") {
		t.Errorf("subject = %q", c.Subject)
	}
	if !strings.Contains(c.PublicKeyAlgorithm, "RSA") {
		t.Errorf("pubkey alg = %q", c.PublicKeyAlgorithm)
	}
	if len(r.SignedData.Signers) != 0 {
		t.Errorf("a cert bundle has no signers, got %d", len(r.SignedData.Signers))
	}
}

func TestDecode_SignedSHA256(t *testing.T) {
	r := decode(t, p7s)
	sd := r.SignedData
	if sd == nil || len(sd.Signers) != 1 {
		t.Fatalf("want 1 signer, got %+v", sd)
	}
	if !contains(sd.DigestAlgorithms, "SHA-256 (2.16.840.1.101.3.4.2.1)") {
		t.Errorf("digest algs = %v", sd.DigestAlgorithms)
	}
	s := sd.Signers[0]
	if !strings.Contains(s.DigestAlgorithm, "SHA-256") {
		t.Errorf("signer digest = %q", s.DigestAlgorithm)
	}
	if !strings.Contains(s.IssuerAndSerial, "cms-test") || !strings.Contains(s.IssuerAndSerial, "serial=") {
		t.Errorf("issuer+serial = %q", s.IssuerAndSerial)
	}
	if !s.HasSignedAttrs {
		t.Errorf("expected signed attributes (S/MIME always carries them)")
	}
	if s.SigningTime == "" {
		t.Errorf("expected a signing time from the signed attributes")
	}
	if !sd.Detached == false { // content is embedded (-nodetach)
		t.Errorf("expected embedded (non-detached) content")
	}
	if strings.Contains(r.Note, "WEAK") {
		t.Errorf("SHA-256 should not be flagged weak: %q", r.Note)
	}
}

func TestDecode_WeakSHA1Flagged(t *testing.T) {
	r := decode(t, p7sSHA1)
	if r.SignedData == nil {
		t.Fatal("no signed_data")
	}
	if !strings.Contains(r.Note, "WEAK") || !strings.Contains(strings.ToLower(r.Note), "sha-1") {
		t.Errorf("expected SHA-1 weak flag, note = %q", r.Note)
	}
}

func TestDecode_Enveloped(t *testing.T) {
	r := decode(t, env)
	if !strings.HasPrefix(r.ContentType, "envelopedData") {
		t.Fatalf("content type = %q", r.ContentType)
	}
	ed := r.EnvelopedData
	if ed == nil {
		t.Fatal("no enveloped_data")
	}
	if ed.RecipientCount != 1 {
		t.Errorf("recipients = %d, want 1", ed.RecipientCount)
	}
	if !strings.Contains(ed.ContentEncryptionAlgorithm, "AES-256-CBC") {
		t.Errorf("content enc alg = %q", ed.ContentEncryptionAlgorithm)
	}
	if !strings.Contains(r.Note, "private key is needed") {
		t.Errorf("note = %q", r.Note)
	}
}

func TestDecode_Errors(t *testing.T) {
	for name, in := range map[string][]byte{
		"empty":   {},
		"garbage": []byte("not der at all"),
		"trunc":   {0x30, 0x82, 0xff, 0xff},
	} {
		if _, err := Decode(in); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func FuzzDecode(f *testing.F) {
	for _, v := range []string{p7b, p7s, p7sSHA1, env} {
		if b, err := base64.StdEncoding.DecodeString(v); err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{})
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
