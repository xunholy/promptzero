package x509decode

import "testing"

// seedInputs exercise the PEM / hex-DER / base64 input paths plus the
// truncated and malformed cases each decoder must survive without panicking.
var seedInputs = []string{
	"", "30", "3082", "MIIB", "-----BEGIN CERTIFICATE-----",
	"-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----",
	"-----BEGIN X509 CRL-----\nMIIB\n-----END X509 CRL-----",
	"308202", "MIICabc==", "zzzz", "0a01ff",
}

func FuzzDecode(f *testing.F) {
	for _, s := range seedInputs {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { _, _ = Decode(s) })
}

// FuzzDecodeCSR fuzzes the PKCS#10 decoder, including its PEM-block scan and
// hex-DER path, against arbitrary input.
func FuzzDecodeCSR(f *testing.F) {
	for _, s := range seedInputs {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { _, _ = DecodeCSR(s) })
}

// FuzzDecodeCRL fuzzes the CRL decoder, including the bounded revoked-serial
// loop, against arbitrary input.
func FuzzDecodeCRL(f *testing.F) {
	for _, s := range seedInputs {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { _, _ = DecodeCRL(s) })
}

// FuzzDecodeOCSP fuzzes the OCSP-response decoder, including its hex/base64
// input detection and the responder-name ASN.1 parse, against arbitrary input.
func FuzzDecodeOCSP(f *testing.F) {
	for _, s := range seedInputs {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { _, _ = DecodeOCSP(s) })
}

// FuzzVerifyChain fuzzes the chain verifier, including its multi-block PEM
// scan and DER-concatenation path, against arbitrary input.
func FuzzVerifyChain(f *testing.F) {
	for _, s := range seedInputs {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { _, _ = VerifyChain(s) })
}
