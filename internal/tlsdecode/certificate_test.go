// SPDX-License-Identifier: AGPL-3.0-or-later

package tlsdecode

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// makeCertDER generates a self-signed certificate and returns its DER bytes.
// Go's crypto/x509 is the reference encoder; internal/x509decode (which this
// chains to) is already tested against it, so wrapping a known cert in a TLS
// Certificate message is a self-contained, deterministic anchor.
func makeCertDER(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x1234),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"PromptZero Test"}},
		NotBefore:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC),
		DNSNames:     []string{cn, "alt." + cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// tlsCertRecord wraps DER certificates in a TLS 1.2 Certificate handshake
// message inside a handshake record (content type 0x16, version 0x0303).
func tlsCertRecord(ders ...[]byte) []byte {
	u24 := func(n int) []byte { return []byte{byte(n >> 16), byte(n >> 8), byte(n)} }
	var list []byte
	for _, d := range ders {
		list = append(list, u24(len(d))...)
		list = append(list, d...)
	}
	body := append(u24(len(list)), list...)                        // certificate_list
	hs := append([]byte{0x0b}, append(u24(len(body)), body...)...) // type 11 + len + body
	rec := []byte{0x16, 0x03, 0x03, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
}

func TestDecodeCertificate_SingleCert(t *testing.T) {
	der := makeCertDER(t, "example.test")
	rec := tlsCertRecord(der)

	f, err := DecodeBytes(rec)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Records) != 1 || len(f.Records[0].Handshakes) != 1 {
		t.Fatalf("record/handshake shape: %+v", f.Records)
	}
	hs := f.Records[0].Handshakes[0]
	if hs.MessageType != 11 || hs.MessageName != "Certificate" {
		t.Fatalf("handshake type = %d (%s)", hs.MessageType, hs.MessageName)
	}
	if hs.Certificate == nil || hs.Certificate.CertificateCount != 1 {
		t.Fatalf("certificate message: %+v", hs.Certificate)
	}
	ce := hs.Certificate.Certificates[0]
	if ce.DecodeError != "" || ce.Certificate == nil {
		t.Fatalf("cert decode error: %q", ce.DecodeError)
	}
	c := ce.Certificate
	if c.Subject == nil || c.Subject.CommonName != "example.test" {
		t.Errorf("subject CN = %+v", c.Subject)
	}
	if !c.SelfSigned {
		t.Errorf("self-signed cert should be flagged self-signed")
	}
	// SAN DNS names surfaced via x509decode.
	foundSAN := false
	if c.Extensions != nil {
		for _, n := range c.Extensions.DNSNames {
			if n == "alt.example.test" {
				foundSAN = true
			}
		}
	}
	if !foundSAN {
		t.Errorf("expected SAN alt.example.test in %+v", c.Extensions)
	}
}

func TestDecodeCertificate_Chain(t *testing.T) {
	rec := tlsCertRecord(makeCertDER(t, "leaf.test"), makeCertDER(t, "ca.test"))
	f, err := DecodeBytes(rec)
	if err != nil {
		t.Fatal(err)
	}
	cm := f.Records[0].Handshakes[0].Certificate
	if cm == nil || cm.CertificateCount != 2 {
		t.Fatalf("want 2 certs, got %+v", cm)
	}
	if cm.Certificates[0].Certificate.Subject.CommonName != "leaf.test" ||
		cm.Certificates[1].Certificate.Subject.CommonName != "ca.test" {
		t.Errorf("chain order wrong")
	}
}

func TestDecodeCertificate_MalformedListLength(t *testing.T) {
	// Handshake type 11 with a body whose certificate_list length is wrong.
	body := []byte{0x00, 0x00, 0xFF, 0xAA, 0xBB} // listLen=255 but only 2 bytes follow
	hs := append([]byte{0x0b, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	rec := append([]byte{0x16, 0x03, 0x03, byte(len(hs) >> 8), byte(len(hs))}, hs...)
	f, err := DecodeBytes(rec)
	if err != nil {
		t.Fatal(err)
	}
	cm := f.Records[0].Handshakes[0].Certificate
	if cm == nil || cm.CertificateCount != 0 || len(cm.Notes) == 0 {
		t.Errorf("malformed list length should yield 0 certs + a note: %+v", cm)
	}
}

func TestDecodeCertificate_GarbageCertSurfacedRaw(t *testing.T) {
	// Well-framed Certificate message but the "cert" bytes aren't valid DER.
	garbage := []byte{0x01, 0x02, 0x03, 0x04}
	rec := tlsCertRecord(garbage)
	f, err := DecodeBytes(rec)
	if err != nil {
		t.Fatal(err)
	}
	ce := f.Records[0].Handshakes[0].Certificate.Certificates[0]
	if ce.DecodeError == "" {
		t.Errorf("invalid DER should surface a decode_error, not a confident decode")
	}
	if ce.Certificate != nil {
		t.Errorf("invalid DER should not produce a decoded certificate")
	}
	if ce.DERHex == "" {
		t.Errorf("invalid DER should still be surfaced raw")
	}
}
