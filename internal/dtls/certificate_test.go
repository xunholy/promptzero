// SPDX-License-Identifier: AGPL-3.0-or-later

package dtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"testing"
	"time"
)

func makeCertDER(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x2222),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC),
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// dtlsCertRecord wraps DER certificates in a DTLS Certificate handshake
// message (msg_type 11, unfragmented) inside a DTLS 1.2 handshake record.
func dtlsCertRecord(ders ...[]byte) []byte {
	u24 := func(n int) []byte { return []byte{byte(n >> 16), byte(n >> 8), byte(n)} }
	var list []byte
	for _, d := range ders {
		list = append(list, u24(len(d))...)
		list = append(list, d...)
	}
	body := append(u24(len(list)), list...) // certificate_list

	// DTLS handshake header: type(1) length(3) message_seq(2)
	// fragment_offset(3) fragment_length(3) — unfragmented.
	hs := []byte{0x0b}
	hs = append(hs, u24(len(body))...)
	hs = append(hs, 0x00, 0x00) // message_seq
	hs = append(hs, u24(0)...)  // fragment_offset
	hs = append(hs, u24(len(body))...)
	hs = append(hs, body...)

	// DTLS record header: type(1) version(2) epoch(2) seq(6) length(2).
	rec := []byte{0x16, 0xFE, 0xFD, 0x00, 0x00, 0, 0, 0, 0, 0, 0}
	rec = append(rec, byte(len(hs)>>8), byte(len(hs)))
	return append(rec, hs...)
}

func TestDecodeCertificate_DTLS_SingleCert(t *testing.T) {
	der := makeCertDER(t, "dtls.test")
	r, err := Decode(hex.EncodeToString(dtlsCertRecord(der)))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Records) != 1 || r.Records[0].Handshake == nil {
		t.Fatalf("record/handshake shape: %+v", r.Records)
	}
	hs := r.Records[0].Handshake
	if hs.MsgType != 11 {
		t.Fatalf("msg type = %d, want 11", hs.MsgType)
	}
	if hs.Certificate == nil || hs.Certificate.CertificateCount != 1 {
		t.Fatalf("certificate message: %+v", hs.Certificate)
	}
	ce := hs.Certificate.Certificates[0]
	if ce.DecodeError != "" || ce.Certificate == nil {
		t.Fatalf("cert decode error: %q", ce.DecodeError)
	}
	if ce.Certificate.Subject == nil || ce.Certificate.Subject.CommonName != "dtls.test" {
		t.Errorf("subject CN = %+v", ce.Certificate.Subject)
	}
	if !ce.Certificate.SelfSigned {
		t.Errorf("self-signed cert should be flagged")
	}
}

func TestDecodeCertificate_DTLS_Chain(t *testing.T) {
	r, err := Decode(hex.EncodeToString(dtlsCertRecord(makeCertDER(t, "leaf.dtls"), makeCertDER(t, "ca.dtls"))))
	if err != nil {
		t.Fatal(err)
	}
	cm := r.Records[0].Handshake.Certificate
	if cm == nil || cm.CertificateCount != 2 {
		t.Fatalf("want 2 certs: %+v", cm)
	}
	if cm.Certificates[0].Certificate.Subject.CommonName != "leaf.dtls" ||
		cm.Certificates[1].Certificate.Subject.CommonName != "ca.dtls" {
		t.Errorf("chain order wrong")
	}
}

func TestDecodeCertificate_DTLS_GarbageSurfacedRaw(t *testing.T) {
	r, err := Decode(hex.EncodeToString(dtlsCertRecord([]byte{0x01, 0x02, 0x03})))
	if err != nil {
		t.Fatal(err)
	}
	ce := r.Records[0].Handshake.Certificate.Certificates[0]
	if ce.DecodeError == "" || ce.Certificate != nil {
		t.Errorf("invalid DER should yield decode_error + no cert: %+v", ce)
	}
	if ce.DERHex == "" {
		t.Errorf("invalid DER should be surfaced raw")
	}
}
