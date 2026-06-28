// SPDX-License-Identifier: AGPL-3.0-or-later

package x509decode

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestDecodeCSR_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: "device.example.com", Organization: []string{"Acme"}},
		DNSNames:       []string{"device.example.com", "alt.example.com"},
		IPAddresses:    []net.IP{net.ParseIP("10.0.0.5")},
		EmailAddresses: []string{"ops@example.com"},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))

	// PEM and hex-DER inputs must decode identically.
	for _, in := range []string{pemStr, hex.EncodeToString(der)} {
		info, err := DecodeCSR(in)
		if err != nil {
			t.Fatalf("DecodeCSR: %v", err)
		}
		if info.Subject.CommonName != "device.example.com" {
			t.Errorf("CN = %q", info.Subject.CommonName)
		}
		if !contains(info.DNSNames, "alt.example.com") {
			t.Errorf("DNS SANs = %v", info.DNSNames)
		}
		if !contains(info.IPAddresses, "10.0.0.5") {
			t.Errorf("IP SANs = %v", info.IPAddresses)
		}
		if !contains(info.EmailAddresses, "ops@example.com") {
			t.Errorf("email SANs = %v", info.EmailAddresses)
		}
		if info.PublicKeyDetails != "RSA 2048 bits" {
			t.Errorf("key details = %q", info.PublicKeyDetails)
		}
		if !info.SignatureValid {
			t.Errorf("self-signature should verify: %s", info.SignatureError)
		}
		if len(info.FingerprintSHA256) == 0 {
			t.Error("missing fingerprint")
		}
	}
}

func TestDecodeCRL(t *testing.T) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	crlTmpl := &x509.RevocationList{
		Number:     big.NewInt(7),
		ThisUpdate: now,
		NextUpdate: now.Add(30 * 24 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: big.NewInt(0xdead), RevocationTime: now},
			{SerialNumber: big.NewInt(0xbeef), RevocationTime: now},
		},
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTmpl, caCert, caKey)
	if err != nil {
		t.Fatalf("create CRL: %v", err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER}))

	info, err := DecodeCRL(pemStr)
	if err != nil {
		t.Fatalf("DecodeCRL: %v", err)
	}
	if info.Issuer.CommonName != "Test CA" {
		t.Errorf("issuer CN = %q", info.Issuer.CommonName)
	}
	if info.RevokedCount != 2 {
		t.Errorf("revoked count = %d, want 2", info.RevokedCount)
	}
	if info.CRLNumber != "7" {
		t.Errorf("CRL number = %q, want 7", info.CRLNumber)
	}
	if info.NextUpdate == "" || info.Expired {
		t.Errorf("next_update=%q expired=%v (should be set, not expired)", info.NextUpdate, info.Expired)
	}
	if !contains(info.RevokedSerials, "DEAD") || !contains(info.RevokedSerials, "BEEF") {
		t.Errorf("revoked serials = %v, want DEAD + BEEF", info.RevokedSerials)
	}
}

func TestDecodeCSR_CRL_BadInput(t *testing.T) {
	if _, err := DecodeCSR(""); err == nil {
		t.Error("empty CSR input should error")
	}
	if _, err := DecodeCSR("zzzz"); err == nil {
		t.Error("garbage CSR input should error")
	}
	if _, err := DecodeCRL("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"); err == nil {
		t.Error("PEM without an X509 CRL block should error")
	}
	if _, err := DecodeCRL("zzzz"); err == nil {
		t.Error("garbage CRL input should error")
	}
}

// TestDecodeCRL_SerialCap ensures the revoked-serials list is bounded.
func TestDecodeCRL_SerialCap(t *testing.T) {
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	entries := make([]x509.RevocationListEntry, maxCRLSerials+50)
	for i := range entries {
		entries[i] = x509.RevocationListEntry{SerialNumber: big.NewInt(int64(i + 1)), RevocationTime: now}
	}
	crlTmpl := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now, NextUpdate: now.Add(time.Hour), RevokedCertificateEntries: entries}
	crlDER, _ := x509.CreateRevocationList(rand.Reader, crlTmpl, caCert, caKey)

	info, err := DecodeCRL(hex.EncodeToString(crlDER))
	if err != nil {
		t.Fatalf("DecodeCRL: %v", err)
	}
	if info.RevokedCount != maxCRLSerials+50 {
		t.Errorf("count = %d, want exact %d", info.RevokedCount, maxCRLSerials+50)
	}
	if len(info.RevokedSerials) != maxCRLSerials || !info.RevokedTruncated {
		t.Errorf("serials listed = %d (truncated=%v), want %d capped+truncated", len(info.RevokedSerials), info.RevokedTruncated, maxCRLSerials)
	}
}
