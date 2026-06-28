// SPDX-License-Identifier: AGPL-3.0-or-later

package x509decode

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func ocspTestCA(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "OCSP CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	return cert, key
}

func TestDecodeOCSP_Good(t *testing.T) {
	ca, key := ocspTestCA(t)
	now := time.Now()
	der, err := ocsp.CreateResponse(ca, ca, ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: big.NewInt(0x1234),
		ThisUpdate:   now,
		NextUpdate:   now.Add(24 * time.Hour),
	}, key)
	if err != nil {
		t.Fatalf("create OCSP: %v", err)
	}
	// base64 (HTTP form) and hex must decode identically.
	for _, in := range []string{base64.StdEncoding.EncodeToString(der), hex.EncodeToString(der)} {
		info, err := DecodeOCSP(in)
		if err != nil {
			t.Fatalf("DecodeOCSP: %v", err)
		}
		if info.Status != "good" {
			t.Errorf("status = %q, want good", info.Status)
		}
		if info.SerialNumberHex != "1234" {
			t.Errorf("serial = %q, want 1234", info.SerialNumberHex)
		}
		if info.NextUpdate == "" || info.Expired {
			t.Errorf("next_update=%q expired=%v", info.NextUpdate, info.Expired)
		}
		if !strings.Contains(info.ResponderName, "OCSP CA") {
			t.Errorf("responder = %q", info.ResponderName)
		}
		if info.RevocationReason != "" {
			t.Errorf("good response should carry no revocation reason, got %q", info.RevocationReason)
		}
	}
}

func TestDecodeOCSP_Revoked(t *testing.T) {
	ca, key := ocspTestCA(t)
	now := time.Now()
	der, err := ocsp.CreateResponse(ca, ca, ocsp.Response{
		Status:           ocsp.Revoked,
		SerialNumber:     big.NewInt(0x5678),
		ThisUpdate:       now,
		NextUpdate:       now.Add(24 * time.Hour),
		RevokedAt:        now.Add(-2 * time.Hour),
		RevocationReason: ocsp.KeyCompromise,
	}, key)
	if err != nil {
		t.Fatalf("create OCSP: %v", err)
	}
	info, err := DecodeOCSP(base64.StdEncoding.EncodeToString(der))
	if err != nil {
		t.Fatalf("DecodeOCSP: %v", err)
	}
	if info.Status != "revoked" {
		t.Errorf("status = %q, want revoked", info.Status)
	}
	if info.RevocationReason != "keyCompromise" {
		t.Errorf("reason = %q, want keyCompromise", info.RevocationReason)
	}
	if info.RevokedAt == "" {
		t.Error("revoked response should carry revoked_at")
	}
	if info.SerialNumberHex != "5678" {
		t.Errorf("serial = %q, want 5678", info.SerialNumberHex)
	}
}

func TestDecodeOCSP_BadInput(t *testing.T) {
	if _, err := DecodeOCSP(""); err == nil {
		t.Error("empty input should error")
	}
	if _, err := DecodeOCSP("@@@not-base64-or-hex@@@"); err == nil {
		t.Error("garbage input should error")
	}
	// Valid base64 that isn't an OCSP response.
	if _, err := DecodeOCSP(base64.StdEncoding.EncodeToString([]byte("hello world not ocsp"))); err == nil {
		t.Error("non-OCSP DER should error")
	}
}
