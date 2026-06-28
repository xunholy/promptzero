// SPDX-License-Identifier: AGPL-3.0-or-later

package tools

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestCSRDecodeTool(t *testing.T) {
	spec, ok := Get("csr_decode")
	if !ok {
		t.Fatal("csr_decode not registered")
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "agent.example.com"},
		DNSNames: []string{"agent.example.com"},
	}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))

	out, err := spec.Handler(context.Background(), &Deps{}, map[string]any{"input": pemStr})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	var r struct {
		Subject struct {
			CommonName string `json:"common_name"`
		} `json:"subject"`
		SignatureValid bool `json:"signature_valid"`
	}
	if jerr := json.Unmarshal([]byte(out), &r); jerr != nil {
		t.Fatalf("unmarshal: %v\n%s", jerr, out)
	}
	if r.Subject.CommonName != "agent.example.com" || !r.SignatureValid {
		t.Errorf("got CN=%q valid=%v", r.Subject.CommonName, r.SignatureValid)
	}

	if _, err := spec.Handler(context.Background(), &Deps{}, map[string]any{}); err == nil {
		t.Error("missing input should error")
	}
}

func TestCRLDecodeTool(t *testing.T) {
	spec, ok := Get("crl_decode")
	if !ok {
		t.Fatal("crl_decode not registered")
	}
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(3), ThisUpdate: now, NextUpdate: now.Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: big.NewInt(0xabc), RevocationTime: now}},
	}, caCert, caKey)
	if err != nil {
		t.Fatalf("create CRL: %v", err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER}))

	out, err := spec.Handler(context.Background(), &Deps{}, map[string]any{"input": pemStr})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"revoked_count": 1`) || !strings.Contains(out, "ABC") {
		t.Errorf("crl output missing expected fields:\n%s", out)
	}
	if _, err := spec.Handler(context.Background(), &Deps{}, map[string]any{}); err == nil {
		t.Error("missing input should error")
	}
}
