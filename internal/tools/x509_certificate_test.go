package tools

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// TestX509CertificateDecodeHandler_PEM pins a freshly-generated
// RSA cert through the Spec handler to JSON.
func TestX509CertificateDecodeHandler_PEM(t *testing.T) {
	pemBytes := newTestCertForHandler(t)
	out, err := x509CertificateDecodeHandler(context.Background(), nil, map[string]any{
		"input": string(pemBytes),
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"source": "PEM"`) {
		t.Errorf("expected source PEM:\n%s", out)
	}
	if !strings.Contains(out, `"public_key_algorithm": "RSA"`) {
		t.Errorf("expected RSA algorithm:\n%s", out)
	}
	if !strings.Contains(out, `"common_name": "handler-test.example.com"`) {
		t.Errorf("expected CN:\n%s", out)
	}
}

func TestX509CertificateDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := x509CertificateDecodeHandler(context.Background(), nil, map[string]any{"input": ""})
	if err == nil {
		t.Fatal("want error for empty input")
	}
}

func TestX509CertificateDecodeHandler_RejectsBadInput(t *testing.T) {
	_, err := x509CertificateDecodeHandler(context.Background(), nil, map[string]any{"input": "ZZ"})
	if err == nil {
		t.Fatal("want error for invalid hex")
	}
}

func newTestCertForHandler(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "handler-test.example.com"},
		Issuer:       pkix.Name{CommonName: "handler-test.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
