// SPDX-License-Identifier: AGPL-3.0-or-later

package x509decode

import (
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

// chainCert creates a certificate signed by parent (parent==nil/parentKey for
// a self-signed root). isCA controls BasicConstraints; notAfter sets validity.
func chainCert(t *testing.T, cn string, serial int64, isCA bool, notAfter time.Time, parent *x509.Certificate, parentKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	signer, signerKey := parent, parentKey
	if signer == nil { // self-signed
		signer, signerKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("create cert %q: %v", cn, err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert %q: %v", cn, err)
	}
	return c, key
}

func pemChain(certs ...*x509.Certificate) string {
	var b strings.Builder
	for _, c := range certs {
		b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	return b.String()
}

func TestVerifyChain_OrderedToRoot(t *testing.T) {
	far := time.Now().Add(24 * time.Hour)
	root, rootKey := chainCert(t, "Root CA", 1, true, far, nil, nil)
	inter, interKey := chainCert(t, "Intermediate CA", 2, true, far, root, rootKey)
	leaf, _ := chainCert(t, "leaf.example.com", 3, false, far, inter, interKey)

	res, err := VerifyChain(pemChain(leaf, inter, root))
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if res.Count != 3 || !res.Ordered || !res.ReachesSelfSignedRoot || res.AnyExpired {
		t.Errorf("got %+v", res)
	}
	if len(res.Links) != 2 || !res.Links[0].Valid || !res.Links[1].Valid {
		t.Errorf("links = %+v", res.Links)
	}
}

func TestVerifyChain_WrongOrder(t *testing.T) {
	far := time.Now().Add(24 * time.Hour)
	root, rootKey := chainCert(t, "Root CA", 1, true, far, nil, nil)
	inter, interKey := chainCert(t, "Intermediate CA", 2, true, far, root, rootKey)
	leaf, _ := chainCert(t, "leaf.example.com", 3, false, far, inter, interKey)

	// Supplied root-first: adjacent links won't verify.
	res, err := VerifyChain(pemChain(root, leaf, inter))
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if res.Ordered {
		t.Errorf("a misordered chain must not report Ordered=true: %+v", res.Links)
	}
}

func TestVerifyChain_SingleCert(t *testing.T) {
	leaf, _ := chainCert(t, "solo.example.com", 9, false, time.Now().Add(24*time.Hour), nil, nil)
	res, err := VerifyChain(pemChain(leaf))
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if res.Count != 1 || len(res.Links) != 0 || !strings.Contains(res.Note, "single certificate") {
		t.Errorf("single-cert: %+v", res)
	}
}

func TestVerifyChain_ExpiredFlagged(t *testing.T) {
	root, rootKey := chainCert(t, "Root CA", 1, true, time.Now().Add(24*time.Hour), nil, nil)
	// Intermediate already expired.
	inter, _ := chainCert(t, "Old Intermediate", 2, true, time.Now().Add(-time.Hour), root, rootKey)
	res, err := VerifyChain(pemChain(inter, root))
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !res.AnyExpired {
		t.Error("expired intermediate should set AnyExpired")
	}
	// The signature link still verifies (expiry isn't folded into link validity).
	if !res.Ordered {
		t.Errorf("expiry must not break signature linkage: %+v", res.Links)
	}
}

func TestVerifyChain_BadInput(t *testing.T) {
	if _, err := VerifyChain(""); err == nil {
		t.Error("empty input should error")
	}
	if _, err := VerifyChain("-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----"); err == nil {
		t.Error("PEM without a CERTIFICATE block should error")
	}
}
