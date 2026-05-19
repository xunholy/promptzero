package x509decode

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestDecode_PEM_RSA_RoundTrip generates a self-signed RSA-2048
// certificate with rich extensions (SANs, EKU, key usage, basic
// constraints, AIA, CRL), wraps it in PEM, and pins every
// documented field.
func TestDecode_PEM_RSA_RoundTrip(t *testing.T) {
	pemBytes := newTestRSACert(t)
	got, err := Decode(string(pemBytes))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Source != "PEM" {
		t.Errorf("Source = %q; want 'PEM'", got.Source)
	}
	if got.Version != 3 {
		t.Errorf("Version = %d; want 3", got.Version)
	}
	if got.PublicKeyAlgorithm != "RSA" {
		t.Errorf("PublicKeyAlgorithm = %q", got.PublicKeyAlgorithm)
	}
	if got.PublicKeyDetails != "RSA 2048 bits" {
		t.Errorf("PublicKeyDetails = %q; want 'RSA 2048 bits'", got.PublicKeyDetails)
	}
	if !strings.Contains(got.SignatureAlgorithm, "SHA256") {
		t.Errorf("SignatureAlgorithm = %q; want SHA256-RSA flavor", got.SignatureAlgorithm)
	}
	if got.Subject.CommonName != "test.example.com" {
		t.Errorf("Subject.CommonName = %q", got.Subject.CommonName)
	}
	if len(got.Subject.Organization) != 1 || got.Subject.Organization[0] != "Acme Corp" {
		t.Errorf("Subject.Organization = %v", got.Subject.Organization)
	}
	if !got.SelfSigned {
		t.Error("SelfSigned = false; want true")
	}
	if got.Expired {
		t.Error("Expired = true; want false (fresh cert)")
	}
	if got.DaysRemaining < 0 {
		t.Errorf("DaysRemaining = %d; want positive", got.DaysRemaining)
	}
	if got.Extensions == nil {
		t.Fatal("Extensions nil")
	}
	if !contains(got.Extensions.DNSNames, "test.example.com") {
		t.Errorf("DNSNames = %v; want to contain 'test.example.com'", got.Extensions.DNSNames)
	}
	if !contains(got.Extensions.DNSNames, "alt.example.com") {
		t.Errorf("DNSNames = %v; want to contain 'alt.example.com'", got.Extensions.DNSNames)
	}
	if len(got.Extensions.IPAddresses) == 0 {
		t.Error("IPAddresses empty; want IPv4")
	}
	if !contains(got.Extensions.EmailAddresses, "admin@example.com") {
		t.Errorf("EmailAddresses = %v", got.Extensions.EmailAddresses)
	}
	if !contains(got.Extensions.URIs, "https://example.com/") {
		t.Errorf("URIs = %v", got.Extensions.URIs)
	}
	if !contains(got.Extensions.KeyUsage, "digitalSignature") {
		t.Errorf("KeyUsage = %v; want 'digitalSignature'", got.Extensions.KeyUsage)
	}
	if !contains(got.Extensions.KeyUsage, "keyEncipherment") {
		t.Errorf("KeyUsage = %v; want 'keyEncipherment'", got.Extensions.KeyUsage)
	}
	if !contains(got.Extensions.ExtendedKeyUsage, "serverAuth") {
		t.Errorf("ExtendedKeyUsage = %v; want 'serverAuth'", got.Extensions.ExtendedKeyUsage)
	}
	if !contains(got.Extensions.ExtendedKeyUsage, "clientAuth") {
		t.Errorf("ExtendedKeyUsage = %v; want 'clientAuth'", got.Extensions.ExtendedKeyUsage)
	}
	if !contains(got.Extensions.OCSPServers, "http://ocsp.example.com") {
		t.Errorf("OCSPServers = %v", got.Extensions.OCSPServers)
	}
	if !contains(got.Extensions.IssuingCertificateURLs, "http://issuer.example.com/ca.crt") {
		t.Errorf("IssuingCertificateURLs = %v", got.Extensions.IssuingCertificateURLs)
	}
	if !contains(got.Extensions.CRLDistributionPoints, "http://crl.example.com/ca.crl") {
		t.Errorf("CRLDistributionPoints = %v", got.Extensions.CRLDistributionPoints)
	}
	if got.Extensions.SubjectKeyID == "" {
		t.Error("SubjectKeyID empty")
	}
	if !strings.Contains(got.FingerprintSHA1, ":") {
		t.Errorf("FingerprintSHA1 = %q; want colon-separated", got.FingerprintSHA1)
	}
	if !strings.Contains(got.FingerprintSHA256, ":") {
		t.Errorf("FingerprintSHA256 = %q; want colon-separated", got.FingerprintSHA256)
	}
	// SHA-1 fingerprint = 20 bytes → 20×3-1 = 59 chars (with
	// inter-byte separators).
	if len(got.FingerprintSHA1) != 59 {
		t.Errorf("FingerprintSHA1 length = %d; want 59", len(got.FingerprintSHA1))
	}
	// SHA-256 fingerprint = 32 bytes → 32×3-1 = 95 chars.
	if len(got.FingerprintSHA256) != 95 {
		t.Errorf("FingerprintSHA256 length = %d; want 95", len(got.FingerprintSHA256))
	}
}

// TestDecode_DER_HexInput exercises the DER path (hex-encoded
// bytes rather than PEM).
func TestDecode_DER_HexInput(t *testing.T) {
	pemBytes := newTestRSACert(t)
	// Strip PEM wrapper to get DER bytes
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("pem.Decode returned nil")
	}
	der := block.Bytes
	got, err := Decode(hex.EncodeToString(der))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Source != "DER" {
		t.Errorf("Source = %q; want 'DER'", got.Source)
	}
	if got.Subject.CommonName != "test.example.com" {
		t.Errorf("Subject.CommonName = %q", got.Subject.CommonName)
	}
}

// TestDecode_PEM_ECDSA pins ECDSA P-256 key details and the
// SHA256-ECDSA signature algorithm.
func TestDecode_PEM_ECDSA(t *testing.T) {
	pemBytes := newTestECDSACert(t)
	got, err := Decode(string(pemBytes))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.PublicKeyAlgorithm != "ECDSA" {
		t.Errorf("PublicKeyAlgorithm = %q", got.PublicKeyAlgorithm)
	}
	if got.PublicKeyDetails != "ECDSA P-256" {
		t.Errorf("PublicKeyDetails = %q; want 'ECDSA P-256'", got.PublicKeyDetails)
	}
	if !strings.Contains(got.SignatureAlgorithm, "ECDSA") {
		t.Errorf("SignatureAlgorithm = %q; want ECDSA flavor", got.SignatureAlgorithm)
	}
}

// TestDecode_PEM_Ed25519 pins Ed25519 key details.
func TestDecode_PEM_Ed25519(t *testing.T) {
	pemBytes := newTestEd25519Cert(t)
	got, err := Decode(string(pemBytes))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.PublicKeyAlgorithm != "Ed25519" {
		t.Errorf("PublicKeyAlgorithm = %q", got.PublicKeyAlgorithm)
	}
	if got.PublicKeyDetails != "Ed25519 256 bits" {
		t.Errorf("PublicKeyDetails = %q", got.PublicKeyDetails)
	}
}

// TestDecode_PEM_Chain pins the chain-length count when
// multiple certs are concatenated.
func TestDecode_PEM_Chain(t *testing.T) {
	first := newTestRSACert(t)
	second := newTestECDSACert(t)
	combined := string(first) + string(second)
	got, err := Decode(combined)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.ChainLength != 2 {
		t.Errorf("ChainLength = %d; want 2", got.ChainLength)
	}
	// First cert in the chain is decoded (the RSA one in our
	// concatenation order).
	if got.PublicKeyAlgorithm != "RSA" {
		t.Errorf("PublicKeyAlgorithm = %q; want 'RSA' (first cert)", got.PublicKeyAlgorithm)
	}
}

// TestDecode_Expired surfaces Expired=true and a negative
// DaysRemaining for a cert past its NotAfter.
func TestDecode_Expired(t *testing.T) {
	pemBytes := newTestExpiredCert(t)
	got, err := Decode(string(pemBytes))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.Expired {
		t.Error("Expired = false; want true")
	}
	if got.DaysRemaining >= 0 {
		t.Errorf("DaysRemaining = %d; want negative", got.DaysRemaining)
	}
}

// TestDecode_BadInput rejects garbage inputs.
func TestDecode_BadInput(t *testing.T) {
	if _, err := Decode(""); err == nil {
		t.Error("empty: want error")
	}
	if _, err := Decode("ZZ"); err == nil {
		t.Error("invalid hex: want error")
	}
	if _, err := Decode("-----BEGIN CERTIFICATE-----\nINVALID\n-----END CERTIFICATE-----"); err == nil {
		t.Error("bogus PEM body: want error")
	}
	if _, err := Decode("-----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY-----"); err == nil {
		t.Error("non-CERTIFICATE PEM block: want error")
	}
}

// TestFormatFingerprint pins the colon-separated format.
func TestFormatFingerprint(t *testing.T) {
	got := formatFingerprint([]byte{0x01, 0xAB, 0xCD, 0xEF})
	if got != "01:AB:CD:EF" {
		t.Errorf("formatFingerprint = %q; want '01:AB:CD:EF'", got)
	}
}

// TestKeyUsageNames spot-checks the bit→name lookup.
func TestKeyUsageNames(t *testing.T) {
	ku := x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	got := keyUsageNames(ku)
	want := []string{"digitalSignature", "keyCertSign", "cRLSign"}
	if len(got) != len(want) {
		t.Fatalf("len = %d; want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("[%d] = %q; want %q", i, got[i], w)
		}
	}
}

// TestExtKeyUsageName spot-checks.
func TestExtKeyUsageName(t *testing.T) {
	cases := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageServerAuth:   "serverAuth",
		x509.ExtKeyUsageClientAuth:   "clientAuth",
		x509.ExtKeyUsageCodeSigning:  "codeSigning",
		x509.ExtKeyUsageOCSPSigning:  "OCSPSigning",
		x509.ExtKeyUsageTimeStamping: "timeStamping",
	}
	for ek, want := range cases {
		if got := extKeyUsageName(ek); got != want {
			t.Errorf("extKeyUsageName(%d) = %q; want %q", ek, got, want)
		}
	}
}

// --- test helpers --------------------------------------------------

func newTestRSACert(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	u, _ := url.Parse("https://example.com/")
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Acme Corp"},
			Country:      []string{"US"},
		},
		Issuer: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"test.example.com", "alt.example.com"},
		IPAddresses:           []net.IP{net.ParseIP("192.0.2.1")},
		EmailAddresses:        []string{"admin@example.com"},
		URIs:                  []*url.URL{u},
		OCSPServer:            []string{"http://ocsp.example.com"},
		IssuingCertificateURL: []string{"http://issuer.example.com/ca.crt"},
		CRLDistributionPoints: []string{"http://crl.example.com/ca.crl"},
		SubjectKeyId:          []byte{0x01, 0x02, 0x03, 0x04, 0x05},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func newTestECDSACert(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(67890),
		Subject:               pkix.Name{CommonName: "ecdsa.example.com"},
		Issuer:                pkix.Name{CommonName: "ecdsa.example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(180 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func newTestEd25519Cert(t *testing.T) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "ed25519.example.com"},
		Issuer:                pkix.Name{CommonName: "ed25519.example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(180 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func newTestExpiredCert(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "expired.example.com"},
		Issuer:                pkix.Name{CommonName: "expired.example.com"},
		NotBefore:             time.Now().Add(-10 * 24 * time.Hour),
		NotAfter:              time.Now().Add(-48 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
