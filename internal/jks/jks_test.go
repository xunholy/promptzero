package jks

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
)

// testJKSb64 is a real two-entry JKS made with:
//
//	keytool -genkeypair -alias serverkey  -keyalg RSA -keysize 2048 \
//	    -dname "CN=app.example.com,O=Example Corp,C=US" -storetype JKS \
//	    -keystore test.jks -storepass changeit -keypass changeit
//	keytool -genkeypair -alias signingkey -keyalg RSA -keysize 2048 \
//	    -dname "CN=Code Signing,O=Example Corp,C=US" -storetype JKS \
//	    -keystore test.jks -storepass changeit -keypass changeit
//
// keytool -list reports: 2 entries, both PrivateKeyEntry (serverkey, signingkey).
const testJKSb64 = "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"

// trustJKSb64 is a JKS holding a single trusted-cert entry (no private key),
// made by importing the serverkey cert under alias "ca-root". keytool -list
// reports: 1 entry, trustedCertEntry (ca-root).
const trustJKSb64 = "/u3+7QAAAAIAAAABAAAAAgAHY2Etcm9vdAAAAZ6/rC0QAAVYLjUwOQAAAyQwggMgMIICCKADAgECAgkAx8XQNS9REpQwDQYJKoZIhvcNAQELBQAwPjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDEV4YW1wbGUgQ29ycDEYMBYGA1UEAxMPYXBwLmV4YW1wbGUuY29tMB4XDTI2MDYxMzA2MjgwN1oXDTI3MDYxMzA2MjgwN1owPjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDEV4YW1wbGUgQ29ycDEYMBYGA1UEAxMPYXBwLmV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoDfaYVrj8guFWiizYAxiA61rS4E4OYEge4f/+WkImdti2Q9D5mB50NQ1aM9zqT4P7crP3aOjqnzB7wOGTLk9heqjnu4fC5+aQfwjtBchxVj8iSvwZ5BO7cSSJ/KDPa0CNLi65/VJWdh9h/R4yhAI5gaLBqfrAQumlI0whvbaRVPv1eQdymV1o6Ob0PialRLJiA7YQBvgfc/gjaHt+4/fUfr4OvDVK/VlKVeuaj79t3621LWuhi5rA+5BBnq+zrloPUMco20+6viTyxLVZZyhwedibM1psUOWm/9A03OrVJ/3SyQZn2/1X46y6l8X4OhMmqDQIVyN0cD+u2OmZG0PMQIDAQABoyEwHzAdBgNVHQ4EFgQUB+pZvP5lgqVeQ1BTZzmdD/YKDWkwDQYJKoZIhvcNAQELBQADggEBAJjmW9NbIaHTR97TynrHYs5oIOrQ/yjZ+kiY5KC3TnLcXmHRuBk0n4VhI7Trb3NiDMub0V3lhplg1ck93OKvFh6J3Ys8QwWfTguZTiNCBHhHUiPsA3bxCGsEMkdmUMrnc6vAvLSJ/9sfllseoabLDjbfwPWpfWK7LGrySiywiFMbeY83ccrTIki9lOswJtzrda4qP4+dh/Oae2Ftosv8Jg2yVessUHHvI4VZ4i/4/vs+9daQ4RKyxxGDpYw6C5ad23Kk3RJ3cjrRf/yDZTioaCihwpX4tHHGH4jRRNesW7xQ/M97dDf1UHo2jsU5cRI6iDJHmBRu65GIgzCGpK1ODiVGoPK/DMJHTMAFDfomoLigNhUHaw=="

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	return b
}

func TestDecode_RealTwoKeyStore(t *testing.T) {
	r, err := Decode(mustB64(t, testJKSb64))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 2 || r.EntryCount != 2 || r.PrivateKeys != 2 || r.TrustedCerts != 0 {
		t.Fatalf("got v=%d count=%d pk=%d tc=%d", r.Version, r.EntryCount, r.PrivateKeys, r.TrustedCerts)
	}
	if r.HashcatMode != 15500 || r.JohnTool != "keystore2john" {
		t.Errorf("mode=%d tool=%q", r.HashcatMode, r.JohnTool)
	}
	if !strings.Contains(r.Note, "15500") {
		t.Errorf("note missing crack mode: %q", r.Note)
	}
	// Anchored to the keytool oracle: aliases, types, and the dnames set above.
	want := []struct{ alias, subjCN string }{
		{"serverkey", "CN=app.example.com"},
		{"signingkey", "CN=Code Signing"},
	}
	for i, w := range want {
		e := r.Entries[i]
		if e.Alias != w.alias || e.Type != "private-key" {
			t.Errorf("entry %d = (%q,%q), want (%q,private-key)", i, e.Alias, e.Type, w.alias)
		}
		if e.EncryptedKeyBytes <= 0 {
			t.Errorf("entry %d: encrypted_key_bytes=%d", i, e.EncryptedKeyBytes)
		}
		if len(e.CertChain) != 1 {
			t.Fatalf("entry %d: chain len %d, want 1", i, len(e.CertChain))
		}
		c := e.CertChain[0]
		if c.ParseError != "" {
			t.Errorf("entry %d cert parse error: %s", i, c.ParseError)
		}
		if !strings.Contains(c.Subject, w.subjCN) || !c.SelfSigned {
			t.Errorf("entry %d subject=%q self=%v, want contains %q + self-signed", i, c.Subject, c.SelfSigned, w.subjCN)
		}
	}
}

func TestDecode_TrustedCertOnly(t *testing.T) {
	r, err := Decode(mustB64(t, trustJKSb64))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.EntryCount != 1 || r.PrivateKeys != 0 || r.TrustedCerts != 1 {
		t.Fatalf("got count=%d pk=%d tc=%d", r.EntryCount, r.PrivateKeys, r.TrustedCerts)
	}
	e := r.Entries[0]
	if e.Alias != "ca-root" || e.Type != "trusted-cert" || e.EncryptedKeyBytes != 0 {
		t.Errorf("entry = %+v", e)
	}
	if len(e.CertChain) != 1 || !strings.Contains(e.CertChain[0].Subject, "CN=app.example.com") {
		t.Errorf("cert = %+v", e.CertChain)
	}
	if !strings.Contains(r.Note, "only trusted certificates") {
		t.Errorf("trusted-only note should explain there is no private-key target: %q", r.Note)
	}
}

// TestDecode_Version1 exercises the version-1 cert layout (no per-cert type UTF)
// with a hand-built minimal keystore: one trusted-cert entry whose body is not a
// real certificate, so the x509 parse fails gracefully (ParseError set, no
// identity claimed) — the structural decode still succeeds.
func TestDecode_Version1(t *testing.T) {
	var b []byte
	u32 := func(v uint32) { var x [4]byte; binary.BigEndian.PutUint32(x[:], v); b = append(b, x[:]...) }
	utf := func(s string) {
		var x [2]byte
		binary.BigEndian.PutUint16(x[:], uint16(len(s)))
		b = append(b, x[:]...)
		b = append(b, s...)
	}

	u32(magic)
	u32(1) // version 1
	u32(1) // one entry
	u32(tagTrustedCert)
	utf("legacy")
	b = append(b, make([]byte, 8)...) // date (epoch 0)
	// version 1: NO cert-type UTF — straight to length + body.
	u32(4)
	b = append(b, []byte("\xde\xad\xbe\xef")...)
	b = append(b, make([]byte, 20)...) // 20-byte trailer

	r, err := Decode(b)
	if err != nil {
		t.Fatalf("Decode v1: %v", err)
	}
	if r.Version != 1 || r.TrustedCerts != 1 {
		t.Fatalf("got v=%d tc=%d", r.Version, r.TrustedCerts)
	}
	c := r.Entries[0].CertChain[0]
	if c.Type != "X.509" || c.Bytes != 4 || c.ParseError == "" {
		t.Errorf("cert = %+v, want X.509/4 bytes/parse-error", c)
	}
}

func TestDecode_Errors(t *testing.T) {
	good := mustB64(t, trustJKSb64)
	cases := map[string][]byte{
		"empty":         {},
		"bad magic":     {0x00, 0x00, 0x00, 0x00, 0, 0, 0, 2, 0, 0, 0, 0},
		"bad version":   {0xFE, 0xED, 0xFE, 0xED, 0, 0, 0, 9, 0, 0, 0, 0},
		"truncated mid": good[:len(good)-30], // trailer/last cert sheared off
		"no trailer":    good[:len(good)-20], // exactly the 20-byte digest removed
	}
	for name, in := range cases {
		if _, err := Decode(in); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func FuzzDecode(f *testing.F) {
	if seed, err := base64.StdEncoding.DecodeString(trustJKSb64); err == nil {
		f.Add(seed)
	}
	f.Add([]byte{})
	f.Add([]byte{0xFE, 0xED, 0xFE, 0xED, 0, 0, 0, 2, 0, 0, 0, 1})
	f.Fuzz(func(_ *testing.T, in []byte) {
		_, _ = Decode(in)
	})
}
