// SPDX-License-Identifier: AGPL-3.0-or-later

package pgppacket_test

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // SHA-1 is the RFC 4880 v4 fingerprint algorithm
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/xunholy/promptzero/internal/pgppacket"
	// x/crypto/openpgp is deprecated and is used here ONLY as an independent
	// reference oracle to cross-check the native walker; the runtime package
	// depends on none of it.
	"golang.org/x/crypto/openpgp"        //nolint:staticcheck // SA1019: reference oracle only
	"golang.org/x/crypto/openpgp/armor"  //nolint:staticcheck // SA1019: reference oracle only
	"golang.org/x/crypto/openpgp/packet" //nolint:staticcheck // SA1019: reference oracle only
)

// sha1FromTest computes the lowercase-hex SHA-1 of b, independently of the
// package under test.
func sha1FromTest(b []byte) string {
	s := sha1.Sum(b) //nolint:gosec
	return hex.EncodeToString(s[:])
}

// makeEntity builds a deterministic-time OpenPGP entity for cross-checking.
func makeEntity(t *testing.T) *openpgp.Entity {
	t.Helper()
	cfg := &packet.Config{RSABits: 1024, Time: func() time.Time { return time.Unix(1700000000, 0) }}
	e, err := openpgp.NewEntity("Alice Example", "test key", "alice@example.com", cfg)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	return e
}

// oracleFingerprints parses a serialized key with the reference x/crypto
// implementation and returns the fingerprint→keyid map it computes — the
// independent ground truth.
func oracleFingerprints(t *testing.T, data []byte) map[string]string {
	t.Helper()
	out := map[string]string{}
	r := packet.NewReader(bytes.NewReader(data))
	for {
		p, err := r.Next()
		if err != nil {
			break
		}
		switch k := p.(type) {
		case *packet.PublicKey:
			out[hex.EncodeToString(k.Fingerprint[:])] = strings.ToUpper(hex.EncodeToString(uint64ToBytes(k.KeyId)))
		case *packet.PrivateKey:
			out[hex.EncodeToString(k.Fingerprint[:])] = strings.ToUpper(hex.EncodeToString(uint64ToBytes(k.KeyId)))
		}
	}
	return out
}

func uint64ToBytes(v uint64) []byte {
	b := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
	return b
}

// TestPublicKeyCrossCheck serializes a public entity and confirms this native
// walker reproduces every fingerprint / key ID the reference implementation
// computes — the strong external anchor.
func TestPublicKeyCrossCheck(t *testing.T) {
	e := makeEntity(t)
	var buf bytes.Buffer
	if err := e.Serialize(&buf); err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	oracle := oracleFingerprints(t, buf.Bytes())

	res, err := pgppacket.Decode(buf.String())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	got := map[string]string{}
	var sawPub, sawSubkey, sawUID, sawSig bool
	for _, p := range res.Packets {
		if p.Fingerprint != "" {
			got[p.Fingerprint] = p.KeyID
		}
		switch p.Tag {
		case 6:
			sawPub = true
		case 14:
			sawSubkey = true
		case 13:
			sawUID = true
			if p.UserID == "" {
				t.Errorf("user ID packet decoded empty")
			}
		case 2:
			sawSig = true
		}
	}
	if !sawPub || !sawSubkey || !sawUID || !sawSig {
		t.Errorf("missing packet types: pub=%v subkey=%v uid=%v sig=%v", sawPub, sawSubkey, sawUID, sawSig)
	}
	if len(oracle) == 0 {
		t.Fatal("oracle produced no fingerprints")
	}
	for fp, kid := range oracle {
		if got[fp] != kid {
			t.Errorf("fingerprint %s: key id = %q; oracle says %q (native parser diverges from x/crypto)", fp, got[fp], kid)
		}
	}

	// Cross-check signature subpackets (creation time + issuer key ID) against
	// the reference implementation's parsed packet.Signature objects.
	wantSigs := oracleSignatures(t, buf.Bytes())
	var gotSigs []string
	for _, p := range res.Packets {
		if p.Tag == 2 {
			if p.SigCreatedUTC == "" || p.IssuerKeyID == "" {
				t.Errorf("signature packet missing subpacket fields: created=%q issuer=%q", p.SigCreatedUTC, p.IssuerKeyID)
			}
			gotSigs = append(gotSigs, p.SigCreatedUTC+"/"+p.IssuerKeyID)
		}
	}
	for _, w := range wantSigs {
		if !contains(gotSigs, w) {
			t.Errorf("signature %q not reproduced by the native parser (got %v)", w, gotSigs)
		}
	}
}

// oracleSignatures returns "created/issuerKeyID" for each signature the
// reference implementation parses — the independent ground truth for the
// subpacket fields.
func oracleSignatures(t *testing.T, data []byte) []string {
	t.Helper()
	var out []string
	r := packet.NewReader(bytes.NewReader(data))
	for {
		p, err := r.Next()
		if err != nil {
			break
		}
		if s, ok := p.(*packet.Signature); ok && s.IssuerKeyId != nil {
			out = append(out, s.CreationTime.UTC().Format("2006-01-02T15:04:05Z07:00")+"/"+
				strings.ToUpper(hex.EncodeToString(uint64ToBytes(*s.IssuerKeyId))))
		}
	}
	return out
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// TestSecretKeyCrossCheck does the same for a serialized PRIVATE entity, proving
// the public-MPI walk that isolates the public portion of a secret-key packet.
func TestSecretKeyCrossCheck(t *testing.T) {
	e := makeEntity(t)
	var buf bytes.Buffer
	if err := e.SerializePrivate(&buf, nil); err != nil {
		t.Fatalf("SerializePrivate: %v", err)
	}
	oracle := oracleFingerprints(t, buf.Bytes())

	res, err := pgppacket.Decode(buf.String())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	got := map[string]string{}
	var sawSecret, sawSecretSub bool
	for _, p := range res.Packets {
		if p.Fingerprint != "" {
			got[p.Fingerprint] = p.KeyID
		}
		switch p.Tag {
		case 5:
			sawSecret = true
		case 7:
			sawSecretSub = true
		}
	}
	if !sawSecret || !sawSecretSub {
		t.Errorf("missing secret packets: secret=%v secret-subkey=%v", sawSecret, sawSecretSub)
	}
	for fp, kid := range oracle {
		if got[fp] != kid {
			t.Errorf("secret-key fingerprint %s: key id = %q; oracle says %q", fp, got[fp], kid)
		}
	}
}

// TestArmored confirms the ASCII-armor path decodes identically to binary.
func TestArmored(t *testing.T) {
	e := makeEntity(t)
	var bin bytes.Buffer
	if err := e.Serialize(&bin); err != nil {
		t.Fatal(err)
	}
	var armored bytes.Buffer
	w, err := armor.Encode(&armored, "PGP PUBLIC KEY BLOCK", nil)
	if err != nil {
		t.Fatalf("armor: %v", err)
	}
	if err := e.Serialize(w); err != nil {
		t.Fatal(err)
	}
	w.Close()

	binRes, err := pgppacket.Decode(bin.String())
	if err != nil {
		t.Fatalf("binary Decode: %v", err)
	}
	armRes, err := pgppacket.Decode(armored.String())
	if err != nil {
		t.Fatalf("armored Decode: %v", err)
	}
	if !armRes.Armored {
		t.Errorf("armored input not flagged Armored")
	}
	if armRes.PacketCount != binRes.PacketCount {
		t.Errorf("armored packet count %d != binary %d", armRes.PacketCount, binRes.PacketCount)
	}
}

// TestNonRSAPublicKeyFingerprint proves the whole-body public-key fingerprint
// path is correct for a non-RSA algorithm (EdDSA, which the RSA-only oracle
// cannot generate) by hand-constructing a v4 public-key packet and computing the
// RFC 4880 §12.2 fingerprint independently.
func TestNonRSAPublicKeyFingerprint(t *testing.T) {
	// v4 public-key body: version(4) ‖ created(4B) ‖ algo(22=EdDSA) ‖ 9 bytes of
	// (stand-in) public material. The fingerprint hashes the WHOLE body.
	body := []byte{0x04, 0x65, 0x53, 0xf1, 0x00, 22, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x03}
	// Wrap as a new-format Public-Key packet (tag 6): 0xC6, length, body.
	pkt := append([]byte{0xc6, byte(len(body))}, body...)

	// Independent fingerprint: SHA-1(0x99 ‖ uint16(len(body)) ‖ body).
	pre := append([]byte{0x99, byte(len(body) >> 8), byte(len(body))}, body...)
	want := sha1FromTest(pre)

	res, err := pgppacket.Decode(string(pkt))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(res.Packets) != 1 || res.Packets[0].Tag != 6 {
		t.Fatalf("packets = %+v", res.Packets)
	}
	p := res.Packets[0]
	if p.Fingerprint != want {
		t.Errorf("fingerprint = %s; want %s", p.Fingerprint, want)
	}
	if p.Algorithm != "EdDSA" {
		t.Errorf("algorithm = %q; want EdDSA", p.Algorithm)
	}
	if !strings.EqualFold(p.KeyID, want[24:]) {
		t.Errorf("key id = %s; want last 8 bytes of fingerprint %s", p.KeyID, want[24:])
	}
}

func TestRejects(t *testing.T) {
	cases := map[string]string{
		"empty":         "",
		"not openpgp":   "hello world this is not a pgp key at all",
		"high bit only": string([]byte{0x00, 0x01, 0x02}),
	}
	for name, in := range cases {
		if _, err := pgppacket.Decode(in); err == nil {
			t.Errorf("%s: Decode = nil error, want error", name)
		}
	}
}
