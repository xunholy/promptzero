// SPDX-License-Identifier: AGPL-3.0-or-later

package cwt

import (
	"encoding/hex"
	"fmt"
	"testing"
)

// rfc8392A1Claims is the CWT claims set from RFC 8392 Appendix A.1 (the
// canonical example): iss/sub/aud + exp/nbf/iat + cti. Used as the decoder's
// verification anchor.
const rfc8392A1Claims = "a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77" +
	"037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b71"

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// cborBStr wraps a hex payload as a CBOR byte string (header + bytes).
func cborBStr(t *testing.T, payloadHex string) string {
	t.Helper()
	n := len(payloadHex) / 2
	switch {
	case n <= 23:
		return fmt.Sprintf("%02x", 0x40+n) + payloadHex
	case n <= 255:
		return fmt.Sprintf("58%02x", n) + payloadHex
	default:
		return fmt.Sprintf("59%04x", n) + payloadHex
	}
}

// TestDecode_UnsecuredClaims_RFC8392_A1 decodes the RFC example claims set
// (a bare CBOR map = an unsecured CWT) and checks every standard claim.
func TestDecode_UnsecuredClaims_RFC8392_A1(t *testing.T) {
	c, err := Decode(mustHex(t, rfc8392A1Claims))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if c.COSEType != "unsecured" || c.Claims == nil {
		t.Fatalf("got cose_type=%q claims=%v", c.COSEType, c.Claims)
	}
	cl := c.Claims
	if cl.Issuer != "coap://as.example.com" || cl.Subject != "erikw" || cl.Audience != "coap://light.example.com" {
		t.Errorf("iss/sub/aud = %q/%q/%q", cl.Issuer, cl.Subject, cl.Audience)
	}
	if cl.ExpiresAt == nil || cl.ExpiresAt.Epoch != 1444064944 {
		t.Errorf("exp = %+v, want epoch 1444064944", cl.ExpiresAt)
	}
	if cl.NotBefore == nil || cl.NotBefore.Epoch != 1443944944 || cl.IssuedAt == nil || cl.IssuedAt.Epoch != 1443944944 {
		t.Errorf("nbf/iat = %+v/%+v", cl.NotBefore, cl.IssuedAt)
	}
	if cl.CWTIDHex != "0B71" {
		t.Errorf("cti = %q, want 0B71", cl.CWTIDHex)
	}
}

// TestDecode_COSESign1 wraps the A.1 claims in a tagged COSE_Sign1 with an
// ES256 protected header and checks the envelope + claims are decoded and
// the not-verified note is present.
func TestDecode_COSESign1(t *testing.T) {
	prot := cborBStr(t, "a10126") // protected header {1:-7} (ES256)
	payload := cborBStr(t, rfc8392A1Claims)
	sig := cborBStr(t, "deadbeef") // dummy signature
	// d2 = tag(18); 84 = array(4); a0 = empty unprotected map.
	full := "d2" + "84" + prot + "a0" + payload + sig

	c, err := Decode(mustHex(t, full))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if c.COSEType != "COSE_Sign1" {
		t.Errorf("cose_type = %q, want COSE_Sign1", c.COSEType)
	}
	if c.Algorithm != "ES256" {
		t.Errorf("algorithm = %q, want ES256", c.Algorithm)
	}
	if c.Claims == nil || c.Claims.Issuer != "coap://as.example.com" {
		t.Errorf("claims not decoded from Sign1 payload: %+v", c.Claims)
	}
	if c.Note == "" {
		t.Error("expected a not-verified note")
	}
}

// TestDecode_Encrypt0 reports an encrypted payload without trying to decode
// claims.
func TestDecode_Encrypt0(t *testing.T) {
	prot := cborBStr(t, "a1011801") // {1:1} A128GCM (illustrative)
	ct := cborBStr(t, "cafebabe")
	full := "d0" + "83" + prot + "a0" + ct // d0 = tag(16) Encrypt0; 83 = array(3)

	c, err := Decode(mustHex(t, full))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if c.COSEType != "COSE_Encrypt0" || !c.PayloadEncrypted {
		t.Errorf("got cose_type=%q encrypted=%v", c.COSEType, c.PayloadEncrypted)
	}
	if c.Claims != nil {
		t.Errorf("encrypted payload must not yield claims, got %+v", c.Claims)
	}
}

func TestDecode_Errors(t *testing.T) {
	// A CBOR text string is neither a COSE message array nor a claims map.
	if _, err := Decode(mustHex(t, "6161")); err == nil {
		t.Error("expected error for non-map/array top-level")
	}
}
