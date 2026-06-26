// SPDX-License-Identifier: AGPL-3.0-or-later

package cose

import (
	"encoding/hex"
	"testing"
)

func msgHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// TestDecodeMessage_Sign1 — tag 18, protected {1:-7 ES256}, unprotected
// kid, payload, signature.
func TestDecodeMessage_Sign1(t *testing.T) {
	// d2(tag18) 84(arr4) 43a10126(prot {1:-7}) a1044231 31(unprot {4:h'3131'})
	// 42cafe(payload) 44deadbeef(sig)
	m, err := DecodeMessage(msgHex(t, "d28443a10126a10442313142cafe44deadbeef"))
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}
	if m.Type != "COSE_Sign1" || !m.Tagged {
		t.Errorf("type=%q tagged=%v", m.Type, m.Tagged)
	}
	if m.Protected.Algorithm != "ES256" {
		t.Errorf("protected alg = %q, want ES256", m.Protected.Algorithm)
	}
	if m.Unprotected.KeyIDHex != "3131" {
		t.Errorf("kid = %q, want 3131", m.Unprotected.KeyIDHex)
	}
	if m.PayloadHex != "CAFE" || m.SignatureHex != "DEADBEEF" {
		t.Errorf("payload=%q sig=%q", m.PayloadHex, m.SignatureHex)
	}
	if m.PayloadDetached {
		t.Error("payload should not be detached")
	}
}

// TestDecodeMessage_Mac0 — tag 17, empty protected, payload, MAC tag.
func TestDecodeMessage_Mac0(t *testing.T) {
	// d1(tag17) 84 40(empty prot) a0(empty unprot) 42cafe 44feedface
	m, err := DecodeMessage(msgHex(t, "d18440a042cafe44feedface"))
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}
	if m.Type != "COSE_Mac0" {
		t.Errorf("type = %q, want COSE_Mac0", m.Type)
	}
	if m.TagHex != "FEEDFACE" || m.PayloadHex != "CAFE" {
		t.Errorf("tag=%q payload=%q", m.TagHex, m.PayloadHex)
	}
}

// TestDecodeMessage_Encrypt0 — tag 16, protected {1:1 A128GCM}, IV, ciphertext.
func TestDecodeMessage_Encrypt0(t *testing.T) {
	// d0(tag16) 83(arr3) 43a10101(prot {1:1}) a1054c<12-byte IV>(unprot {5:iv}) 45cafebabe00(ct)
	m, err := DecodeMessage(msgHex(t, "d08343a10101a1054c000102030405060708090a0b45cafebabe00"))
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}
	if m.Type != "COSE_Encrypt0" {
		t.Errorf("type = %q, want COSE_Encrypt0", m.Type)
	}
	if m.Protected.Algorithm != "A128GCM" {
		t.Errorf("alg = %q, want A128GCM", m.Protected.Algorithm)
	}
	if m.Unprotected.IVHex != "000102030405060708090A0B" {
		t.Errorf("iv = %q", m.Unprotected.IVHex)
	}
	if m.CiphertextHex != "CAFEBABE00" {
		t.Errorf("ciphertext = %q", m.CiphertextHex)
	}
}

// TestDecodeMessage_Sign_MultiSigner — tag 98, one signature in the array.
func TestDecodeMessage_Sign_MultiSigner(t *testing.T) {
	// d862(tag98) 84 40 a0 42cafe 81(arr1)[ 83 40 a0 44deadbeef ]
	m, err := DecodeMessage(msgHex(t, "d8628440a042cafe818340a044deadbeef"))
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}
	if m.Type != "COSE_Sign" {
		t.Errorf("type = %q, want COSE_Sign", m.Type)
	}
	if m.SignatureCount == nil || *m.SignatureCount != 1 {
		t.Errorf("signature_count = %v, want 1", m.SignatureCount)
	}
}

// TestDecodeMessage_UntaggedSign1Mac0 — a bare 4-element array can't tell
// Sign1 from Mac0; report honestly.
func TestDecodeMessage_UntaggedSign1Mac0(t *testing.T) {
	m, err := DecodeMessage(msgHex(t, "8443a10126a042cafe44deadbeef"))
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}
	if m.Type != "COSE_Sign1/Mac0 (untagged)" {
		t.Errorf("type = %q", m.Type)
	}
	if m.SignatureHex != "DEADBEEF" {
		t.Errorf("final element = %q", m.SignatureHex)
	}
}

// TestDecodeMessage_DetachedPayload — a CBOR-null payload slot is detached.
func TestDecodeMessage_DetachedPayload(t *testing.T) {
	// d2 84 43a10126 a0 f6(null payload) 44deadbeef
	m, err := DecodeMessage(msgHex(t, "d28443a10126a0f644deadbeef"))
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}
	if !m.PayloadDetached || m.PayloadHex != "" {
		t.Errorf("detached=%v payload=%q, want detached", m.PayloadDetached, m.PayloadHex)
	}
}

func TestDecodeMessage_Errors(t *testing.T) {
	cases := map[string]string{
		"not an array":       "01",                         // a uint
		"non-COSE tag":       "d8638440a042cafe44deadbeef", // tag 99
		"untagged 2-element": "82a040",                     // 2-element array
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeMessage(msgHex(t, h)); err == nil {
				t.Errorf("expected error for %s", name)
			}
		})
	}
}
