package ndp

import "testing"

// SeND option vectors (RFC 3971) are hand-built per the RFC §5 layouts and
// cross-checked against scapy.contrib.send for the Nonce / RSA-Signature /
// CGA framing. (scapy's Timestamp field size is non-conformant — 4 bytes vs
// the RFC's 8 — so the RFC layout is the authority for Type 13.) Each option
// is embedded after a Router Solicitation (type 133, 4-byte reserved body).
const rsPrefix = "85000000" + "00000000" // ICMPv6 RS header + 4-byte reserved

func decodeOpt(t *testing.T, optHex string) Option {
	t.Helper()
	r, err := Decode(rsPrefix + optHex)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.Options) != 1 {
		t.Fatalf("got %d options, want 1", len(r.Options))
	}
	return r.Options[0]
}

func TestSendTimestampOption(t *testing.T) {
	// Type 13 Timestamp: len=2, reserved(6) + timestamp(8).
	o := decodeOpt(t, "0d02"+"000000000000"+"0102030405060708")
	if o.TypeName != "Timestamp" {
		t.Errorf("TypeName = %q, want Timestamp (NOT Nonce — the old bug)", o.TypeName)
	}
	if o.TimestampHex != "0102030405060708" {
		t.Errorf("TimestampHex = %q", o.TimestampHex)
	}
	if o.NonceHex != "" {
		t.Errorf("Timestamp option should not populate NonceHex, got %q", o.NonceHex)
	}
}

func TestSendNonceOption(t *testing.T) {
	// Type 14 Nonce: len=1, nonce(6).
	o := decodeOpt(t, "0e01"+"aabbccddeeff")
	if o.TypeName != "Nonce" {
		t.Errorf("TypeName = %q, want Nonce", o.TypeName)
	}
	if o.NonceHex != "AABBCCDDEEFF" {
		t.Errorf("NonceHex = %q", o.NonceHex)
	}
}

func TestSendRSASignatureOption(t *testing.T) {
	// Type 12 RSA Signature: len=4, reserved(2) + key_hash(16) + sig(12).
	o := decodeOpt(t, "0c04"+"0000"+"000102030405060708090a0b0c0d0e0f"+"111111111111111111111111")
	if o.TypeName != "RSA_Signature" {
		t.Errorf("TypeName = %q", o.TypeName)
	}
	if o.RSAKeyHash != "000102030405060708090A0B0C0D0E0F" {
		t.Errorf("RSAKeyHash = %q", o.RSAKeyHash)
	}
	if o.RSASignatureHex != "111111111111111111111111" {
		t.Errorf("RSASignatureHex = %q", o.RSASignatureHex)
	}
}

func TestSendCGAOption(t *testing.T) {
	// Type 11 CGA: len=5, padLen(1)+reserved(1) + modifier(16) +
	// subnet prefix(8 = 2001:db8::/64) + collision count(1=2) + pubkey(11).
	o := decodeOpt(t, "0b05"+"00"+"00"+"00000000000000000000000000000000"+
		"20010db800000000"+"02"+"aaaaaaaaaaaaaaaaaaaaaa")
	if o.TypeName != "CGA" {
		t.Errorf("TypeName = %q", o.TypeName)
	}
	if o.CGAModifier != "00000000000000000000000000000000" {
		t.Errorf("CGAModifier = %q", o.CGAModifier)
	}
	if o.CGASubnetPrefix != "2001:db8::/64" {
		t.Errorf("CGASubnetPrefix = %q, want 2001:db8::/64", o.CGASubnetPrefix)
	}
	if o.CGACollisionCount == nil || *o.CGACollisionCount != 2 {
		t.Errorf("CGACollisionCount = %v, want 2", o.CGACollisionCount)
	}
	if o.CGAPublicKeyHex != "AAAAAAAAAAAAAAAAAAAAAA" {
		t.Errorf("CGAPublicKeyHex = %q", o.CGAPublicKeyHex)
	}
}
