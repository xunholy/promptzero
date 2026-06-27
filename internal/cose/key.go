// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cose decodes a COSE_Key (RFC 9052 / RFC 8152, with parameters
// from the IANA COSE registries) into human-readable fields: key type,
// signature algorithm, curve, and the public-key coordinates. COSE keys
// are how WebAuthn / FIDO2 credentials, CWT (CBOR Web Tokens), and many
// IoT flows carry public keys, so an operator who has pulled a credential
// public key out of an attestation (e.g. via webauthn_authdata_decode)
// can read what it actually is instead of eyeballing a CBOR map of integer
// labels.
//
// It builds on internal/cbordecode for the CBOR parse and then interprets
// the COSE label/value registries. There is no checksum — this is
// registry-driven field interpretation — so the risk is mis-mapping a
// label, which the tests pin against real-format EC2 / OKP / RSA keys.
package cose

import (
	"fmt"
	"strconv"

	"github.com/xunholy/promptzero/internal/cbordecode"
)

// Key is a decoded COSE_Key. Only the fields relevant to the key type are
// populated; hex fields carry the raw coordinate / modulus bytes.
type Key struct {
	KeyType   string `json:"key_type"` // OKP / EC2 / RSA / Symmetric / unknown(N)
	KeyTypeID int64  `json:"key_type_id"`
	Algorithm string `json:"algorithm,omitempty"` // e.g. ES256, EdDSA, RS256, unknown(N)
	AlgID     *int64 `json:"algorithm_id,omitempty"`
	Curve     string `json:"curve,omitempty"` // EC2/OKP: P-256, Ed25519, ...
	CurveID   *int64 `json:"curve_id,omitempty"`
	KeyIDHex  string `json:"key_id_hex,omitempty"`

	// EC2 / OKP public coordinates.
	XHex string `json:"x_hex,omitempty"`
	YHex string `json:"y_hex,omitempty"` // EC2 only

	// RSA public parameters.
	ModulusHex  string `json:"modulus_hex,omitempty"`
	ExponentHex string `json:"exponent_hex,omitempty"`

	// HasPrivateKey is true when a private component (EC2/OKP d, or RSA d)
	// is present — a captured COSE key that carries the private key is
	// worth flagging.
	HasPrivateKey bool `json:"has_private_key"`
}

// COSE key types (IANA "COSE Key Types"), label 1.
var keyTypeNames = map[int64]string{
	1: "OKP", 2: "EC2", 3: "RSA", 4: "Symmetric", 5: "HSS-LMS", 6: "WalnutDSA",
}

// COSE algorithms (IANA "COSE Algorithms"), label 3. Covers the signature,
// MAC, AEAD, and key-wrap identifiers a decoded COSE_Key, COSE_Sign1 /
// COSE_Mac0 / COSE_Encrypt0 header, or CWT is likely to carry. Identifiers
// outside this set fall back to "unknown(<id>)" — never a wrong name.
var algNames = map[int64]string{
	// Signature.
	-7: "ES256", -35: "ES384", -36: "ES512", -47: "ES256K",
	-8:   "EdDSA",
	-257: "RS256", -258: "RS384", -259: "RS512",
	-37: "PS256", -38: "PS384", -39: "PS512",
	// MAC (HMAC).
	4: "HMAC 256/64", 5: "HMAC 256/256", 6: "HMAC 384/384", 7: "HMAC 512/512",
	// MAC (AES-MAC).
	14: "AES-MAC 128/64", 15: "AES-MAC 256/64", 25: "AES-MAC 128/128", 26: "AES-MAC 256/128",
	// AEAD (AES-GCM).
	1: "A128GCM", 2: "A192GCM", 3: "A256GCM",
	// AEAD (AES-CCM).
	10: "AES-CCM-16-64-128", 11: "AES-CCM-16-64-256", 12: "AES-CCM-64-64-128", 13: "AES-CCM-64-64-256",
	30: "AES-CCM-16-128-128", 31: "AES-CCM-16-128-256", 32: "AES-CCM-64-128-128", 33: "AES-CCM-64-128-256",
	// AEAD (ChaCha20/Poly1305).
	24: "ChaCha20/Poly1305",
	// Content-key distribution (AES key wrap / direct).
	-3: "A128KW", -4: "A192KW", -5: "A256KW", -6: "direct",
}

// COSE elliptic curves (IANA "COSE Elliptic Curves").
var curveNames = map[int64]string{
	1: "P-256", 2: "P-384", 3: "P-521",
	4: "X25519", 5: "X448", 6: "Ed25519", 7: "Ed448",
}

// DecodeKey parses raw CBOR bytes as a COSE_Key. It requires a CBOR map
// keyed by integer labels (the COSE_Key shape); anything else is an error.
func DecodeKey(raw []byte) (*Key, error) {
	v, err := cbordecode.DecodeBytes(raw)
	if err != nil {
		return nil, fmt.Errorf("cose: %w", err)
	}
	if v.MajorType != 5 || v.Map == nil {
		return nil, fmt.Errorf("cose: not a COSE_Key (expected a CBOR map, got %s)", v.MajorName)
	}

	// Index entries by integer label. COSE_Key labels are always integers;
	// a non-integer key means this isn't a COSE_Key.
	labels := make(map[int64]*cbordecode.Value, len(v.Map))
	for _, e := range v.Map {
		lbl, ok := e.Key.AsInt()
		if !ok {
			return nil, fmt.Errorf("cose: non-integer key label in map (not a COSE_Key)")
		}
		labels[lbl] = e.Value
	}

	ktyV, ok := labels[1]
	if !ok {
		return nil, fmt.Errorf("cose: missing required kty (label 1)")
	}
	kty, ok := ktyV.AsInt()
	if !ok {
		return nil, fmt.Errorf("cose: kty (label 1) is not an integer")
	}

	k := &Key{KeyTypeID: kty, KeyType: nameOr(keyTypeNames, kty)}

	if algV, ok := labels[3]; ok {
		if alg, ok := algV.AsInt(); ok {
			a := alg
			k.AlgID = &a
			k.Algorithm = nameOr(algNames, alg)
		}
	}
	if kidV, ok := labels[2]; ok && kidV.MajorType == 2 {
		k.KeyIDHex = kidV.Bytes
	}

	// The negative labels are key-type-specific.
	switch kty {
	case 1, 2: // OKP, EC2
		if crvV, ok := labels[-1]; ok {
			if crv, ok := crvV.AsInt(); ok {
				c := crv
				k.CurveID = &c
				k.Curve = nameOr(curveNames, crv)
			}
		}
		if xV, ok := labels[-2]; ok && xV.MajorType == 2 {
			k.XHex = xV.Bytes
		}
		if kty == 2 { // EC2 also has y
			if yV, ok := labels[-3]; ok && yV.MajorType == 2 {
				k.YHex = yV.Bytes
			}
		}
		k.HasPrivateKey = labels[-4] != nil // d
	case 3: // RSA (RFC 8230): -1 n, -2 e, -3 d
		if nV, ok := labels[-1]; ok && nV.MajorType == 2 {
			k.ModulusHex = nV.Bytes
		}
		if eV, ok := labels[-2]; ok && eV.MajorType == 2 {
			k.ExponentHex = eV.Bytes
		}
		k.HasPrivateKey = labels[-3] != nil // d
	case 4: // Symmetric: -1 k (the secret itself); presence implies a private key
		k.HasPrivateKey = labels[-1] != nil
	}

	return k, nil
}

// AlgorithmName maps a COSE algorithm identifier (the value at COSE header
// label 1, or COSE_Key label 3) to its IANA name, or "unknown(<id>)". The
// registry is shared by COSE keys and COSE message headers (e.g. CWT), so
// it is exported for reuse rather than duplicated.
func AlgorithmName(id int64) string {
	return nameOr(algNames, id)
}

// nameOr returns the registry name for id, or "unknown(<id>)".
func nameOr(table map[int64]string, id int64) string {
	if n, ok := table[id]; ok {
		return n
	}
	return "unknown(" + strconv.FormatInt(id, 10) + ")"
}
