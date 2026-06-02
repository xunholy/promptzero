// SPDX-License-Identifier: AGPL-3.0-or-later

package jwtsig

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"strings"
)

// hmacHashFor maps a JWS HMAC algorithm to its hash constructor. It returns
// (nil, nil) for alg:none (no signature) and an error for an unsupported /
// asymmetric algorithm (those need a private key, not a shared secret).
func hmacHashFor(alg string) (func() hash.Hash, error) {
	switch alg {
	case "HS256":
		return sha256.New, nil
	case "HS384":
		return sha512.New384, nil
	case "HS512":
		return sha512.New, nil
	case "NONE", "":
		return nil, nil
	default:
		return nil, fmt.Errorf("jwtsig: signing algorithm %q is unsupported (HS256/HS384/HS512/none; asymmetric signing needs a private key)", alg)
	}
}

// Sign builds a compact JWS (JWT) from a raw payload-claims JSON string, an
// algorithm, and an HMAC secret — the inverse of Verify. It is an offline
// token-forging primitive for authorized web-pentest: re-sign a token with
// escalated claims (e.g. {"admin":true}), craft an alg:none token, or craft the
// RS->HS algorithm-confusion token (pass HS256 with the issuer's public key
// bytes as the secret). The payload is taken as a raw JSON string so the
// operator controls the exact claim bytes.
//
// Supported algs: HS256 / HS384 / HS512 (HMAC) and none. Asymmetric signing
// (RS*/ES*/PS*/EdDSA) needs a private key and is out of scope here.
func Sign(payloadJSON, alg, secret string) (string, error) {
	if !json.Valid([]byte(payloadJSON)) {
		return "", fmt.Errorf("jwtsig: payload is not valid JSON")
	}
	algU := strings.ToUpper(strings.TrimSpace(alg))
	// Header is marshalled with a fixed field order (alg, typ) for a stable,
	// reproducible encoding.
	hdr := struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}{Alg: strings.TrimSpace(alg), Typ: "JWT"}
	if algU == "NONE" || algU == "" {
		hdr.Alg = "none"
	}
	headerJSON, _ := json.Marshal(hdr)
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))

	h, err := hmacHashFor(algU)
	if err != nil {
		return "", err
	}
	if h == nil { // alg:none
		return signingInput + ".", nil
	}
	mac := hmac.New(h, []byte(secret))
	mac.Write([]byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}
