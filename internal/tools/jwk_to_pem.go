// jwk_to_pem.go — host-side JWK / JWKS → PEM converter Spec, delegating to
// internal/jwtsig.JWKToPEM.
//
// Wrap-vs-native: native — issuers publish signing keys as a JWK Set at
// /.well-known/jwks.json (RFC 7517), but jwt_verify (and most tooling) wants a
// PEM public key. This converts an RSA / EC / Ed25519 JWK or JWKS to PKIX PEM
// so a captured JWKS can be turned straight into key material for jwt_verify.
// Pure offline transform over operator-supplied JSON; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/jwtsig"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(jwkToPEMSpec)
}

var jwkToPEMSpec = Spec{
	Name: "jwk_to_pem",
	Description: "Convert a JSON Web Key (JWK) or JWK Set (JWKS) — the form an issuer publishes at " +
		"/.well-known/jwks.json — into PKIX PEM public keys, the form jwt_verify consumes. Closes the " +
		"capture-JWKS → verify-token workflow: paste the JWKS, get the PEM(s), feed the matching one to " +
		"jwt_verify (which also now accepts a JWK/JWKS directly in public_key).\n\n" +
		"Supports **RSA** (kty=RSA), **ECDSA** (kty=EC, P-256/384/521) and **Ed25519** (kty=OKP) public " +
		"keys; private members are ignored. A JWKS yields one PEM per key, each tagged with its kid / kty / " +
		"alg / use. Field: **jwk** (the JWK or JWKS JSON).\n\n" +
		"Offline transform over operator-supplied JSON — no network, no device, transmits nothing, so it " +
		"is Low risk. Verified in-tree by round-tripping RSA/EC/Ed25519 keys against the Go standard " +
		"library. Wrap-vs-native: native — base64url + crypto/x509 PKIX marshalling, standard-library only.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"jwk":{"type":"string","description":"A single JWK or a JWKS ({\"keys\":[...]}) JSON document."}
		},
		"required":["jwk"]
	}`),
	Required:  []string{"jwk"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   jwkToPEMHandler,
}

func jwkToPEMHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	jwk := str(p, "jwk")
	if strings.TrimSpace(jwk) == "" {
		return "", fmt.Errorf("jwk_to_pem: 'jwk' is required")
	}
	keys, err := jwtsig.JWKToPEM(jwk)
	if err != nil {
		return "", fmt.Errorf("jwk_to_pem: %w", err)
	}
	out, _ := json.MarshalIndent(map[string]any{
		"count": len(keys),
		"keys":  keys,
	}, "", "  ")
	return string(out), nil
}
