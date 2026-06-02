// jwt_verify.go — host-side JWT (JWS) HMAC signature verifier Spec, delegating
// to internal/jwtsig. The verification counterpart to jwt_decode.
//
// Wrap-vs-native: native — JWS HMAC verification recomputes HMAC-SHA{256,384,
// 512} over "header.payload" and constant-time-compares to the signature, all
// standard library. It is a web-pentest primitive: test a captured token
// against a weak / guessed secret (or a candidate list), and confirm the
// alg:none vulnerability. Offline compute against operator-supplied secrets;
// no network or device.

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
	Register(jwtVerifySpec)
}

var jwtVerifySpec = Spec{
	Name: "jwt_verify",
	Description: "Verify a JWT (JWS) HMAC signature against a candidate secret — the verification " +
		"counterpart to jwt_decode (which is decode-only). A top web-pentest primitive: confirm a " +
		"captured token is signed with a weak or guessed HS256/HS384/HS512 secret, test a list of " +
		"candidate secrets against it, and confirm the alg:none vulnerability.\n\n" +
		"Provide **token** and either **secret** (one candidate) or **secrets** (a list — the tool reports " +
		"which, if any, validates: the weak-secret test). For an HMAC alg the signature is recomputed and " +
		"constant-time-compared. For alg:none the token is reported as unsigned/vulnerable (no secret can " +
		"verify it). For an asymmetric alg (RS*/ES*/PS*/EdDSA) the tool reports that a public key is " +
		"required, not a shared secret — it is not guessed. A 'Bearer ' prefix is tolerated.\n\n" +
		"Offline compute against operator-supplied secrets — no network, no device, transmits nothing, so " +
		"it is Low risk. Verified in-tree against the canonical jwt.io HS256 token. Wrap-vs-native: " +
		"native — HMAC-SHA* + base64url, standard library only.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"token":{"type":"string","description":"The JWT/JWS compact token (3 dot-separated segments). 'Bearer ' prefix tolerated."},
			"secret":{"type":"string","description":"A single candidate HMAC secret to verify against."},
			"secrets":{"type":"array","items":{"type":"string"},"description":"A list of candidate secrets — the tool reports which (if any) validates."}
		},
		"required":["token"]
	}`),
	Required:  []string{"token"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   jwtVerifyHandler,
}

func jwtVerifyHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	token := strings.TrimSpace(str(p, "token"))
	if token == "" {
		return "", fmt.Errorf("jwt_verify: 'token' is required")
	}

	// Collect candidate secrets from 'secret' and/or 'secrets'.
	var secrets []string
	if s := str(p, "secret"); s != "" {
		secrets = append(secrets, s)
	}
	if raw, ok := p["secrets"].([]any); ok {
		for _, v := range raw {
			if s, ok := v.(string); ok && s != "" {
				secrets = append(secrets, s)
			}
		}
	}

	// With no secret supplied, still classify the token (alg:none / asymmetric).
	if len(secrets) == 0 {
		res, err := jwtsig.Verify(token, "")
		if err != nil {
			return "", fmt.Errorf("jwt_verify: %w", err)
		}
		if res.Family == "HMAC" {
			return "", fmt.Errorf("jwt_verify: token uses %s (HMAC) — supply 'secret' or 'secrets' to verify", res.Algorithm)
		}
		out, _ := json.MarshalIndent(map[string]any{"verified": false, "result": res}, "", "  ")
		return string(out), nil
	}

	// Try each candidate; first match wins.
	var last *jwtsig.Result
	for _, s := range secrets {
		res, err := jwtsig.Verify(token, s)
		if err != nil {
			return "", fmt.Errorf("jwt_verify: %w", err)
		}
		last = res
		if res.Verified {
			out, _ := json.MarshalIndent(map[string]any{
				"verified":         true,
				"algorithm":        res.Algorithm,
				"matched_secret":   s,
				"candidates_tried": len(secrets),
			}, "", "  ")
			return string(out), nil
		}
		if res.Family != "HMAC" {
			// alg:none / asymmetric — secrets are irrelevant; report once.
			out, _ := json.MarshalIndent(map[string]any{"verified": false, "result": res}, "", "  ")
			return string(out), nil
		}
	}
	out, _ := json.MarshalIndent(map[string]any{
		"verified":         false,
		"algorithm":        last.Algorithm,
		"candidates_tried": len(secrets),
		"note":             "no supplied secret validates the signature",
	}, "", "  ")
	return string(out), nil
}
