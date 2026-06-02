// jwt_forge.go — host-side JWT (JWS) forging Spec, delegating to
// internal/jwtsig.Sign. The generation counterpart completing the JWT trio
// (jwt_decode / jwt_verify / jwt_forge).
//
// Wrap-vs-native: native — forging a JWS is base64url(header) +
// base64url(payload) + an HMAC-SHA{256,384,512} signature, standard library
// only. It is an offline web-pentest payload builder for authorized testing —
// re-sign a token with escalated claims, craft an alg:none token, or craft the
// RS->HS algorithm-confusion token (HS256 with the issuer's public-key bytes as
// the secret). Generation only: it emits a token string and transmits nothing,
// the same offline-payload posture as pacs_encode / uds_encode.

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
	Register(jwtForgeSpec)
}

var jwtForgeSpec = Spec{
	Name: "jwt_forge",
	Description: "Forge a JWT (JWS) from operator-supplied claims — the generation counterpart to " +
		"jwt_decode / jwt_verify, for authorized web-pentest. Re-sign a captured token with escalated " +
		"claims (e.g. add {\"admin\":true} or change \"sub\"), craft an alg:none token to test permissive " +
		"servers, or craft the RS->HS algorithm-confusion token (use algorithm HS256 with the issuer's " +
		"RSA public-key bytes as the secret).\n\n" +
		"Fields: **payload** (the claims as a raw JSON string — you control the exact bytes), " +
		"**algorithm** (HS256 default / HS384 / HS512 / none), and **secret** (the HMAC key; ignored for " +
		"none). Output is the compact token plus a verify-back confirmation (the forged token re-verified " +
		"against the same secret — round-trip-checked against jwt_verify). Asymmetric signing " +
		"(RS*/ES*/PS*/EdDSA) needs a private key and is out of scope.\n\n" +
		"Generation only — it emits a token string and performs no network or device interaction (the " +
		"same offline-payload posture as pacs_encode / uds_encode), so it is Low risk; the operator wields " +
		"the result in an authorized engagement. Wrap-vs-native: native — base64url + HMAC-SHA*, standard " +
		"library only.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"payload":{"type":"string","description":"Claims as a raw JSON string, e.g. {\"sub\":\"admin\",\"admin\":true}."},
			"algorithm":{"type":"string","description":"HS256 (default) / HS384 / HS512 / none.","enum":["HS256","HS384","HS512","none"]},
			"secret":{"type":"string","description":"HMAC secret (required for HS*; ignored for none). For alg-confusion, the issuer's public-key bytes."}
		},
		"required":["payload"]
	}`),
	Required:  []string{"payload"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   jwtForgeHandler,
}

func jwtForgeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	payload := strings.TrimSpace(str(p, "payload"))
	if payload == "" {
		return "", fmt.Errorf("jwt_forge: 'payload' (claims JSON) is required")
	}
	alg := strings.TrimSpace(str(p, "algorithm"))
	if alg == "" {
		alg = "HS256"
	}
	secret := str(p, "secret")

	token, err := jwtsig.Sign(payload, alg, secret)
	if err != nil {
		return "", fmt.Errorf("jwt_forge: %w", err)
	}
	back, _ := jwtsig.Verify(token, secret) // round-trip confirmation
	out, _ := json.MarshalIndent(map[string]any{
		"token":       token,
		"algorithm":   alg,
		"verify_back": back,
	}, "", "  ")
	return string(out), nil
}
