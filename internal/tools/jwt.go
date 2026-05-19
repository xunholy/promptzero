// jwt.go — host-side JSON Web Token dissector Spec,
// delegating to the internal/jwtdecode package for the
// walker proper.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/jwtdecode"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(jwtDecodeSpec)
}

var jwtDecodeSpec = Spec{
	Name: "jwt_decode",
	Description: "Decode a JSON Web Token (JWT) into a structured view — the dominant API " +
		"auth token format in modern web stacks. Used pervasively in OAuth 2.0 / OIDC " +
		"bearer-token flows, REST API authentication, SSO assertion exchange, service-" +
		"to-service token-based auth, and almost every modern identity-provider integration. " +
		"Per RFC 7519 (JWT) + RFC 7515 (JWS Compact Serialization) + RFC 7516 (JWE). " +
		"Decodes:\n\n" +
		"- **Compact Serialization detection**: 3 base64url-encoded segments joined by '.' " +
		"(JWS, the signed form), or 5 segments (JWE, the encrypted form). 'Bearer ' prefix " +
		"from an Authorization header value is auto-stripped.\n" +
		"- **JWS header**: alg (algorithm name + family classification — none / HS* HMAC / " +
		"RS* RSA-PKCS1 / ES* ECDSA / PS* RSA-PSS / EdDSA), typ, cty (content type), kid " +
		"(key ID), x5t (X.509 cert thumbprint), x5t#S256 (SHA-256 thumbprint), x5c (X.509 " +
		"cert chain count), jku (JWK Set URL), jwk (embedded JWK), and crit (critical " +
		"extensions list).\n" +
		"- **JWT payload registered claims** (RFC 7519 §4.1): iss (issuer), sub (subject), " +
		"aud (audience — both single-string and array forms supported), exp (expiration), " +
		"nbf (not-before), iat (issued-at), jti (JWT ID). Timestamp claims surfaced as both " +
		"the raw Unix epoch value and an RFC 3339 string for human inspection.\n" +
		"- **Custom claims** preserved as a free-form map so OIDC claims (email, " +
		"given_name, family_name, picture, etc.) and application-specific claims survive " +
		"to the output.\n" +
		"- **Security flags** for at-a-glance triage:\n" +
		"  - **alg_none** — set when `alg == \"none\"`, a famous JWT vulnerability " +
		"class (CVE-2015-2951 and friends).\n" +
		"  - **signature_missing** — set when the signature segment is empty on a JWS " +
		"(should normally only be the case for alg=none).\n" +
		"  - **expired / not_yet_valid** — computed from exp / nbf against current wall " +
		"clock.\n" +
		"  - **hours_until_expiry / hours_since_expired** — numeric triage values.\n" +
		"- **JWE handling**: 5-segment tokens are labeled as JWE; the plaintext header is " +
		"decoded (alg + enc are the most important), and the four encrypted segments " +
		"(encrypted_key / iv / ciphertext / auth_tag) are surfaced as raw base64url for " +
		"any caller that wants them. Decryption requires the recipient's private key and " +
		"is deliberately out of scope.\n\n" +
		"Pure offline parser — operators paste a token from `curl -H 'Authorization: " +
		"Bearer <token>'`, a browser cookie, an OAuth flow trace, an API debugger, or any " +
		"JWT-in-the-wild capture and inspect every documented field. No key material " +
		"required — this is a decode primitive, not a signature verifier (verification is " +
		"a separate Spec that needs a key store).\n\n" +
		"Out of scope (deferred to future iterations): signature verification (HS256 " +
		"requires the HMAC secret; RS256/ES256/EdDSA require the verifier public key), " +
		"JWE body decryption (needs the recipient private key), JWS JSON Serialization " +
		"(the non-Compact form), audience-vs-expected policy matching (a configurable " +
		"verifier Spec would handle that), key-store integration.\n\n" +
		"Source: docs/catalog/gap-analysis.md (modern web auth decode space — high " +
		"defensive value for SOC blue-team and offensive recon). Wrap-vs-native: native " +
		"— RFC 7519 + 7515 + 7516 are fully public; the wire format is base64url-encoded " +
		"JSON + opaque bytes; the standard library covers base64url and JSON.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"token":{"type":"string","description":"JWT in Compact Serialization form: three base64url segments joined by '.' for JWS or five for JWE. Leading 'Bearer ' prefix from an Authorization header value is tolerated."}
		},
		"required":["token"]
	}`),
	Required:  []string{"token"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   jwtDecodeHandler,
}

func jwtDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "token")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("jwt_decode: 'token' is required")
	}
	res, err := jwtdecode.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("jwt_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
