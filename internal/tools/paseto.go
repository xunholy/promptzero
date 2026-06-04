// paseto.go — host-side PASETO token decode + (Ed25519) verify Spec, delegating
// to internal/paseto.
//
// Wrap-vs-native: native — PASETO decode is base64url + a length split;
// Ed25519 verification is crypto/ed25519 over the PASETO Pre-Authentication
// Encoding. The PASETO counterpart of jwt_decode for the web-token decode stack.
// Offline; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/paseto"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(pasetoDecodeSpec)
}

var pasetoDecodeSpec = Spec{
	Name: "paseto_decode",
	Description: "Decode (and optionally Ed25519-verify) a PASETO token — \"Platform-Agnostic Security " +
		"Tokens\", the modern signed/encrypted token format positioned as the safer alternative to JWT (no " +
		"algorithm confusion, versioned crypto). The PASETO counterpart of jwt_decode for the web-token " +
		"decode stack: paste a token captured from an Authorization header / cookie / API body and get its " +
		"structure — and, for the **public** (signed, not encrypted) variants, the **cleartext claims** " +
		"without any key (exactly like jwt_decode reads a JWT body).\n\n" +
		"A token is `version.purpose.payload[.footer]` (base64url). For **public** tokens the payload is the " +
		"cleartext message followed by a signature (v2/v4 Ed25519 = 64 bytes, v3 ECDSA P-384 = 96, v1 RSA-PSS " +
		"= 256), so the claims + signature are surfaced. For **local** (encrypted) tokens only the structure " +
		"is visible — the payload is surfaced as length + hex with a note (decryption needs the symmetric " +
		"key). The footer (often a `kid`) is decoded.\n\n" +
		"Provide **token**. Optionally provide a hex-encoded 32-byte Ed25519 **public_key** (v2/v4 public " +
		"only) to **verify** the signature — the authenticity check, computed over the PASETO " +
		"Pre-Authentication Encoding; an optional **implicit** assertion (v3/v4) is included if given. " +
		"Output is the decoded structure, plus a `verified` true/false when a key is supplied.\n\n" +
		"Offline transform — reads a string, transmits nothing, so it is Low risk. A malformed token (wrong " +
		"part count, bad base64url, payload shorter than the signature) is rejected, never mis-decoded. v1 " +
		"(RSA) / v3 (ECDSA) verification and local decryption are deferred. Verified in-tree against the " +
		"official PASETO v4 test vectors (4-S-1 decodes to its claims + verifies; a tampered token fails). " +
		"Wrap-vs-native: native — base64url + crypto/ed25519, standard-library only.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"token":{"type":"string","description":"The PASETO token (version.purpose.payload[.footer])."},
			"public_key":{"type":"string","description":"Optional hex-encoded 32-byte Ed25519 public key to verify a v2/v4 public token's signature."},
			"implicit":{"type":"string","description":"Optional implicit assertion (v3/v4) to include in verification."}
		},
		"required":["token"]
	}`),
	Required:  []string{"token"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   pasetoDecodeHandler,
}

func pasetoDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	token := strings.TrimSpace(str(p, "token"))
	if token == "" {
		return "", fmt.Errorf("paseto_decode: 'token' is required")
	}
	res, err := paseto.Decode(token)
	if err != nil {
		return "", fmt.Errorf("paseto_decode: %w", err)
	}
	out := map[string]any{"decoded": res}
	if pk := strings.TrimSpace(str(p, "public_key")); pk != "" {
		verified, verr := paseto.Verify(token, pk, str(p, "implicit"))
		if verr != nil {
			out["verify_error"] = verr.Error()
		} else {
			out["verified"] = verified
		}
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	return string(b), nil
}
