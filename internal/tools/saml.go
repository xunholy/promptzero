// saml.go — host-side SAML message decoder Spec, delegating to internal/saml.
//
// Wrap-vs-native: native — a SAML message value is base64(±DEFLATE(xml)); the
// decode is encoding/base64 + compress/flate + an encoding/xml token scan. The
// SSO counterpart of jwt_decode / paseto_decode for the web-auth decode stack.
// Offline; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/saml"
)

func init() { //nolint:gochecknoinits
	Register(samlDecodeSpec)
}

var samlDecodeSpec = Spec{
	Name: "saml_decode",
	Description: "Decode a SAML 2.0 message — a SAMLRequest / SAMLResponse value captured from an SSO flow — " +
		"into its XML and the high-signal fields a pentester triages. The SSO counterpart of jwt_decode / " +
		"paseto_decode for the web-auth decode stack: paste a SAMLRequest from a redirect URL or a " +
		"SAMLResponse from a POST body and get the readable XML + key fields without a SAML library or a " +
		"manual base64-then-inflate dance.\n\n" +
		"Auto-detects the binding: **HTTP-Redirect** (base64(raw-DEFLATE(xml)), the GET-redirect form) vs " +
		"**HTTP-POST** (base64(xml)). Percent-encoding (when pasted straight from a URL) and base64url are " +
		"tolerated. Surfaces the decoded **xml** (always, as the source of truth) plus the extracted " +
		"**message_type** (AuthnRequest / Response / LogoutRequest…), **issuer**, **destination**, **id** / " +
		"**version** / **issue_instant** / **in_response_to**, **name_id** (the asserted identity), " +
		"**status_code**, the assertion **conditions** (NotBefore / NotOnOrAfter) + **audiences**, and — " +
		"crucially for **golden-SAML / unsigned-assertion** triage — a **signature_count** + " +
		"**signature_present** flag (whether an XML-DSig Signature element is present).\n\n" +
		"Pure offline parser — fields are extracted by a namespace-agnostic local-name scan and the raw XML " +
		"is the source of truth (an absent field is empty, never guessed); a value that is neither " +
		"DEFLATE-compressed XML nor raw XML is rejected; the inflate is size-bounded against a hostile blob. " +
		"No network, no device, transmits nothing, so it is Low risk.\n\n" +
		"Out of scope (deferred): XML-DSig signature **verification** (canonicalization + certificate trust " +
		"is a separate problem) — this reports whether a signature is present (the attack-surface signal), " +
		"not whether it validates; and decryption of EncryptedAssertion (needs the SP key).\n\n" +
		"Source: docs/catalog/gap-analysis.md (web-auth decode stack — pairs with jwt_decode + paseto_decode " +
		"for the SSO/token triage trio; golden-SAML is a top AD-federation attack). Wrap-vs-native: native — " +
		"encoding/base64 + compress/flate + encoding/xml, standard-library only. Anchored to an independent " +
		"DEFLATE redirect-binding vector + a POST-binding signed Response.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"value":{"type":"string","description":"The SAMLRequest / SAMLResponse value (base64, optionally DEFLATE-compressed for the redirect binding; percent-encoding and base64url tolerated)."}
		},
		"required":["value"]
	}`),
	Required:  []string{"value"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   samlDecodeHandler,
}

func samlDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	v := strings.TrimSpace(str(p, "value"))
	if v == "" {
		return "", fmt.Errorf("saml_decode: 'value' is required")
	}
	res, err := saml.Decode(v)
	if err != nil {
		return "", fmt.Errorf("saml_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
