// cbor.go — host-side CBOR dissector Spec, delegating to
// the internal/cbordecode package for the walker proper.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/cbordecode"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(cborDecodeSpec)
}

var cborDecodeSpec = Spec{
	Name: "cbor_decode",
	Description: "Decode CBOR (Concise Binary Object Representation) per RFC 8949. CBOR is " +
		"the binary JSON-like format used by COSE (signed/encrypted JWT alternative), " +
		"WebAuthn / CTAP (FIDO2 hardware-token transport), Bluetooth Mesh, CoAP IoT " +
		"payloads, MQTT-SN attribute encoding, and the 'self-describing binary' of choice " +
		"for any IoT / constrained-device flow since ~2014. Decodes:\n\n" +
		"- **8 major types**: 0 unsigned int / 1 negative int / 2 byte string (rendered as " +
		"hex) / 3 text string (UTF-8) / 4 array (recursive) / 5 map (ordered key/value " +
		"pairs preserving duplicate keys + ordering) / 6 tagged value (semantic tag + " +
		"nested value) / 7 simple value or float.\n" +
		"- **Argument encoding**: direct values 0..23 in the low 5 bits of the initial " +
		"byte, plus 1/2/4/8-byte arguments via additional codes 24/25/26/27, plus " +
		"indefinite-length markers (additional 31).\n" +
		"- **Indefinite-length containers**: byte/text-string chunks concatenated until " +
		"0xFF break code; arrays/maps walk children until break.\n" +
		"- **~30-entry well-known tag table** covering RFC 8949 §3.4 standard tags " +
		"(0 RFC 3339 date-time / 1 epoch-time / 2/3 unsigned/negative bignum / 4 decimal " +
		"fraction / 5 bigfloat / 21/22/23 expected base64url/base64/base16 / 24 encoded " +
		"CBOR data / 32 URI / 33 base64url text / 34 base64 text / 35 regex / 36 MIME / " +
		"37 binary UUID / 55799 self-describe magic) + COSE tags (16 Encrypt0 / 17 Mac0 / " +
		"18 Sign1 / 96 Encrypt / 97 Mac / 98 Sign) + WebAuthn / CTAP tag 24.\n" +
		"- **Simple values**: 20 false / 21 true / 22 null / 23 undefined + general " +
		"1-byte simple values.\n" +
		"- **IEEE 754 floats**: 16-bit half / 32-bit single / 64-bit double with NaN + " +
		"Inf detection and special-value labeling.\n\n" +
		"Pure offline parser — operators paste a hex blob from a WebAuthn authenticator " +
		"response, a CTAP request, a CoAP body, a COSE token, or any CBOR-emitting IoT " +
		"device and inspect every nested element without needing a CBOR library. Pairs " +
		"with jwt_decode for the auth-token decode stack: JWT/JOSE for cleartext-friendly " +
		"JSON-based tokens, CBOR/COSE for binary IoT-friendly tokens.\n\n" +
		"Out of scope (deferred to future iterations): COSE message body schema (the " +
		"COSE_Sign1/Encrypt0/etc. outer tag + array is decoded, but the inner " +
		"protected-header / unprotected-header / payload / signature fields are not " +
		"annotated as named fields); WebAuthn / CTAP request-body schema knowledge " +
		"(authData / publicKey / clientDataJSON field naming); CDDL (RFC 8610) schema " +
		"validation; strict deterministic-encoding validation.\n\n" +
		"Source: docs/catalog/gap-analysis.md (constrained-IoT decode space; complements " +
		"jwt_decode + tls_handshake_decode for the modern auth-token decode stack). " +
		"Wrap-vs-native: native — RFC 8949 is fully public, the wire format is 8 major " +
		"types with a clean argument-encoding dispatch table.\n\n" +
		"Accepts ':' / '-' / '_' / whitespace separators and a leading '0x' prefix.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded CBOR data item. Trailing bytes after the first complete item are rejected. ':' / '-' / '_' / whitespace separators tolerated; '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   cborDecodeHandler,
}

func cborDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("cbor_decode: 'hex' is required")
	}
	res, err := cbordecode.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("cbor_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
