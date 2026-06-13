// pkcs12_decode.go — host-side PKCS#12 / PFX forensic-decode Spec, delegating to
// internal/pkcs12.
//
// Wrap-vs-native: native — a bounded encoding/asn1 walk of the documented
// PKCS#12 structure (RFC 7292) plus stdlib crypto/x509 for the certificate
// identities; no new go.mod dep. A looted .p12/.pfx holds a TLS/signing key and
// its cert chain; this answers "whose identity, how is it protected, which crack
// mode, any unshrouded key?" offline. The modern sibling of jks_decode. Offline;
// no network or device.

package tools

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/pkcs12"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(pkcs12DecodeSpec)
}

var pkcs12DecodeSpec = Spec{
	Name: "pkcs12_decode",
	Description: "Triage a **PKCS#12 / PFX** keystore (`.p12` / `.pfx`) — the **modern, ubiquitous** keystore: " +
		"keytool's **default since Java 9**, the format **Windows** exports TLS client/server identities into, " +
		"and the container for **mobile provisioning**. A looted `.p12` holds a private key and its cert chain, " +
		"all under one password. This parses the PFX **offline** and reports the **version**, the **MAC " +
		"parameters** (algorithm / salt / iterations — the integrity digest is the **`pfx2john` crack " +
		"target**), each top-level **safe** (plaintext vs **password-encrypted**, with the PBE algorithm), the " +
		"**certificate identities** found in **plaintext** bags (via `crypto/x509`: subject / issuer / expiry / " +
		"self-signed), and whether any private key is stored **unshrouded** (no per-key encryption — recoverable " +
		"from the container **without** the password, a finding in its own right). The modern sibling of " +
		"`jks_decode`.\n\n" +
		"**No confidently-wrong output**: recognised only as a well-formed PFX (version + a `pkcs7-data` " +
		"authSafe); the ASN.1 is parsed with stdlib `encoding/asn1` (which **errors** rather than panics on " +
		"malformed input); a certificate that fails to parse is recorded with its error, never asserted valid; " +
		"password-encrypted safes are reported as **encrypted**, never guessed; and it does **not** crack, " +
		"decrypt, or recover any key or password. No network, no device, transmits nothing — Low risk. Pairs " +
		"with `jks_decode` / `x509_certificate_decode` / `pem_privkey_decode` (the key-forensics set).\n\n" +
		"Provide the keystore **base64-encoded** (it is binary, DER). Source: docs/catalog/gap-analysis.md " +
		"(key / credential forensics). Wrap-vs-native: native — a bounded `encoding/asn1` walk of RFC 7292 + " +
		"stdlib `crypto/x509`, no new go.mod dep; anchored to real openssl-generated `.p12` files.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"pfx_base64":{"type":"string","description":"The PKCS#12 / PFX file, base64-encoded (it is binary DER)."}
		},
		"required":["pfx_base64"]
	}`),
	Required:  []string{"pfx_base64"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   pkcs12DecodeHandler,
}

func pkcs12DecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	b64 := strings.TrimSpace(str(p, "pfx_base64"))
	if b64 == "" {
		return "", fmt.Errorf("pkcs12_decode: 'pfx_base64' is required")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("pkcs12_decode: 'pfx_base64' is not valid base64: %w", err)
	}
	res, err := pkcs12.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("pkcs12_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
