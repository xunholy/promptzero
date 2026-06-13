// jks_decode.go — host-side Java KeyStore forensic-decode Spec, delegating to
// internal/jks.
//
// Wrap-vs-native: native — a bounds-checked binary reader over the documented
// Sun JKS layout plus stdlib crypto/x509 for the certificate identities; no new
// go.mod dep. A looted .jks holds a Java server's TLS / signing keys; this
// answers "whose identity, how many keys, which crack mode?" offline. Offline;
// no network or device.

package tools

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/jks"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(jksDecodeSpec)
}

var jksDecodeSpec = Spec{
	Name: "jks_decode",
	Description: "Triage a **Java KeyStore** (`.jks` / `.keystore`) — classic **enterprise loot**: Java app servers " +
		"(Tomcat, JBoss, custom services) keep their **TLS server keys** and **code-signing keys** in one, " +
		"protected by a store password. This parses the JKS container **offline** and reports the **version**, " +
		"every **entry** (alias, type — private-key vs trusted-cert — and creation time), the **certificate " +
		"identities** (parsed with `crypto/x509`: subject / issuer / expiry / self-signed — **whose** TLS or " +
		"signing identity each key is), and the matching **crack mode (hashcat -m 15500, `keystore2john`)**. The " +
		"store password is a slow SHA-1-keyed digest; recovering it then decrypts the private keys, granting the " +
		"server's own identity.\n\n" +
		"**No confidently-wrong output**: the file is recognised only by its **`0xFEEDFEED` magic** and a known " +
		"version (1 / 2); every field is **bounds-checked** and a structural deviation (truncation, an " +
		"over-long length, a missing 20-byte trailer) is reported as an error, never guessed; a certificate " +
		"that fails to parse is recorded with its error, never asserted valid; and it does **not** crack, " +
		"decrypt, or recover any key or password. A keystore with only trusted certs (no private key) is noted " +
		"as having **no** `-m 15500` target. No network, no device, transmits nothing — Low risk. Pairs with " +
		"`x509_certificate_decode` / `ssh_privkey_decode` / `pem_privkey_decode` (the key-forensics set).\n\n" +
		"Provide the keystore **base64-encoded** (it is binary). Source: docs/catalog/gap-analysis.md (key / " +
		"credential forensics). Wrap-vs-native: native — a bounds-checked reader over the documented Sun JKS " +
		"format + stdlib `crypto/x509`, no new go.mod dep; anchored to a real keytool-generated keystore.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"jks_base64":{"type":"string","description":"The Java KeyStore file, base64-encoded (it is binary)."}
		},
		"required":["jks_base64"]
	}`),
	Required:  []string{"jks_base64"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   jksDecodeHandler,
}

func jksDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	b64 := strings.TrimSpace(str(p, "jks_base64"))
	if b64 == "" {
		return "", fmt.Errorf("jks_decode: 'jks_base64' is required")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("jks_decode: 'jks_base64' is not valid base64: %w", err)
	}
	res, err := jks.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("jks_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
