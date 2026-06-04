// pemkey.go — host-side PEM private-key triage Spec, delegating to
// internal/pemkey.
//
// Wrap-vs-native: native — own code + Go stdlib (crypto/x509 for the standard
// unencrypted key DER; a hand-rolled encoding/asn1 walk for the encrypted-key
// cipher/KDF params stdlib won't read without the passphrase). Triages a stolen
// .pem/.key file (encrypted? algorithm+size? public fingerprint? cipher+KDF?) —
// the openssl-key counterpart to ssh_privkey_decode / putty_privkey_decode.
// Offline; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/pemkey"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(pemKeyDecodeSpec)
}

var pemKeyDecodeSpec = Spec{
	Name: "pem_privkey_decode",
	Description: "Triage a PEM private key file (the openssl-style `-----BEGIN [RSA|EC|ENCRYPTED] PRIVATE KEY-----` " +
		"/ PKCS#1 / SEC1 / PKCS#8 formats). A stolen `.pem` / `.key` — a TLS server key, client-cert key, or " +
		"API key — is top pentest loot; paste it and learn the answers that drive the next step (the " +
		"openssl-key counterpart to `ssh_privkey_decode` / `putty_privkey_decode`):\n\n" +
		"- **encrypted?** — the `encrypted` flag. An encrypted key must have its passphrase cracked " +
		"(`openssl` / pem2john → John the Ripper) before use; an unencrypted key is **directly usable**.\n" +
		"- **algorithm + size** — RSA (+ modulus bits — an RSA-1024 / weak key is flagged), ECDSA (+ curve), " +
		"Ed25519, DSA. For an encrypted key the type/size live in the ciphertext and are reported as " +
		"unavailable, never guessed.\n" +
		"- **public_sha256** (unencrypted) — the SHA-256 of the public SubjectPublicKeyInfo DER, exactly as " +
		"`openssl pkey -pubout -outform DER | sha256sum` prints it — use it to correlate the key with a " +
		"known certificate / TLS endpoint.\n" +
		"- **cipher + KDF** (encrypted) — for a traditional Proc-Type/DEK-Info key the cipher + IV length " +
		"(legacy MD5-based KDF); for a PKCS#8 PBES2 key the cipher + IV, and the KDF — **PBKDF2** (salt " +
		"length + iterations + PRF) or **scrypt** (N / r / p) — i.e. the crack cost.\n\n" +
		"Pure offline parser — a non-PEM blob, or DER that fails to parse, is rejected; an unrecognised " +
		"cipher/KDF/PRF OID is surfaced as its dotted string with `(unrecognized)` rather than guessed; an " +
		"OpenSSH-format key is redirected to `ssh_privkey_decode`. No network, no device, transmits nothing, " +
		"so it is Low risk.\n\n" +
		"Source: docs/catalog/gap-analysis.md (credential-loot triage — pairs with ssh_privkey_decode, " +
		"putty_privkey_decode and the hash_crack / pem2john workflow). Wrap-vs-native: native — own code + " +
		"Go stdlib (crypto/x509 for standard key DER; a hand-rolled encoding/asn1 walk for the encrypted-key " +
		"params), no new go.mod dep. Anchored to openssl: algorithm/curve/bits + public_sha256 reproduce " +
		"`openssl pkey -pubout`, and the encrypted cipher/KDF/salt/iter/N,r,p reproduce `openssl asn1parse`.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"key":{"type":"string","description":"The PEM private key file text (-----BEGIN … PRIVATE KEY-----)."}
		},
		"required":["key"]
	}`),
	Required:  []string{"key"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   pemKeyDecodeHandler,
}

func pemKeyDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	key := strings.TrimSpace(str(p, "key"))
	if key == "" {
		return "", fmt.Errorf("pem_privkey_decode: 'key' is required")
	}
	res, err := pemkey.Decode(key)
	if err != nil {
		return "", fmt.Errorf("pem_privkey_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
