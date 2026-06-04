// sshkey.go — host-side OpenSSH private-key triage Spec, delegating to
// internal/sshkey.
//
// Wrap-vs-native: native — the openssh-key-v1 format is base64 + an SSH-wire
// length-prefixed walk + SHA-256. Triages stolen private-key loot (encrypted?
// type? fingerprint? comment?) from the public portion. Offline; no network or
// device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/sshkey"
)

func init() { //nolint:gochecknoinits
	Register(sshKeyDecodeSpec)
}

var sshKeyDecodeSpec = Spec{
	Name: "ssh_privkey_decode",
	Description: "Triage an OpenSSH private key file (the `-----BEGIN OPENSSH PRIVATE KEY-----` / " +
		"openssh-key-v1 format). A stolen private key (id_ed25519 / id_rsa) is top pentest loot — paste it " +
		"and immediately learn the answers that drive the next step:\n\n" +
		"- **encrypted?** — `cipher` + `encrypted` flag. An encrypted key must have its passphrase cracked " +
		"(ssh2john → hashcat `-m 22921`) before use; an unencrypted key is **directly usable**.\n" +
		"- **kdf** — for an encrypted key, the `bcrypt` KDF rounds + salt length (the crack cost).\n" +
		"- **key type + SHA256 fingerprint** — per public key, the type (ssh-ed25519 / ssh-rsa / " +
		"ecdsa-… ) and the `SHA256:…` fingerprint exactly as `ssh-keygen -l` prints it — use it to " +
		"correlate the stolen key with an `authorized_keys` entry / a known target identity.\n" +
		"- **comment** — for an unencrypted key, the comment (often `user@host`), a strong identity hint. " +
		"For an encrypted key the comment lives in the encrypted section and is reported as unavailable, " +
		"never guessed.\n\n" +
		"All of the above (except the comment) come from the key's **public** portion, so they are readable " +
		"even when the key is encrypted. Accepts the full PEM or just its base64 body. Pure offline parser " +
		"— a non-openssh-key-v1 blob or a truncated/over-long length field is rejected. No network, no " +
		"device, transmits nothing, so it is Low risk.\n\n" +
		"Source: docs/catalog/gap-analysis.md (credential-loot triage — pairs with the hash_crack / ssh2john " +
		"workflow). Wrap-vs-native: native — base64 + an SSH-wire length-prefixed walk + crypto/sha256; " +
		"x/crypto/ssh refuses to even parse an encrypted key without the passphrase, defeating triage. " +
		"Anchored to `ssh-keygen -l`: a generated ed25519 + rsa key (encrypted and not) reproduce its exact " +
		"SHA256 fingerprint / type / encrypted state / comment.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"key":{"type":"string","description":"The OpenSSH private key — the full PEM (-----BEGIN OPENSSH PRIVATE KEY-----…) or just its base64 body."}
		},
		"required":["key"]
	}`),
	Required:  []string{"key"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   sshKeyDecodeHandler,
}

func sshKeyDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	key := strings.TrimSpace(str(p, "key"))
	if key == "" {
		return "", fmt.Errorf("ssh_privkey_decode: 'key' is required")
	}
	res, err := sshkey.Decode(key)
	if err != nil {
		return "", fmt.Errorf("ssh_privkey_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
