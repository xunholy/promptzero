// puttykey.go — host-side PuTTY .ppk private-key triage Spec, delegating to
// internal/puttykey.
//
// Wrap-vs-native: native — the .ppk format is line-based "Key: value" text
// wrapping a base64 SSH-wire public blob; type + fingerprint are a base64-decode
// + a length-prefixed read + a SHA-256. Triages a stolen PuTTY/WinSCP key
// (encrypted? type? fingerprint? comment?) — the Windows counterpart to
// ssh_privkey_decode. Offline; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/puttykey"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(puttyKeyDecodeSpec)
}

var puttyKeyDecodeSpec = Spec{
	Name: "putty_privkey_decode",
	Description: "Triage a PuTTY private key file (the `PuTTY-User-Key-File-N` / `.ppk` format used by " +
		"PuTTY, WinSCP, FileZilla and pscp/plink). A saved .ppk is the Windows counterpart to a stolen " +
		"id_ed25519 — top pentest loot — and answers the same questions as `ssh_privkey_decode`:\n\n" +
		"- **encrypted?** — `encryption` (`none` / `aes256-cbc`) + `encrypted` flag. An encrypted key must " +
		"have its passphrase cracked (putty2john → John the Ripper) before use; an unencrypted key is " +
		"**directly usable**.\n" +
		"- **kdf (v3 encrypted)** — `key_derivation` (Argon2id / Argon2i / Argon2d) + the Argon2 memory / " +
		"passes / parallelism / salt length (the crack cost).\n" +
		"- **key type + SHA256 fingerprint** — the type (ssh-ed25519 / ssh-rsa / ecdsa-…) and the " +
		"`SHA256:…` fingerprint exactly as `ssh-keygen -l` prints it (a .ppk's public block is the same " +
		"SSH-wire blob as an OpenSSH `.pub`) — use it to correlate the stolen key with an " +
		"`authorized_keys` entry / a known target identity.\n" +
		"- **comment** — often `user@host`, a strong identity hint. Unlike an OpenSSH key, a .ppk's " +
		"comment is a **cleartext header**, so it is readable even for an encrypted key.\n\n" +
		"Accepts the full .ppk text. Pure offline parser — a non-PuTTY blob or a missing/undecodable " +
		"public block is rejected. The Private-Lines section (PuTTY's own private layout) and Private-MAC " +
		"are not decoded or verified (MAC verification needs the passphrase-derived key — a wrong verdict " +
		"would be worse than none). No network, no device, transmits nothing, so it is Low risk.\n\n" +
		"Source: docs/catalog/gap-analysis.md (credential-loot triage — pairs with ssh_privkey_decode and " +
		"the hash_crack / putty2john workflow). Wrap-vs-native: native — line parsing + base64 + " +
		"crypto/sha256, stdlib only. Anchored to `ssh-keygen -l`: a .ppk built from a generated ed25519 + " +
		"rsa key reproduces its exact SHA256 fingerprint / type / comment; the header fields follow the " +
		"PuTTY AppendixC format.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"key":{"type":"string","description":"The PuTTY .ppk private key file text (-----BEGIN omitted; starts with PuTTY-User-Key-File-N: …)."}
		},
		"required":["key"]
	}`),
	Required:  []string{"key"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   puttyKeyDecodeHandler,
}

func puttyKeyDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	key := strings.TrimSpace(str(p, "key"))
	if key == "" {
		return "", fmt.Errorf("putty_privkey_decode: 'key' is required")
	}
	res, err := puttykey.Decode(key)
	if err != nil {
		return "", fmt.Errorf("putty_privkey_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
