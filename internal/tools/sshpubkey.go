// sshpubkey.go — host-side OpenSSH public-key / authorized_keys / known_hosts
// triage Spec, delegating to internal/sshpub.
//
// Wrap-vs-native: native — the public-key wire blob is parsed off the RFC 4253
// length-prefixed format and fingerprinted with stdlib SHA-256 / MD5; the
// hashed known_hosts test is stdlib HMAC-SHA1. The public-key counterpart to
// ssh_privkey_decode. Offline; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/sshpub"
)

func init() { //nolint:gochecknoinits
	Register(sshPubKeyDecodeSpec)
}

var sshPubKeyDecodeSpec = Spec{
	Name: "ssh_pubkey_decode",
	Description: "Triage OpenSSH **public** keys — the **`authorized_keys` / `known_hosts` / `*.pub`** lines an " +
		"operator finds on a host during IR or an audit (the public-key counterpart to `ssh_privkey_decode`). " +
		"Finding an `authorized_keys` file on a compromised box, or a `known_hosts` file that maps a host's " +
		"**lateral-movement reach**, is standard loot — and these lines are **not opaque**. Paste one line or " +
		"a whole file and get, per key: the **type** (ssh-ed25519 / ssh-rsa / ecdsa-… / ssh-dss / sk-… FIDO), " +
		"the **key size**, the **SHA256 and MD5 fingerprints exactly as `ssh-keygen -l` prints them** (to " +
		"correlate a key against a known identity), the **comment**, any `authorized_keys` **options**, and " +
		"any `known_hosts` **marker** / host field.\n\n" +
		"Two forensic levers beyond parsing:\n" +
		"- For an **ssh-rsa** key the **modulus** is surfaced (hex) so the key chains straight into " +
		"`roca_detect` — fingerprint the key, then screen the RSA ones for the Infineon **ROCA** weakness " +
		"(CVE-2017-15361). A sub-2048-bit RSA key is flagged weak.\n" +
		"- For a **hashed `known_hosts` entry** (`|1|salt|hash`) supply a **`hostname`** to test it against " +
		"the **HMAC-SHA1** — deanonymising which host the entry refers to (the `ssh-keygen -F` technique, the " +
		"standard way to read a hashed known_hosts file). A plaintext host list is matched directly " +
		"(comma lists + `*`/`?` globs).\n\n" +
		"**No confidently-wrong output**: a key blob is accepted **only** when its embedded algorithm name " +
		"matches its declared type (the validity gate); a malformed line is surfaced with a note rather than " +
		"aborting the batch; a candidate hostname that does not match is reported as no match, never a guess. " +
		"No network, no device, transmits nothing — Low risk. Pairs with `roca_detect`, `ssh_privkey_decode`, " +
		"and `ssh_handshake_decode`.\n\n" +
		"Source: docs/catalog/gap-analysis.md (credential-loot triage). Wrap-vs-native: native — RFC 4253 " +
		"wire parse + crypto/sha256 + crypto/md5 + crypto/hmac, stdlib only, **no x/crypto/ssh surface and " +
		"no new go.mod dep**. Pinned to `ssh-keygen -l` / `-H` / `-F`: generated ed25519 / rsa / ecdsa / dss " +
		"keys reproduce its exact fingerprints, and the hashed-host vector deanonymises its host.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"keys":{"type":"string","description":"One or more OpenSSH public-key lines (authorized_keys / known_hosts / *.pub), newline-separated. Blank lines and #-comments are skipped."},
			"hostname":{"type":"string","description":"Optional candidate hostname to test against each entry's host field — matches hashed |1|salt|hash known_hosts entries (HMAC-SHA1) and plaintext host lists."}
		},
		"required":["keys"]
	}`),
	Required:  []string{"keys"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   sshPubKeyDecodeHandler,
}

func sshPubKeyDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	keys := strings.TrimSpace(str(p, "keys"))
	if keys == "" {
		return "", fmt.Errorf("ssh_pubkey_decode: 'keys' is required")
	}
	host := strings.TrimSpace(str(p, "hostname"))
	res, err := sshpub.Decode(keys, host)
	if err != nil {
		return "", fmt.Errorf("ssh_pubkey_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
