// bip39_decode.go — host-side BIP-39 mnemonic decoder Spec, delegating to
// internal/bip39.
//
// Wrap-vs-native: native — BIP-39 is a public spec (11-bit word indices over the
// embedded 2048-word list, a SHA-256 checksum, a PBKDF2-HMAC-SHA512 seed), all
// stdlib crypto + the in-tree wpa.PBKDF2; no runtime dep added. Validates a
// captured wallet seed phrase and derives its seed — high-value crypto-forensics
// loot. Offline; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/bip39"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(bip39DecodeSpec)
}

var bip39DecodeSpec = Spec{
	Name: "bip39_decode",
	Description: "Validate and decode a **BIP-39 mnemonic** — the 12/15/18/21/24-word *seed phrase* used by " +
		"virtually every cryptocurrency wallet (Bitcoin, Ethereum, hardware wallets) — into its entropy, " +
		"checksum validity, per-word list indices, and the derived **BIP-39 seed**. A captured seed phrase " +
		"is prime crypto-forensics / IR / pentest loot: it is the root secret from which every wallet key " +
		"descends, so confirming a phrase is a **genuine** mnemonic (vs. a typo / wrong word / wrong order) " +
		"and deriving its seed is a high-value offline step.\n\n" +
		"Returns `entropy_hex`, `entropy_bits` (128-256), `checksum_valid`, the word `indices`, and the " +
		"64-byte `seed_hex` (PBKDF2-HMAC-SHA512(mnemonic, 'mnemonic'+passphrase, 2048), with the optional " +
		"BIP-39 passphrase / 25th word). **No confidently-wrong output**: a phrase whose **checksum does " +
		"not validate** is reported as such (likely a typo) rather than asserted genuine — the seed is " +
		"still derived from the words as given but clearly flagged; a non-wordlist word or an invalid word " +
		"count is rejected. Case- and whitespace-insensitive. **English wordlist only** (the embedded " +
		"official BIP-39 list); other languages are rejected, not guessed. No network, no device, " +
		"transmits nothing — Low risk. Pairs with the credential / wallet loot tooling.\n\n" +
		"Source: docs/catalog/gap-analysis.md (crypto-wallet loot). Wrap-vs-native: native — 11-bit index " +
		"unpacking + SHA-256 checksum + PBKDF2-HMAC-SHA512 over the embedded 2048-word list, stdlib + the " +
		"in-tree wpa.PBKDF2, no runtime dep. Anchored to the official Trezor BIP-39 test vectors.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"mnemonic":{"type":"string","description":"The BIP-39 seed phrase: 12/15/18/21/24 space-separated English words."},
			"passphrase":{"type":"string","description":"Optional BIP-39 passphrase (the '25th word'); case-sensitive. Changes the derived seed, not the checksum."}
		},
		"required":["mnemonic"]
	}`),
	Required:  []string{"mnemonic"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   bip39DecodeHandler,
}

func bip39DecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	mnemonic := strings.TrimSpace(str(p, "mnemonic"))
	if mnemonic == "" {
		return "", fmt.Errorf("bip39_decode: 'mnemonic' is required")
	}
	res, err := bip39.Decode(mnemonic, str(p, "passphrase"))
	if err != nil {
		return "", fmt.Errorf("bip39_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
