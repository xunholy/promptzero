// eth_keystore_decrypt.go — host-side Ethereum V3 keystore decryptor Spec,
// delegating to internal/ethkeystore.
//
// Wrap-vs-native: native orchestration — the Web3 Secret Storage scheme is a
// public spec (scrypt / PBKDF2-HMAC-SHA256 KDF + AES-128-CTR + a Keccak-256
// MAC). The KDFs and Keccak come from golang.org/x/crypto (already a project
// dependency); AES/CTR are stdlib; the JSON parse, MAC gate, and field assembly
// are our own. Recovers the private key from a captured wallet file — the ETH
// companion to bip39_decode / base58check_decode. Offline; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ethkeystore"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(ethKeystoreDecryptSpec)
}

var ethKeystoreDecryptSpec = Spec{
	Name: "eth_keystore_decrypt",
	Description: "Decrypt an **Ethereum V3 keystore** — the encrypted JSON wallet file Geth, MyEtherWallet, " +
		"MetaMask, and most Ethereum tooling export — recovering the **32-byte private key** with the " +
		"operator's passphrase. A captured keystore file is prime crypto-forensics / IR / pentest loot: it " +
		"is an offline-crackable wrapper around an Ethereum private key, the ETH counterpart to a BIP-39 " +
		"seed (`bip39_decode`) or a WIF key (`base58check_decode`).\n\n" +
		"Handles the Web3 Secret Storage scheme: **scrypt** or **PBKDF2-HMAC-SHA256** key derivation, " +
		"**AES-128-CTR**, and a **Keccak-256 MAC**. The MAC is the gate — `Keccak-256(derivedKey[16:32] ‖ " +
		"ciphertext)` must equal the stored MAC. **No confidently-wrong output**: when the MAC does not " +
		"validate (wrong passphrase or a corrupt file) the private key is **NOT surfaced** — `mac_valid` is " +
		"false and a note explains why. A hostile scrypt N (128·N·r over 1 GiB) or an out-of-range PBKDF2 " +
		"iteration count is rejected rather than allowed to exhaust the host; an unsupported cipher/KDF or " +
		"malformed JSON is rejected. Address derivation (private key → address) needs secp256k1 (not a " +
		"current dependency) and is deferred — the recovered key is the loot; import it into any wallet. " +
		"No network, no device, transmits nothing — Low risk.\n\n" +
		"Source: docs/catalog/gap-analysis.md (crypto-wallet loot — the Ethereum keystore companion to " +
		"bip39_decode / base58check_decode). Wrap-vs-native: native orchestration over x/crypto " +
		"scrypt/Keccak + stdlib AES, no new go.mod dep. Anchored to the canonical Web3 Secret Storage " +
		"PBKDF2 vector (testpassword → 7a28b5ba…7514fe9d).",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"keystore":{"type":"string","description":"The V3 keystore JSON (the contents of the wallet / UTC--… file)."},
			"passphrase":{"type":"string","description":"The passphrase that unlocks the keystore."}
		},
		"required":["keystore","passphrase"]
	}`),
	Required:  []string{"keystore", "passphrase"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ethKeystoreDecryptHandler,
}

func ethKeystoreDecryptHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	ks := strings.TrimSpace(str(p, "keystore"))
	if ks == "" {
		return "", fmt.Errorf("eth_keystore_decrypt: 'keystore' is required")
	}
	res, err := ethkeystore.Decrypt(ks, str(p, "passphrase"))
	if err != nil {
		return "", fmt.Errorf("eth_keystore_decrypt: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
