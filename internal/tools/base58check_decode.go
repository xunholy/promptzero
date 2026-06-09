// base58check_decode.go — host-side Base58Check decoder Spec, delegating to
// internal/base58check.
//
// Wrap-vs-native: native — Base58Check is a base-58 integer conversion + a
// 4-byte double-SHA-256 checksum + a version prefix (math/big + crypto/sha256).
// Decodes WIF private keys, legacy Bitcoin addresses, and BIP-32 extended keys
// from captured loot — the companion to bip39_decode. Offline; no network or
// device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/base58check"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(base58checkDecodeSpec)
}

var base58checkDecodeSpec = Spec{
	Name: "base58check_decode",
	Description: "Decode a **Base58Check** string — the encoding Bitcoin (and many forks / chains) use for " +
		"**WIF private keys**, **legacy addresses**, and **BIP-32 extended keys** (xprv/xpub) — into its " +
		"version, payload, and checksum validity, and identify the artifact type. A leaked WIF private " +
		"key, address, or xprv/xpub is common crypto-forensics / IR / pentest loot; decoding one offline " +
		"and confirming its 4-byte double-SHA-256 checksum is the natural companion to `bip39_decode`.\n\n" +
		"Identifies **P2PKH** (0x00 mainnet / 0x6F testnet), **P2SH** (0x05 / 0xC4), and **WIF private " +
		"keys** (0x80 / 0xEF — surfacing the 32-byte private key + the compressed flag), and field-parses " +
		"**BIP-32 extended keys** (xprv/xpub/tprv/tpub: depth, parent fingerprint, child number, chain " +
		"code, key). **No confidently-wrong output**: a string whose checksum does not validate is reported " +
		"as such (likely a typo / truncation) rather than asserted genuine; an unknown version byte is " +
		"surfaced raw; a non-Base58 character or a too-short decode is rejected. Bech32 (segwit `bc1…`) is " +
		"a different encoding and is out of scope here. No network, no device, transmits nothing — Low " +
		"risk.\n\n" +
		"Source: docs/catalog/gap-analysis.md (crypto-wallet loot — the Base58Check companion to " +
		"bip39_decode). Wrap-vs-native: native — base-58 + double-SHA-256 + version prefix, stdlib only, no " +
		"new go.mod dep. Anchored to the canonical WIF (5HueCGU8…→0c28fca3…) and genesis-address " +
		"(1A1zP1eP…→62e907b1…) vectors.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"input":{"type":"string","description":"The Base58Check string: a WIF private key, a legacy address (1…/3…/m…/n…/2…), or a BIP-32 extended key (xprv/xpub/tprv/tpub)."}
		},
		"required":["input"]
	}`),
	Required:  []string{"input"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   base58checkDecodeHandler,
}

func base58checkDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	in := strings.TrimSpace(str(p, "input"))
	if in == "" {
		return "", fmt.Errorf("base58check_decode: 'input' is required")
	}
	res, err := base58check.Decode(in)
	if err != nil {
		return "", fmt.Errorf("base58check_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
