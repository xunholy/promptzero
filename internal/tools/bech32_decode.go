// bech32_decode.go — host-side Bech32 / Bech32m decoder Spec, delegating to
// internal/bech32.
//
// Wrap-vs-native: native — Bech32/Bech32m (BIP-173 / BIP-350) is a base-32
// charset + a BCH checksum + a 5↔8-bit regroup, stdlib only. Decodes SegWit
// addresses (bc1…/tb1…) plus Nostr (npub/nsec) and Lightning (lnbc…) artifacts;
// the Bech32 companion to base58check_decode. Offline; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/bech32"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(bech32DecodeSpec)
}

var bech32DecodeSpec = Spec{
	Name: "bech32_decode",
	Description: "Decode a **Bech32 / Bech32m** string (BIP-173 / BIP-350) — the encoding modern Bitcoin uses " +
		"for **SegWit addresses** (`bc1…` / `tb1…`), and which **Nostr** (`npub`/`nsec`/`note`), " +
		"**Lightning** (`lnbc…`), and Cosmos-family chains also use — into its human-readable prefix " +
		"(HRP), data payload, and checksum variant. The Bech32 companion to `base58check_decode`, closing " +
		"out Bitcoin-address coverage for crypto-forensics / IR / pentest loot.\n\n" +
		"Reports the HRP, the **checksum variant** (bech32 vs bech32m) and its validity, and the 5→8-bit " +
		"data payload (hex). For the **SegWit** HRPs (bc/tb/bcrt) it decodes the **witness version** and " +
		"**witness program** and identifies the address type (**P2WPKH** / **P2WSH** / **P2TR/Taproot**), " +
		"enforcing the BIP-173/350 rule that witness v0 uses Bech32 and v1+ uses Bech32m. Nostr and " +
		"Lightning HRPs are labelled (their inner TLV / invoice structure is left to the caller). **No " +
		"confidently-wrong output**: a string whose checksum does not validate, or a SegWit address whose " +
		"variant does not match its witness version, is reported as such rather than asserted valid; " +
		"mixed-case input, a missing `1` separator, or an out-of-charset character is rejected. No network, " +
		"no device, transmits nothing — Low risk.\n\n" +
		"Source: docs/catalog/gap-analysis.md (crypto-wallet loot — the Bech32 companion to " +
		"base58check_decode). Wrap-vs-native: native — base-32 charset + BCH checksum + 5↔8-bit regroup, " +
		"stdlib only, no new go.mod dep. Anchored to the BIP-173/350 vectors (A12UEL5L, A1LQFN3A, and the " +
		"P2WPKH address bc1qw508…→751e76e8…).",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"input":{"type":"string","description":"The Bech32/Bech32m string: a SegWit address (bc1…/tb1…), a Nostr key (npub…/nsec…), a Lightning invoice (lnbc…), or any Bech32-encoded value."}
		},
		"required":["input"]
	}`),
	Required:  []string{"input"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   bech32DecodeHandler,
}

func bech32DecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	in := strings.TrimSpace(str(p, "input"))
	if in == "" {
		return "", fmt.Errorf("bech32_decode: 'input' is required")
	}
	res, err := bech32.Decode(in)
	if err != nil {
		return "", fmt.Errorf("bech32_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
