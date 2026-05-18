// mifare_classic.go — host-side Mifare Classic block / dump
// dissector Spec, delegating to the internal/mifare package for
// the parser proper.
//
// Wrap-vs-native judgement: Mifare Classic's block layouts are
// public (NXP AN10833 for sector trailer + access conditions,
// AN10834 for value blocks, AN10927 for UID formats, ISO/IEC
// 14443-3 for ATQA / SAK). The decoder is bit-twiddling over
// 16-byte blocks. Wrapping a FAP for this would add an SD-card
// install step + a firmware-fork dependency for a pure parser.
// Native delivers offline analysis (operators can paste a Flipper
// / Proxmark dump and decode it without the card present),
// unit-testable round-trips, and an output shape that's easy to
// post-process or chain into a workflow.
//
// Pairs with internal/crypto1 (mfoc / mfcuk / mfkey32) — those
// recover keys; this one decodes the data once you have it.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/mifare"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(mifareClassicDecodeBlockSpec)
	Register(mifareClassicDecodeDumpSpec)
}

var mifareClassicDecodeBlockSpec = Spec{
	Name: "mifare_classic_decode_block",
	Description: "Decode a single 16-byte Mifare Classic block into its structured view. " +
		"Classifies as manufacturer (sector 0 block 0 — NUID + BCC integrity + SAK + ATQA + " +
		"IC manufacturer name lookup), sector trailer (Key A + access bits + GPB + Key B, with " +
		"the per-block read/write/increment/decrement permission expansion per NXP AN10833 Table " +
		"6 / Table 7), value block (signed int32 value + complement integrity check + address " +
		"byte + complement check), or plain data block (raw hex + ASCII preview).\n\n" +
		"Provide the block index when known — that's what selects manufacturer / trailer " +
		"classification. With index < 0 the classifier still works structurally (value vs data); " +
		"it just can't identify the manufacturer block.\n\n" +
		"Pure offline parser — no Flipper required. Pairs with crypto1 / mfoc / mfcuk / mfkey32 " +
		"(those recover keys; this decodes the data once you have it). Accepts ':' '-' '_' / " +
		"whitespace separators in `hex`.\n\n" +
		"Source: docs/catalog/gap-analysis.md (NFC decode space adjacent to rank 23 nfc_mfp_sl1_read " +
		"— the Classic baseline operators see most often).",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded 16-byte block (32 hex chars). ':' / '-' / '_' / whitespace separators tolerated."},
			"index":{"type":"integer","description":"Block index (0-63 for 1K, 0-255 for 4K). Use -1 (default) when no dump context is available — the classifier still recognises value blocks structurally."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   mifareClassicDecodeBlockHandler,
}

var mifareClassicDecodeDumpSpec = Spec{
	Name: "mifare_classic_decode_dump",
	Description: "Decode a full Mifare Classic 1K (1024 bytes / 64 blocks) or 4K (4096 bytes / " +
		"256 blocks) dump into a list of structured blocks. Each block is classified as " +
		"manufacturer / trailer / value / data with the same per-kind decoders as " +
		"mifare_classic_decode_block. Useful for one-shot operator-facing summaries of a fresh " +
		"capture.\n\n" +
		"Pure offline parser — no Flipper required. Rejects inputs whose hex length isn't a " +
		"multiple of 32 chars (16 bytes). Accepts ':' / '-' / '_' / whitespace separators.\n\n" +
		"Source: docs/catalog/gap-analysis.md (NFC decode space).",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded full dump (1K = 2048 hex chars; 4K = 8192 hex chars). ':' / '-' / '_' / whitespace separators tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   mifareClassicDecodeDumpHandler,
}

func mifareClassicDecodeBlockHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := strings.TrimSpace(str(p, "hex"))
	if raw == "" {
		return "", fmt.Errorf("mifare_classic_decode_block: 'hex' is required")
	}
	index := -1
	if v, ok := p["index"]; ok {
		switch x := v.(type) {
		case float64:
			index = int(x)
		case int:
			index = x
		}
	}
	blk, err := mifare.DecodeBlock(raw, index)
	if err != nil {
		return "", fmt.Errorf("mifare_classic_decode_block: %w", err)
	}
	out, _ := json.MarshalIndent(blk, "", "  ")
	return string(out), nil
}

func mifareClassicDecodeDumpHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := strings.TrimSpace(str(p, "hex"))
	if raw == "" {
		return "", fmt.Errorf("mifare_classic_decode_dump: 'hex' is required")
	}
	blocks, err := mifare.DecodeDump(raw)
	if err != nil {
		return "", fmt.Errorf("mifare_classic_decode_dump: %w", err)
	}
	out, _ := json.MarshalIndent(map[string]any{
		"blocks":      blocks,
		"block_count": len(blocks),
	}, "", "  ")
	return string(out), nil
}
