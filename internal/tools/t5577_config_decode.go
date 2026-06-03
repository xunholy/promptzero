// t5577_config_decode.go — host-side T5577 / ATA5577 configuration-register
// dissector Spec, delegating to internal/t55xx.
//
// Wrap-vs-native: native — fixed bit-field extraction from one 32-bit word, no
// dependency. The bit layout, data-bit-rate table, and modulation table are
// taken from the Proxmark3 reference (T5577_Guide.md + cmdlft55xx.c) and
// verified against two real config words (EM4100 0x00148040 + HID 0x00107060).
// Offline read of an operator-supplied word — no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/t55xx"
)

func init() { //nolint:gochecknoinits
	Register(t5577ConfigDecodeSpec)
}

var t5577ConfigDecodeSpec = Spec{
	Name: "t5577_config_decode",
	Description: "Decode a **T5577 / T55x7 (ATA5577) configuration register** — block 0, the 32-bit word that " +
		"controls how an LF 125 kHz tag modulates and clocks its data. The T5577 is the ubiquitous rewritable " +
		"LF blank used to clone EM4100 / HID Prox / Indala / AWID credentials; decoding its config block tells " +
		"you the modulation scheme, data bit rate, block count, and protection flags a tag is set to — the " +
		"diagnostic complement to the project's T5577 clone/write tooling (rfid_write / " +
		"loader_t5577_multiwriter).\n\n" +
		"Field: **hex** — the 32-bit config word (8 hex digits; an optional `0x` prefix and ':' / '-' / " +
		"whitespace separators are tolerated). Decodes the Master Key nibble, Data Bit Rate (RF/8…RF/128), " +
		"Modulation (Direct / FSK1/2/1a/2a / ASK-Manchester / PSK1/2/3 / Biphase / Biphase-a), PSK Clock " +
		"Frequency (for PSK modulations), Answer-On-Request, Max Block, Password-enabled, and Sequence " +
		"Terminator flags.\n\n" +
		"Offline, deterministic, transmits nothing -> Low risk. No confidently-wrong output: a modulation " +
		"value outside the documented set is surfaced as a numeric code (not a guessed name), and the decode " +
		"assumes basic mode — the rarely-used extended mode (master key 0x6/0x9) is flagged, not " +
		"misinterpreted. Verified against the Proxmark3 reference + EM4100 (0x00148040) and HID (0x00107060) " +
		"config words. Wrap-vs-native: native — fixed bit-field extraction.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"T5577 block-0 config word, 8 hex digits (optional 0x prefix; ':' / '-' / whitespace tolerated)."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   t5577ConfigDecodeHandler,
}

func t5577ConfigDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("t5577_config_decode: 'hex' is required")
	}
	res, err := t55xx.DecodeHex(raw)
	if err != nil {
		return "", fmt.Errorf("t5577_config_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
