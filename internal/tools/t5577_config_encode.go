// t5577_config_encode.go — host-side T5577 config-word builder Spec, the inverse
// of t5577_config_decode, delegating to internal/t55xx.EncodeHex.
//
// Wrap-vs-native: native — fixed bit-field placement into one 32-bit word,
// stdlib only. Round-trips with t5577_config_decode. Completes the offline
// clone-prep chain: read credential -> generate clone block -> generate the
// T5577 config word that sets the blank up for the right protocol. Offline
// transform, transmits nothing.

package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/t55xx"
)

func init() { //nolint:gochecknoinits
	Register(t5577ConfigEncodeSpec)
}

var t5577ConfigEncodeSpec = Spec{
	Name: "t5577_config_encode",
	Description: "Build a **T5577 / ATA5577 configuration word** (block 0) from its raw field values — the " +
		"inverse of `t5577_config_decode`. The T5577 is the ubiquitous rewritable LF 125 kHz blank used to clone " +
		"EM4100 / HID Prox / Indala / AWID / ioProx / Jablotron / Viking / Noralsy / Presco credentials; the " +
		"config word in block 0 tells the tag how to **modulate and clock** its data, so writing the right config " +
		"word is the setup step before writing the cloned data blocks. This completes the offline clone-prep " +
		"chain (read credential → generate the clone block via the *_encode tools → generate this config word).\n\n" +
		"Inputs (raw field values, basic mode): **modulation_raw** (0-31: e.g. 8=ASK/Manchester, 7=FSK2a, " +
		"1=PSK1, 0x18=Biphase-a/CDP), **data_bit_rate_raw** (0-7: RF/8,16,32,40,50,64,100,128), **max_block** " +
		"(0-7), and optional **master_key** (0-15), **psk_clock** (0-3, PSK modulations only), " +
		"**answer_on_request**, **password_enabled**, **sequence_terminator**.\n\n" +
		"No confidently-wrong output: the bit layout is the same Proxmark3-verified one `t5577_config_decode` " +
		"uses, and the encoder **round-trips** with it (decoding the emitted word reproduces the fields) and " +
		"reproduces the two reference configs (EM4100 → 00148040, HID Prox → 00107060). The PSK clock bits are " +
		"only written for the PSK modulations (1-3), matching the decoder. Out-of-range fields are rejected. " +
		"Generation only — transmits nothing and writes to no device, so it is Low risk.\n\n" +
		"Source: docs/catalog/gap-analysis.md (the inverse of t5577_config_decode; completes the offline " +
		"clone-prep chain). Wrap-vs-native: native — fixed bit-field placement, stdlib only, no new go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"modulation_raw":{"type":"integer","description":"5-bit modulation code (0-31): 8=ASK/Manchester, 7=FSK2a, 5=FSK2, 1=PSK1, 0x18=Biphase-a."},
			"data_bit_rate_raw":{"type":"integer","description":"3-bit data bit rate (0-7): RF/8,16,32,40,50,64,100,128."},
			"max_block":{"type":"integer","description":"Number of data blocks (0-7)."},
			"master_key":{"type":"integer","description":"4-bit master key (0-15; default 0)."},
			"psk_clock":{"type":"integer","description":"2-bit PSK clock (0-3, only meaningful for PSK modulations 1-3)."},
			"answer_on_request":{"type":"boolean","description":"Answer-On-Request (AOR) flag."},
			"password_enabled":{"type":"boolean","description":"Password (PWD) flag."},
			"sequence_terminator":{"type":"boolean","description":"Sequence Terminator (ST) flag."}
		},
		"required":["modulation_raw","data_bit_rate_raw","max_block"]
	}`),
	Required:  []string{"modulation_raw", "data_bit_rate_raw", "max_block"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   t5577ConfigEncodeHandler,
}

func t5577ConfigEncodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	mod, err := intField(p, "modulation_raw", 0, 31)
	if err != nil {
		return "", fmt.Errorf("t5577_config_encode: %w", err)
	}
	rate, err := intField(p, "data_bit_rate_raw", 0, 7)
	if err != nil {
		return "", fmt.Errorf("t5577_config_encode: %w", err)
	}
	maxBlock, err := intField(p, "max_block", 0, 7)
	if err != nil {
		return "", fmt.Errorf("t5577_config_encode: %w", err)
	}
	params := t55xx.EncodeParams{
		ModulationRaw:      mod,
		DataBitRateRaw:     rate,
		MaxBlock:           maxBlock,
		AnswerOnRequest:    boolField(p, "answer_on_request"),
		PasswordEnabled:    boolField(p, "password_enabled"),
		SequenceTerminator: boolField(p, "sequence_terminator"),
	}
	if v, ok := p["master_key"].(float64); ok {
		params.MasterKey = int(v)
	}
	if v, ok := p["psk_clock"].(float64); ok {
		params.PSKClock = int(v)
	}
	word, err := t55xx.EncodeHex(params)
	if err != nil {
		return "", fmt.Errorf("t5577_config_encode: %w", err)
	}
	out := map[string]any{
		"config_word_hex":   word,
		"modulation_raw":    mod,
		"data_bit_rate_raw": rate,
		"max_block":         maxBlock,
	}
	body, _ := json.MarshalIndent(out, "", "  ")
	return string(body), nil
}

func boolField(p map[string]any, name string) bool {
	v, ok := p[name].(bool)
	return ok && v
}
