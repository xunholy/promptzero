// ir_raw_encode.go — host-side IR raw-timing generator Spec, the inverse of
// ir_raw_decode, delegating to internal/ir.EncodeRaw.
//
// Wrap-vs-native: native — per-protocol timing emission (pulse-distance,
// pulse-width, Manchester) from address/command, stdlib only. Round-trips with
// ir_raw_decode. The offline IR signal generator (the device-side ir_build
// writes a .ir file; this emits raw µs timings) — feeds ir_pronto_encode.
// Offline transform, transmits nothing.

package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/xunholy/promptzero/internal/ir"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(irRawEncodeSpec)
}

var irRawEncodeSpec = Spec{
	Name: "ir_raw_encode",
	Description: "Generate the raw infrared timing sequence (space-separated microsecond mark/space durations) " +
		"for a consumer-IR frame — the **inverse of `ir_raw_decode`**, and the offline complement to the " +
		"device-side `ir_build` (which writes a Flipper .ir file). The emitted timings round-trip through " +
		"`ir_raw_decode` to the same protocol + address + command, and can be fed to `ir_pronto_encode` to " +
		"produce a shareable Pronto code.\n\n" +
		"Supports **NEC** (8-bit address + command — both inverse-byte checksums are emitted), **NEC-extended** " +
		"(16-bit address, command inversion only), the **NEC-repeat** code, **Samsung32** " +
		"(address·address·command·~command), **Sony SIRC** (12 / 15 / 20-bit via `bits`, with the 20-bit `ext`), " +
		"**Philips RC5 / RC5X** (14-bit Manchester; a command > 63 emits an RC5X frame, `toggle` selects the " +
		"toggle bit), **Kaseikyo** (Panasonic / Denon / JVC / Sharp / Mitsubishi — 48-bit; `vendor` sets the " +
		"16-bit vendor ID, default Panasonic 0x2002; both the vendor parity and the frame parity are computed), " +
		"and **RCA** (24-bit; 4-bit address + 8-bit command, both inverse-field checksums emitted). " +
		"No confidently-wrong output: each generator is the exact inverse of the corresponding " +
		"`ir_raw_decode` reader (the encode↔decode pair is round-trip- and fuzz-verified — every successful " +
		"encode decodes back to the same protocol/address/command), and out-of-range address/command/bits are " +
		"rejected. No network, no device, transmits nothing (the actual replay is a separate device step), so it " +
		"is Low risk.\n\n" +
		"Inputs: **protocol** (NEC / Samsung32 / SIRC / RC5 / Kaseikyo / RCA), **address**, **command**, and optional " +
		"**bits** (SIRC width 12/15/20), **toggle** (RC5), **ext** (SIRC 20-bit extension), **vendor** (Kaseikyo " +
		"16-bit vendor ID).\n\n" +
		"Source: docs/catalog/gap-analysis.md (the offline inverse of ir_raw_decode). Wrap-vs-native: native — " +
		"per-protocol timing emission, stdlib only, no new go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"protocol":{"type":"string","description":"NEC, NEC-extended, NEC-repeat, Samsung32, SIRC (Sony), RC5, Kaseikyo or RCA."},
			"address":{"type":"integer","description":"Address / device code (range depends on protocol)."},
			"command":{"type":"integer","description":"Command / key code (range depends on protocol)."},
			"bits":{"type":"integer","description":"Sony SIRC frame width: 12 (default), 15 or 20."},
			"toggle":{"type":"integer","description":"RC5 toggle bit (0 or 1)."},
			"ext":{"type":"integer","description":"Sony SIRC 20-bit extension byte."},
			"vendor":{"type":"integer","description":"Kaseikyo 16-bit vendor ID (default Panasonic 0x2002)."}
		},
		"required":["protocol","address","command"]
	}`),
	Required:  []string{"protocol", "address", "command"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   irRawEncodeHandler,
}

func irRawEncodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	protocol := str(p, "protocol")
	if protocol == "" {
		return "", fmt.Errorf("ir_raw_encode: 'protocol' is required")
	}
	addr, err := intField(p, "address", 0, 0xFFFFFF)
	if err != nil {
		return "", fmt.Errorf("ir_raw_encode: %w", err)
	}
	cmd, err := intField(p, "command", 0, 0xFFFFFF)
	if err != nil {
		return "", fmt.Errorf("ir_raw_encode: %w", err)
	}
	opt := ir.EncodeOptions{}
	if v, ok := p["bits"].(float64); ok {
		opt.SIRCBits = int(v)
	}
	if v, ok := p["toggle"].(float64); ok {
		opt.Toggle = int(v)
	}
	if v, ok := p["ext"].(float64); ok {
		opt.Ext = int(v)
	}
	if v, ok := p["vendor"].(float64); ok {
		opt.Vendor = int(v)
	}
	timings, err := ir.EncodeRaw(protocol, addr, cmd, opt)
	if err != nil {
		return "", fmt.Errorf("ir_raw_encode: %w", err)
	}
	out := map[string]any{
		"protocol": protocol,
		"address":  addr,
		"command":  cmd,
		"timings":  timings,
	}
	body, _ := json.MarshalIndent(out, "", "  ")
	return string(body), nil
}
