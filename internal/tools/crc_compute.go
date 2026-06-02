// crc_compute.go — host-side CRC compute / identify Spec, delegating to
// internal/crc.
//
// Wrap-vs-native: native — a CRC is a parameterised bit-walk and the catalogue
// is a table of published (poly, init, refin, refout, xorout, check) models.
// It is a protocol reverse-engineering aid: compute a frame's CRC under the
// standard models, or — the identify mode — find which model reproduces an
// observed CRC over the data, the constant question when bringing up a decoder
// for a new RF/wired protocol. Offline compute, no hardware.

package tools

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/crc"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(crcComputeSpec)
}

var crcComputeSpec = Spec{
	Name: "crc_compute",
	Description: "Compute or identify a CRC against the standard catalogue (CRC-8/16/32 models from the " +
		"reveng catalogue) — a protocol reverse-engineering aid for the constant case where a captured " +
		"RF or wired frame ends in a checksum of an unknown algorithm.\n\n" +
		"**compute** (default): give **data** (hex) and optionally a **model** name (e.g. CRC-16/MODBUS, " +
		"CRC-32/ISO-HDLC); omit the model or pass 'all' to compute every catalogue model. **identify**: " +
		"also give **expected** (the observed CRC as hex) and the tool reports which catalogue model(s) " +
		"reproduce it over the data — reveng's core trick for fingerprinting an unknown frame's CRC. An " +
		"empty identify result is an honest 'no catalogue model matches', never a guess.\n\n" +
		"Models covered: CRC-8/SMBUS, CRC-8/MAXIM-DOW (Dallas 1-Wire), CRC-16/ARC, CRC-16/CCITT-FALSE, " +
		"CRC-16/XMODEM, CRC-16/MODBUS, CRC-16/KERMIT, CRC-24/OPENPGP, CRC-24/BLE (Bluetooth LE PDU), " +
		"CRC-24/FLEXRAY-A, CRC-32/ISO-HDLC (zip/Ethernet/PNG), CRC-32/BZIP2, CRC-32/MPEG-2 — each " +
		"verified in-tree against its published check value (the CRC of " +
		"'123456789'). Offline compute — reads hex, transmits nothing, so it is Low risk. Wrap-vs-native: " +
		"native — parameterised bit-walk over a byte slice.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"data":{"type":"string","description":"Input bytes as hex. Separators tolerated."},
			"model":{"type":"string","description":"CRC model name (e.g. CRC-16/MODBUS), or 'all' / omitted to compute every model. Ignored in identify mode."},
			"expected":{"type":"string","description":"Optional: an observed CRC as hex. When set, switches to identify mode — reports which model(s) produce this CRC over the data."}
		},
		"required":["data"]
	}`),
	Required:  []string{"data"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   crcComputeHandler,
}

func crcComputeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	data, err := decodeLooseHex(str(p, "data"))
	if err != nil {
		return "", fmt.Errorf("crc_compute: data: %w", err)
	}

	// Identify mode: an expected CRC was supplied.
	if exp := strings.TrimSpace(str(p, "expected")); exp != "" {
		ev, err := parseHexUint(exp)
		if err != nil {
			return "", fmt.Errorf("crc_compute: expected: %w", err)
		}
		matches := crc.Identify(data, ev)
		out, _ := json.MarshalIndent(map[string]any{
			"mode":     "identify",
			"expected": exp,
			"matches":  matches,
			"count":    len(matches),
		}, "", "  ")
		return string(out), nil
	}

	// Compute mode.
	model := strings.TrimSpace(str(p, "model"))
	type result struct {
		Model string `json:"model"`
		CRC   string `json:"crc"`
	}
	var results []result
	if model == "" || strings.EqualFold(model, "all") {
		for _, m := range crc.Catalogue {
			results = append(results, result{m.Name, m.Format(m.Compute(data))})
		}
	} else {
		m, ok := crc.Lookup(model)
		if !ok {
			return "", fmt.Errorf("crc_compute: unknown model %q (pass 'all' to list every model's CRC)", model)
		}
		results = append(results, result{m.Name, m.Format(m.Compute(data))})
	}
	out, _ := json.MarshalIndent(map[string]any{
		"mode":    "compute",
		"results": results,
	}, "", "  ")
	return string(out), nil
}

// decodeLooseHex strips common separators and a 0x prefix, then hex-decodes.
func decodeLooseHex(s string) ([]byte, error) {
	clean := strings.NewReplacer(" ", "", ":", "", "-", "", "_", "", "\n", "", "\t", "").Replace(strings.TrimSpace(s))
	clean = strings.TrimPrefix(strings.TrimPrefix(clean, "0x"), "0X")
	if clean == "" {
		return nil, fmt.Errorf("empty input")
	}
	return hex.DecodeString(clean)
}

// parseHexUint parses a hex CRC value (with or without 0x) into a uint32.
func parseHexUint(s string) (uint32, error) {
	clean := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(s), "0x"), "0X")
	clean = strings.NewReplacer(" ", "", ":", "", "-", "").Replace(clean)
	if clean == "" {
		return 0, fmt.Errorf("empty value")
	}
	var v uint64
	for _, c := range clean {
		var d uint64
		switch {
		case c >= '0' && c <= '9':
			d = uint64(c - '0')
		case c >= 'a' && c <= 'f':
			d = uint64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = uint64(c-'A') + 10
		default:
			return 0, fmt.Errorf("%q is not hex", s)
		}
		v = v<<4 | d
		if v > 0xFFFFFFFF {
			return 0, fmt.Errorf("value %q exceeds 32 bits", s)
		}
	}
	return uint32(v), nil
}
