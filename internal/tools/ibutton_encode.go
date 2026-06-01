// ibutton_encode.go — host-side Dallas 1-Wire ROM ID builder Spec, the
// inverse of ibutton_decode, delegating to internal/ibutton.Encode.
//
// Wrap-vs-native: native — the 1-Wire ROM-ID layout is public (Maxim
// AN001 / AN-27) and the CRC is the same 4-line bit walker the decoder
// uses, so encode and decode are guaranteed consistent. Output is
// round-trip-verified against ibutton_decode and the canonical Maxim
// AN-27 vector (family 0x02, serial 1C B8 01 00 00 00 → CRC 0xA2).

package tools

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/xunholy/promptzero/internal/ibutton"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(ibuttonEncodeSpec)
}

var ibuttonEncodeSpec = Spec{
	Name: "ibutton_encode",
	Description: "Build a complete, well-formed Dallas 1-Wire ROM ID (a.k.a. iButton key) from a family " +
		"code and a 48-bit serial — the offline inverse of ibutton_decode. The Dallas/Maxim CRC-8 byte " +
		"is computed for you, so the result passes a reader's integrity check. This is the host-side " +
		"construction step for cloning a contact key (e.g. an intercom / building-access DS1990A): read " +
		"the target's serial with ibutton_read, rebuild the full ROM here, then burn it to a blank or " +
		"magic iButton with ibutton_write. It writes nothing and touches no hardware — generation only " +
		"— so it is Low risk like the decoder.\n\n" +
		"- **family** — 8-bit family code; default 0x01 (DS1990A / DS2401 / DS2411, the canonical " +
		"unique-ID access key). Accepts a number (1) or a hex string (\"0x01\" / \"01\").\n" +
		"- **serial** — the 48-bit (6-byte / 12-hex-char) serial, in the same byte order ibutton_decode " +
		"prints in serial_hex. ':' / '-' / '_' / whitespace and a leading '0x' are tolerated.\n\n" +
		"Returns the assembled 8-byte ROM (hex) plus the decoded view (family name + CRC, CRCValid " +
		"always true) for confirmation — round-trip-verified against ibutton_decode.\n\n" +
		"Scope: Dallas DS-family ROM IDs (8-byte fixed width). Cyfral / Metakom Russian-intercom-key " +
		"variants use different bit-widths and need dedicated encoders. Companion to ibutton_decode. " +
		"Wrap-vs-native: native — public 1-Wire layout, shared CRC walker, no hardware.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"serial":{"type":"string","description":"48-bit serial (6 bytes / 12 hex chars). ':' / '-' / '_' / whitespace and a leading '0x' tolerated."},
			"family":{"type":["string","integer"],"description":"8-bit family code; default 0x01 (DS1990A). A number (1) or hex string (\"0x01\")."}
		},
		"required":["serial"]
	}`),
	Required:  []string{"serial"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ibuttonEncodeHandler,
}

func ibuttonEncodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	serial := str(p, "serial")
	if strings.TrimSpace(serial) == "" {
		return "", fmt.Errorf("ibutton_encode: 'serial' is required")
	}
	family, err := parseFamilyCode(p["family"])
	if err != nil {
		return "", fmt.Errorf("ibutton_encode: %w", err)
	}
	rom, d, err := ibutton.Encode(family, serial)
	if err != nil {
		return "", fmt.Errorf("ibutton_encode: %w", err)
	}
	out, _ := json.MarshalIndent(struct {
		ROMHex  string          `json:"rom_hex"`
		Decoded *ibutton.Dallas `json:"decoded_back"`
	}{ROMHex: strings.ToUpper(hex.EncodeToString(rom)), Decoded: d}, "", "  ")
	return string(out), nil
}

// parseFamilyCode coerces the optional family parameter (a JSON number,
// a decimal string, or a hex string with/without "0x") into a byte,
// defaulting to 0x01 (DS1990A) when absent.
func parseFamilyCode(v any) (byte, error) {
	switch t := v.(type) {
	case nil:
		return 0x01, nil
	case float64:
		if t < 0 || t > 255 {
			return 0, fmt.Errorf("family code %v out of range 0-255", t)
		}
		return byte(t), nil
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return 0x01, nil
		}
		base := 10
		if strings.HasPrefix(strings.ToLower(s), "0x") {
			s = s[2:]
			base = 16
		}
		n, err := strconv.ParseUint(s, base, 8)
		if err != nil {
			return 0, fmt.Errorf("invalid family code %q: %w", t, err)
		}
		return byte(n), nil
	default:
		return 0, fmt.Errorf("family code must be a number or hex string, got %T", v)
	}
}
