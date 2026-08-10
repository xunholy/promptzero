// adsb_bds30.go — explicit BDS 3,0 (ACAS Active Resolution Advisory)
// Comm-B decode Spec, delegating to internal/adsb.

package tools

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/adsb"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(adsbBDS30DecodeSpec)
}

var adsbBDS30DecodeSpec = Spec{
	Name: "adsb_bds30_decode",
	Description: "Decode a Mode S Comm-B MB field as BDS 3,0 — the ACAS Active Resolution Advisory. " +
		"When a TCAS/ACAS II unit issues a Resolution Advisory (a collision-avoidance manoeuvre), the " +
		"aircraft reports it in this register: the ARA bits (what manoeuvre the RA commands — " +
		"climb/descend via the downward-sense bit, corrective vs preventive, increased rate, sense " +
		"reversal, altitude crossing, positive), the RAC bits (manoeuvres now prohibited because " +
		"another aircraft claimed them — no above/below/left/right), whether the RA has terminated, " +
		"multiple-threat, and the threat aircraft's identity. Safety-relevant surveillance: proof an " +
		"aircraft was in a collision-avoidance event.\n\n" +
		"Threat identity depends on the threat type indicator (TTI): TTI=1 gives the threat's 24-bit " +
		"ICAO address; TTI=2 gives its altitude (ft), range (NM) and bearing (deg). Per ICAO Annex 10 " +
		"Vol IV.\n\n" +
		"BDS 3,0 is self-identifying (fixed 0x30 first byte), and is_bds30 (pyModeS's heuristic: the " +
		"0x30 id, ACAS-III-reserved bits < 48, non-reserved threat type) is reported as a confidence " +
		"signal. This is an explicit decode (also appears in DF16 long-ACAS frames), kept out of the " +
		"automatic Comm-B inference.\n\n" +
		"Give **mb**: either the 14-hex-digit (7-byte) MB field, or a full 28-hex-digit DF16/DF20/DF21 " +
		"frame (the MB / trailing 7 bytes are extracted). Separators / '0x' prefix tolerated.\n\n" +
		"Pure offline transform. Wrap-vs-native: native — the ICAO Doc 9871 BDS 3,0 bit-field table " +
		"(as in pyModeS decoder/bds/bds30.py), reusing the package AC13 altitude decoder, stdlib only.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"mb":{"type":"string","description":"14-hex MB field (7 bytes) or a full 28-hex Comm-B/ACAS frame. Separators / '0x' prefix tolerated."}
		},
		"required":["mb"]
	}`),
	Required:  []string{"mb"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   adsbBDS30DecodeHandler,
}

func adsbBDS30DecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "mb")
	cleaned := strings.NewReplacer(":", "", "-", "", "_", "", " ", "").Replace(strings.TrimSpace(raw))
	cleaned = strings.TrimPrefix(strings.ToLower(cleaned), "0x")
	if cleaned == "" {
		return "", fmt.Errorf("adsb_bds30_decode: 'mb' is required")
	}

	var mbHex string
	switch len(cleaned) {
	case 14:
		mbHex = cleaned
	case 28:
		mbHex = cleaned[8:22]
	default:
		return "", fmt.Errorf("adsb_bds30_decode: expected 14 hex digits (MB field) or 28 (full Comm-B frame), got %d", len(cleaned))
	}
	mb, err := hex.DecodeString(mbHex)
	if err != nil {
		return "", fmt.Errorf("adsb_bds30_decode: invalid hex: %w", err)
	}

	b := adsb.DecodeBDS30(mb)
	if b == nil {
		return "", fmt.Errorf("adsb_bds30_decode: MB field too short")
	}
	out, _ := json.MarshalIndent(b, "", "  ")
	return string(out), nil
}
