// adsb_bds44.go — explicit BDS 4,4 (Meteorological Routine Air Report)
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
	Register(adsbBDS44DecodeSpec)
}

var adsbBDS44DecodeSpec = Spec{
	Name: "adsb_bds44_decode",
	Description: "Decode a Mode S Comm-B MB field as BDS 4,4 — the Meteorological Routine Air Report " +
		"(MRAR) some aircraft transmit, carrying live wind speed/direction, static air temperature, " +
		"static pressure, turbulence and humidity measured aloft. This is the meteorological register " +
		"adsb_mode_s_decode deliberately leaves out of its automatic Comm-B inference.\n\n" +
		"Meteorological registers are NOT self-describing and are heuristic to identify, so this is an " +
		"EXPLICIT decode: YOU assert the field is BDS 4,4 (e.g. you know the feed carries MRAR), and " +
		"the tool reports is_bds44 — pyModeS's plausibility heuristic (status/field consistency, figure " +
		"of merit <= 4, wind <= 250 kt, temperature in [-80,60] C, not an all-zero payload) — as a " +
		"CONFIDENCE signal. is_bds44=false means the field is unlikely to be a genuine MRAR; treat the " +
		"decoded values as suspect rather than a fact. It is kept out of the auto-inference path so a " +
		"look-alike frame is never silently mislabelled as weather.\n\n" +
		"Give **mb**: either the 14-hex-digit (7-byte) MB field, or a full 28-hex-digit DF20/DF21 " +
		"Comm-B frame (the MB is extracted). Separators / '0x' prefix tolerated.\n\n" +
		"Anchored to the pyModeS reference: MB 185BD5CF400000 decodes to figure of merit 1, wind 22 kt " +
		"at 344.53 deg, static air temperature -48.75 C.\n\n" +
		"Pure offline transform. Wrap-vs-native: native — the ICAO Doc 9871 BDS 4,4 bit-field table " +
		"(as in pyModeS decoder/bds/bds44.py), stdlib only.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"mb":{"type":"string","description":"14-hex MB field (7 bytes) or a full 28-hex DF20/DF21 Comm-B frame. Separators / '0x' prefix tolerated."}
		},
		"required":["mb"]
	}`),
	Required:  []string{"mb"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   adsbBDS44DecodeHandler,
}

func adsbBDS44DecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "mb")
	cleaned := strings.NewReplacer(":", "", "-", "", "_", "", " ", "").Replace(strings.TrimSpace(raw))
	cleaned = strings.TrimPrefix(strings.ToLower(cleaned), "0x")
	if cleaned == "" {
		return "", fmt.Errorf("adsb_bds44_decode: 'mb' is required")
	}

	// Accept a bare 14-hex MB field, or a full 28-hex Comm-B frame from
	// which the MB is bytes 5-11 (hex chars 8-22).
	var mbHex string
	switch len(cleaned) {
	case 14:
		mbHex = cleaned
	case 28:
		mbHex = cleaned[8:22]
	default:
		return "", fmt.Errorf("adsb_bds44_decode: expected 14 hex digits (MB field) or 28 (full Comm-B frame), got %d", len(cleaned))
	}
	mb, err := hex.DecodeString(mbHex)
	if err != nil {
		return "", fmt.Errorf("adsb_bds44_decode: invalid hex: %w", err)
	}

	b := adsb.DecodeBDS44(mb)
	if b == nil {
		return "", fmt.Errorf("adsb_bds44_decode: MB field too short")
	}
	out, _ := json.MarshalIndent(b, "", "  ")
	return string(out), nil
}
