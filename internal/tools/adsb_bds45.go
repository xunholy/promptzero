// adsb_bds45.go — explicit BDS 4,5 (Meteorological Hazard Report) Comm-B
// decode Spec, delegating to internal/adsb.

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
	Register(adsbBDS45DecodeSpec)
}

var adsbBDS45DecodeSpec = Spec{
	Name: "adsb_bds45_decode",
	Description: "Decode a Mode S Comm-B MB field as BDS 4,5 — the Meteorological Hazard Report (MHR), " +
		"companion to BDS 4,4 (adsb_bds44_decode). Carries discrete in-flight hazard levels — " +
		"turbulence, wind shear, microburst, icing, wake vortex (each NIL/Light/Moderate/Severe) — " +
		"plus static air temperature, static pressure and radio height (height above terrain).\n\n" +
		"As with BDS 4,4, meteorological registers are NOT self-describing, so this is an EXPLICIT " +
		"decode: YOU assert the field is BDS 4,5, and is_bds45 (pyModeS v3's plausibility heuristic — " +
		"status/field consistency, zero reserved tail, temperature in [-80,60] C when present, and NOT " +
		"a BDS 1,7 capability-report look-alike) is reported as a CONFIDENCE signal. is_bds45=false " +
		"means the field is unlikely to be a genuine MHR; treat the decoded values as suspect. Kept out " +
		"of the automatic Comm-B inference so a look-alike frame is never silently mislabelled.\n\n" +
		"Give **mb**: either the 14-hex-digit (7-byte) MB field, or a full 28-hex-digit DF20/DF21 " +
		"Comm-B frame (the MB is extracted). Separators / '0x' prefix tolerated.\n\n" +
		"Anchored to the pyModeS reference: MB 0001FB80000000 decodes to static air temperature " +
		"-4.5 C (all hazards absent).\n\n" +
		"Pure offline transform. Wrap-vs-native: native — the ICAO Doc 9871 BDS 4,5 bit-field table " +
		"(as in pyModeS decoder/bds/bds45.py), stdlib only.",
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
	Handler:   adsbBDS45DecodeHandler,
}

func adsbBDS45DecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "mb")
	cleaned := strings.NewReplacer(":", "", "-", "", "_", "", " ", "").Replace(strings.TrimSpace(raw))
	cleaned = strings.TrimPrefix(strings.ToLower(cleaned), "0x")
	if cleaned == "" {
		return "", fmt.Errorf("adsb_bds45_decode: 'mb' is required")
	}

	var mbHex string
	switch len(cleaned) {
	case 14:
		mbHex = cleaned
	case 28:
		mbHex = cleaned[8:22]
	default:
		return "", fmt.Errorf("adsb_bds45_decode: expected 14 hex digits (MB field) or 28 (full Comm-B frame), got %d", len(cleaned))
	}
	mb, err := hex.DecodeString(mbHex)
	if err != nil {
		return "", fmt.Errorf("adsb_bds45_decode: invalid hex: %w", err)
	}

	b := adsb.DecodeBDS45(mb)
	if b == nil {
		return "", fmt.Errorf("adsb_bds45_decode: MB field too short")
	}
	out, _ := json.MarshalIndent(b, "", "  ")
	return string(out), nil
}
