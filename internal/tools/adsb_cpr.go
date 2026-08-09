// adsb_cpr.go — host-side ADS-B CPR global position resolver Spec,
// delegating to internal/adsb for the algorithm.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/adsb"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(adsbCPRDecodeSpec)
}

var adsbCPRDecodeSpec = Spec{
	Name: "adsb_cpr_decode",
	Description: "Resolve an aircraft's WGS-84 latitude/longitude from a paired even + odd ADS-B " +
		"airborne-position frame — the reference-free half of position that adsb_mode_s_decode " +
		"deliberately leaves out (it surfaces the raw 17-bit CPR values and the even/odd flag; this " +
		"pairs them). Compact Position Reporting (CPR) global decode per ICAO Annex 10 / RTCA " +
		"DO-260B: the NL longitude-zone count, the latitude index j, and the longitude index m — no " +
		"prior reference position required.\n\n" +
		"Give **even_frame** (a hex airborne-position frame with CPR format 0) and **odd_frame** (CPR " +
		"format 1) from the SAME aircraft, captured within ~10 s of each other. Optional **recent** " +
		"('even' or 'odd', default 'even') selects which frame's instant to report — the two are " +
		"moments apart, so the fix belongs to the more recent one. Returns latitude, longitude, the " +
		"ICAO address, and the reference frame's barometric altitude when present.\n\n" +
		"No confidently-wrong output: the tool refuses (with a reason) when a frame is not an " +
		"airborne-position message, when the two are not one even + one odd, when they are from " +
		"different aircraft, or when the pair straddles a latitude-zone boundary and cannot be " +
		"resolved — in which case the caller waits for a fresh pair rather than emitting a wrong " +
		"coordinate. Surface-position CPR (TC 5-8) uses a different grid and is out of scope.\n\n" +
		"Pure offline transform — operators paste two hex frames from dump1090 / readsb / any 1090 " +
		"MHz SDR feed. Anchored to the canonical worked example (even 8D40621D58C382D690C8AC2863A7 + " +
		"odd 8D40621D58C386435CC412692AD6 -> 52.2572, 3.91937).\n\n" +
		"Wrap-vs-native: native — the published CPR algorithm in float maths, stdlib only.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"even_frame":{"type":"string","description":"Hex ADS-B airborne-position frame with CPR format 0 (even). Separators / '0x' prefix tolerated."},
			"odd_frame":{"type":"string","description":"Hex ADS-B airborne-position frame with CPR format 1 (odd), same aircraft, within ~10s."},
			"recent":{"type":"string","enum":["even","odd"],"description":"Which frame's instant to report the fix for (default 'even')."}
		},
		"required":["even_frame","odd_frame"]
	}`),
	Required:  []string{"even_frame", "odd_frame"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   adsbCPRDecodeHandler,
}

func adsbCPRDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	even := strings.TrimSpace(str(p, "even_frame"))
	odd := strings.TrimSpace(str(p, "odd_frame"))
	if even == "" || odd == "" {
		return "", fmt.Errorf("adsb_cpr_decode: both 'even_frame' and 'odd_frame' are required")
	}
	recent := strings.ToLower(strings.TrimSpace(str(p, "recent")))
	switch recent {
	case "", "even":
		recent = "even"
	case "odd":
	default:
		return "", fmt.Errorf("adsb_cpr_decode: 'recent' must be 'even' or 'odd', got %q", recent)
	}

	gp, err := adsb.GlobalPositionFromFrames(even, odd, recent == "even")
	if err != nil {
		return "", fmt.Errorf("adsb_cpr_decode: %w", err)
	}
	out, _ := json.MarshalIndent(gp, "", "  ")
	return string(out), nil
}
