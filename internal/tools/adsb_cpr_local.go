// adsb_cpr_local.go — host-side ADS-B single-frame CPR position resolver
// (local decode against a reference), delegating to internal/adsb.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"

	"github.com/xunholy/promptzero/internal/adsb"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(adsbCPRLocalSpec)
}

var adsbCPRLocalSpec = Spec{
	Name: "adsb_cpr_local",
	Description: "Resolve an aircraft's WGS-84 latitude/longitude from a SINGLE ADS-B airborne-position " +
		"frame, disambiguated against a nearby reference position — the local CPR decode that a " +
		"receiver uses once it has any reference (its own site location, or a prior global fix from " +
		"adsb_cpr_decode) to get an immediate position from every frame without waiting to pair an " +
		"even + odd. Compact Position Reporting local decode per ICAO Annex 10 / RTCA DO-260B, " +
		"reusing the same NL zone maths as adsb_cpr_decode.\n\n" +
		"Give **frame** (one hex airborne-position frame) plus **ref_lat** / **ref_lon** (a reference " +
		"position). The reference MUST be within ~180 NM (about 3 degrees) of the aircraft: local CPR " +
		"resolves within one grid zone, and a reference farther than half a zone away silently " +
		"selects the wrong zone — the caller owns that guarantee by supplying the reference. Returns " +
		"latitude, longitude, the ICAO address, and the frame's barometric altitude when present.\n\n" +
		"Refuses (with a reason) when the frame is not an airborne-position message or the reference " +
		"is out of range. For a reference-free fix from two frames, use adsb_cpr_decode. Surface-" +
		"position CPR is out of scope.\n\n" +
		"Pure offline transform. Anchored to the canonical example: frame 8D40621D58C382D690C8AC2863A7 " +
		"with reference (52.258, 3.918) -> 52.2572, 3.91937.\n\n" +
		"Wrap-vs-native: native — the published CPR local algorithm in float maths, stdlib only.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"frame":{"type":"string","description":"Hex ADS-B airborne-position frame (either CPR format). Separators / '0x' prefix tolerated."},
			"ref_lat":{"type":"number","description":"Reference latitude in degrees, within ~180 NM of the aircraft."},
			"ref_lon":{"type":"number","description":"Reference longitude in degrees, within ~180 NM of the aircraft."}
		},
		"required":["frame","ref_lat","ref_lon"]
	}`),
	Required:  []string{"frame", "ref_lat", "ref_lon"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   adsbCPRLocalHandler,
}

func adsbCPRLocalHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	frame := strings.TrimSpace(str(p, "frame"))
	if frame == "" {
		return "", fmt.Errorf("adsb_cpr_local: 'frame' is required")
	}
	// ref_lat=0 (equator) and ref_lon=0 (prime meridian) are valid, so a
	// fallback sentinel can't stand in for "absent" — check presence
	// explicitly before coercing.
	if _, ok := p["ref_lat"]; !ok {
		return "", fmt.Errorf("adsb_cpr_local: 'ref_lat' is required")
	}
	if _, ok := p["ref_lon"]; !ok {
		return "", fmt.Errorf("adsb_cpr_local: 'ref_lon' is required")
	}
	refLat := floatOr(p, "ref_lat", math.NaN())
	refLon := floatOr(p, "ref_lon", math.NaN())
	if math.IsNaN(refLat) || math.IsNaN(refLon) {
		return "", fmt.Errorf("adsb_cpr_local: 'ref_lat' and 'ref_lon' must be numbers")
	}

	gp, err := adsb.LocalPositionFromFrame(frame, refLat, refLon)
	if err != nil {
		return "", fmt.Errorf("adsb_cpr_local: %w", err)
	}
	out, _ := json.MarshalIndent(gp, "", "  ")
	return string(out), nil
}
