// ubx.go — host-side u-blox UBX binary protocol decode Spec,
// delegating to internal/ubx.
//
// Wrap-vs-native: native — UBX framing is a fixed public wire format
// (sync 0xB5 0x62 + class/id + LE length + payload + Fletcher-16
// checksum) and NAV-PVT is a fixed 92-byte struct; byte-field
// extraction, stdlib only. The binary counterpart to
// gps_nmea_decode. Offline; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/ubx"
)

func init() { //nolint:gochecknoinits
	Register(ubxDecodeSpec)
}

var ubxDecodeSpec = Spec{
	Name: "ubx_decode",
	Description: "Decode the u-blox **UBX binary protocol** — the native binary message format u-blox GNSS " +
		"receivers (the NEO-6/7/8/9 family found in countless wardriving / drone / GPS-tracker rigs, " +
		"including modules paired with the Flipper Zero and ESP32 Marauder) speak as the compact " +
		"alternative to NMEA text. The **binary counterpart to `gps_nmea_decode`**: a GPS capture from a " +
		"u-blox module configured for UBX is undecodable as text — paste the bytes here instead.\n\n" +
		"Decodes the UBX frame envelope and validates the checksum:\n" +
		"- **Frame** — the `0xB5 0x62` sync, message class + id (named for the common NAV/RXM/CFG/MON " +
		"classes), little-endian length, and the 8-bit Fletcher checksum (CK_A/CK_B over class+id+length+" +
		"payload). A capture with several back-to-back frames decodes to a list; leading non-sync bytes " +
		"are skipped so a mid-stream capture still parses.\n" +
		"- **NAV-PVT** (class 0x01 id 0x07) — the flagship 'navigation position velocity time' message " +
		"that bundles a whole fix into one record: iTOW, UTC date/time (with validity flags + time " +
		"accuracy), fix type (no-fix / dead-reckoning / 2D / 3D / GNSS+DR / time-only) and gnssFixOK, " +
		"satellites used, longitude / latitude, height (ellipsoid + MSL), horizontal / vertical accuracy, " +
		"the NED velocity vector, ground speed, heading of motion and position DOP. Raw integer units " +
		"(mm, mm/s, deg×1e-7, deg×1e-5, 0.01 DOP) are converted to metres / m·s⁻¹ / degrees.\n\n" +
		"Paste the UBX bytes as hex; ':' / '-' / '_' / whitespace separators and a '0x' prefix tolerated. " +
		"Each frame reports `checksum_ok` (a bad checksum is still surfaced but flagged). Other UBX " +
		"messages (NAV-POSLLH, NAV-STATUS, RXM-*, CFG-*, …) are frame-decoded and class/id-named but their " +
		"body is surfaced as raw hex rather than guessed — NAV-PVT is the one message bodied out. No " +
		"network, no device, transmits nothing, so it is Low risk.\n\n" +
		"Source: docs/catalog/gap-analysis.md (GPS/GNSS decode — the binary counterpart to gps_nmea_decode). " +
		"Wrap-vs-native: native — fixed public wire format + Fletcher checksum, stdlib only, no new go.mod " +
		"dep. Anchored to the pyubx2 reference library: a NAV-PVT frame minted by pyubx2 reproduces its " +
		"decoded time / position / velocity / accuracy fields exactly.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"One or more UBX frames as hex (sync 0xB5 0x62 + class/id + length + payload + checksum). ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ubxDecodeHandler,
}

func ubxDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	in := strings.TrimSpace(str(p, "hex"))
	if in == "" {
		return "", fmt.Errorf("ubx_decode: 'hex' is required")
	}
	res, err := ubx.Decode(in)
	if err != nil {
		return "", fmt.Errorf("ubx_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
