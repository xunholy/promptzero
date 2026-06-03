// aprs.go — host-side APRS / AX.25 packet dissector Spec,
// delegating to the internal/aprs package for the walker
// proper.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/aprs"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(aprsPacketDecodeSpec)
}

var aprsPacketDecodeSpec = Spec{
	Name: "aprs_packet_decode",
	Description: "Decode an APRS (Automatic Packet Reporting System) packet — the dominant ham-" +
		"radio position + telemetry + messaging beacon family transmitted on 144.39 MHz " +
		"(North America), 144.80 MHz (Europe), and a handful of HF bands. Per APRS101.pdf " +
		"(TAPR, 2000) + AX.25 v2.2 (TAPR, 1998). Accepts two input forms:\n\n" +
		"- **TNC2 text** (`SRC[-SSID]>DST[-SSID][,PATH[-SSID][*]...]:INFO`) — the canonical " +
		"format emitted by direwolf, javaAPRSSrvr, kiss-tnc, APRS-IS, etc.\n" +
		"- **AX.25 hex bytes** — raw UI-frame bytes (no FCS) for operators with a custom KISS " +
		"path or a sniffer that strips the framing.\n\n" +
		"Decodes:\n" +
		"- **Addresses**: source / destination / digipeater path. Each address has a callsign " +
		"(1-6 chars) + SSID (0-15) + digipeated flag (the '*' suffix in TNC2, or the H-bit in " +
		"the raw AX.25 SSID byte).\n" +
		"- **Info field type dispatch** via the first-byte prefix (APRS101 §5): '!' / '=' " +
		"position without timestamp, '/' / '@' position with timestamp, ':' message, '>' " +
		"status, ';' object, ')' item, '_' weather, 'T#' telemetry, '?' query, '<' station " +
		"capabilities. Every prefix is named even if no body decode is attempted.\n" +
		"- **Uncompressed position** (APRS101 §8): 'DDMM.MMN/DDDMM.MMW' converted to signed " +
		"decimal degrees with hemisphere handling + symbol table identifier + symbol code, " +
		"plus a 30+ entry symbol-name lookup covering common categories (Car, House (QTH), " +
		"Yacht, Aircraft, Police station, Repeater, Weather station, Hospital, Fire engine, " +
		"etc.).\n" +
		"- **PHG extension** (APRS101 §7): antenna Power-Height-Gain-Directivity profile " +
		"that fixed stations broadcast for coverage analysis.\n" +
		"- **Status report** ('>'): bare text extraction.\n" +
		"- **Message format** (':'): 9-character addressee + body + optional '{message-" +
		"number}' suffix.\n" +
		"- **Telemetry** ('T#'): basic 'T#seq,a1,a2,a3,a4,a5,bits' parametric form (5 analog " +
		"channels + digital bits).\n" +
		"- **Positionless weather report** ('_', APRS101 §12): the 8-char MDHM timestamp + the " +
		"fully-specified weather fields — wind direction (c), sustained wind speed (s), gust (g), " +
		"temperature (t, incl. the -01..-99 below-zero form), rainfall last hour / 24 h / since " +
		"midnight (r/p/P, hundredths-inch → inches), humidity (h, 00 = 100%), barometric pressure " +
		"(b, tenths-hPa → hPa) and luminosity (L ≤ 999 / l ≥ 1000 W/m²). An absent sensor ('...' " +
		"or spaces) decodes to a null field, not a zero; snowfall, the '#' raw rain counter and " +
		"the trailing software / WX-unit code are under-specified in APRS101 and surfaced raw " +
		"rather than guessed. Anchored to the APRS101 §12 canonical example.\n\n" +
		"Pure offline parser — operators paste a TNC2 string from any APRS feed (or a hex " +
		"blob from a KISS-modem capture) and inspect the decoded packet without re-connecting " +
		"to the air. Complements the existing subghz_* coverage by extending decode to the " +
		"VHF + UHF ham bands where APRS lives.\n\n" +
		"Out of scope for this Spec (deferred to future iterations as separate sub-decoders): " +
		"Mic-E compressed position (encoded in the destination address + info field), " +
		"compressed position format ('/' or '\\' leading char of 13-byte base-91 form), the " +
		"complete weather report (weather data appended to a position report whose symbol code is " +
		"'_', vs the positionless '_' form decoded here), telemetry parameter " +
		"definitions (#PARM / #UNIT / #EQNS / #BITS), and AX.25 connection-mode frames " +
		"(SABM / DISC / RR / I-frames).\n\n" +
		"Source: docs/catalog/gap-analysis.md (ham-radio decode space — APRS is the high-" +
		"traffic SDR target that pairs with subghz_pocsag_decode for paging dragnet workflows). " +
		"Wrap-vs-native: native — APRS101 is fully public, AX.25 is public, every field is " +
		"ASCII or simple shifted-ASCII, no cryptography.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"packet":{"type":"string","description":"APRS packet — either a TNC2 text line (e.g. 'K1ABC-9>APRS,WIDE2-1:!4903.50N/07201.75W>Test') or a hex-encoded AX.25 UI-frame byte blob. Auto-detected by presence of '>' and ':' in the input."}
		},
		"required":["packet"]
	}`),
	Required:  []string{"packet"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   aprsPacketDecodeHandler,
}

func aprsPacketDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "packet")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("aprs_packet_decode: 'packet' is required")
	}
	res, err := aprs.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("aprs_packet_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
