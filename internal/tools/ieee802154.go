// ieee802154.go — host-side IEEE 802.15.4 MAC frame dissector
// Spec, delegating to the internal/ieee802154 package for the
// walker proper.
//
// Wrap-vs-native judgement: IEEE 802.15.4 is a fully public
// standard. The walker is bit-level decoding over a 5-127 byte
// frame with a documented Frame Control + addressing-mode-driven
// address field. Wrapping a FAP for this would add an SD-card
// install step + a firmware-fork dependency for a pure parser.
// Native delivers offline analysis — operators paste a captured
// frame from a CatSniffer / KillerBee / Sniffle / any
// 802.15.4-capable SDR and inspect every MAC-layer field without
// an antenna attached.
//
// Pairs with bruce_zigbee_scan (which surfaces observed PAN
// beacons from a Bruce-equipped Flipper) — this Spec is the
// offline-analyst entry point for captured frames.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ieee802154"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(ieee802154DecodeSpec)
}

var ieee802154DecodeSpec = Spec{
	Name: "ieee802154_decode",
	Description: "Decode an IEEE 802.15.4 MAC-layer frame — the wire format underneath Zigbee, " +
		"Thread, OpenThread, and most other 2.4 GHz IoT mesh stacks. Decodes:\n\n" +
		"- **Frame Control** (16 bits): frame type (Beacon / Data / Ack / MAC Command / " +
		"Multipurpose / Fragment / Extended), Security Enabled / Frame Pending / Ack Request / " +
		"PAN ID Compression / Sequence Number Suppression / IE Present flags, destination + " +
		"source addressing modes (None / Short 16-bit / Extended 64-bit), Frame Version " +
		"(2003 / 2006 / 2015).\n" +
		"- **Sequence Number** (omitted when the 2015-spec suppression flag is set).\n" +
		"- **Addressing fields**: destination PAN + address, source PAN + address. Short " +
		"(16-bit) and Extended (64-bit EUI-64) variants. PAN ID Compression handled (source " +
		"borrows destination's PAN ID when set).\n" +
		"- **Auxiliary Security Header**: when Security Enabled, the header bytes are surfaced " +
		"as hex (1-byte Security Control determines length per KeyIdMode; we don't dissect " +
		"frame counter / key identifier — those need network keys to be useful).\n" +
		"- **MAC Payload**: raw hex (decryption needs network / link keys out-of-band).\n" +
		"- **FCS**: optionally treats the trailing 2 bytes as the Frame Check Sequence — set " +
		"`include_fcs` to true when your capture (e.g. from CatSniffer / Sniffle) includes it.\n\n" +
		"Pure offline parser — no Flipper / SDR required. Pairs with the bruce_zigbee_scan " +
		"capability for device-side scanning. Accepts ':' / '-' / '_' / whitespace separators.\n\n" +
		"Source: docs/catalog/gap-analysis.md (decode space adjacent to honourable-mention " +
		"Zigbee + Thread). Wrap-vs-native: native — IEEE 802.15.4 is a fully public spec, the " +
		"walker is ~400 lines of bit-twiddling.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded IEEE 802.15.4 MAC frame. ':' / '-' / '_' / whitespace separators tolerated."},
			"include_fcs":{"type":"boolean","description":"Treat the trailing 2 bytes as the Frame Check Sequence. Default false. Set true when your capture source (CatSniffer / Sniffle) includes the FCS."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ieee802154DecodeHandler,
}

func ieee802154DecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("ieee802154_decode: 'hex' is required")
	}
	var opts ieee802154.DecodeOptions
	if v, ok := p["include_fcs"]; ok {
		if b, isBool := v.(bool); isBool {
			opts.IncludeFCS = b
		}
	}
	res, err := ieee802154.DecodeWithOptions(raw, opts)
	if err != nil {
		return "", fmt.Errorf("ieee802154_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
