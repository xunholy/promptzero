// zigbee.go — host-side Zigbee Network Layer (NWK) frame
// dissector Spec, delegating to the internal/zigbee package for
// the walker proper.
//
// Wrap-vs-native judgement: Zigbee NWK is a public Zigbee
// Alliance specification (Zigbee Pro 2015 R21+). The walker is
// bit-level decoding over a documented Frame Control + address
// + optional fields layout. Wrapping a FAP for this would add
// an SD-card install step + a firmware-fork dependency for a
// pure parser. Native delivers offline analysis — operators
// decode the IEEE 802.15.4 MAC frame with ieee802154_decode,
// then dispatch the MAC payload here for NWK-layer fields.
//
// Pairs with the existing ieee802154_decode — chain the two for
// full Zigbee frame analysis (MAC + NWK).

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/zigbee"
)

func init() { //nolint:gochecknoinits
	Register(zigbeeNWKDecodeSpec)
}

var zigbeeNWKDecodeSpec = Spec{
	Name: "zigbee_nwk_decode",
	Description: "Decode a Zigbee Network Layer (NWK) frame — the layer that sits on top of " +
		"IEEE 802.15.4 MAC frames in the Zigbee stack. Decodes:\n\n" +
		"- **Frame Control** (16 bits): frame type (Data / NWK Command / Inter-PAN), protocol " +
		"version (R22 = 2), discover route (Suppress / Enable), multicast / security / source " +
		"route / destination IEEE / source IEEE presence flags.\n" +
		"- **Addressing**: 16-bit destination + source NWK short addresses (with broadcast-" +
		"class identification for 0xFFFF / 0xFFFD / 0xFFFC / 0xFFFB), radius (hop limit), " +
		"sequence number, optional 64-bit destination + source IEEE addresses (little-endian " +
		"on wire, rendered big-endian).\n" +
		"- **Multicast control byte** (when multicast flag set): mode (Non-member / Member) + " +
		"non-member radius + max non-member radius.\n" +
		"- **Source route subframe** (when source-route flag set): relay count + relay index + " +
		"relay address list.\n" +
		"- **Auxiliary security header** (when security flag set): walks the 1-byte security " +
		"control to size the header per KeyID + extended-nonce flag; surfaces the full header " +
		"as hex (decryption needs the network key out-of-band).\n" +
		"- **NWK payload**: surfaced as hex; APS / ZCL dissection deferred to follow-on Specs.\n\n" +
		"Pure offline parser — operators paste a captured frame (typically the MAC payload " +
		"from a CatSniffer / KillerBee / Sniffle capture) and inspect every NWK-layer field. " +
		"Pairs with ieee802154_decode for the MAC layer. Accepts ':' / '-' / '_' / whitespace " +
		"separators.\n\n" +
		"Source: docs/catalog/gap-analysis.md (2.4 GHz IoT decode space). Wrap-vs-native: " +
		"native — Zigbee NWK is a fully public spec, the walker is ~400 lines of bit-twiddling.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded Zigbee NWK frame (the MAC payload from an 802.15.4 frame). ':' / '-' / '_' / whitespace separators tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   zigbeeNWKDecodeHandler,
}

func zigbeeNWKDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("zigbee_nwk_decode: 'hex' is required")
	}
	res, err := zigbee.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("zigbee_nwk_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
