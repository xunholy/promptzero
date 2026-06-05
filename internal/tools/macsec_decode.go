// macsec_decode.go — host-side IEEE 802.1AE (MACsec) SecTAG decoder Spec,
// delegating to internal/macsec.
//
// Wrap-vs-native: native — the SecTAG is a fixed public bit/byte layout
// (802.1AE-2006 §9.3: TCI/AN + SL + PN + optional SCI); byte-field
// extraction + bit-masking. Bodies out the 0x88E5 EtherType that the
// vlan/lldp/cdp wired-L2 decoders already name. Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/macsec"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(macsecDecodeSpec)
}

var macsecDecodeSpec = Spec{
	Name: "macsec_decode",
	Description: "Decode an **IEEE 802.1AE (MACsec)** Security TAG — the per-frame header on a MACsec-protected " +
		"Ethernet frame (EtherType `0x88E5`). MACsec gives hop-by-hop L2 confidentiality + integrity on a " +
		"wired LAN, usually keyed by 802.1X / MKA; the SecTAG is sent **in the clear**, so decoding it from a " +
		"capture exposes the secure-channel identity, the association number, the replay-protection packet " +
		"number and whether the user data is encrypted — the visibility a **network-access-control / MACsec " +
		"deployment audit** needs. Complements the wired-L2 decoders (`vlan_decode`, `lldp` / `cdp` / `stp`) " +
		"which already name 0x88E5 but don't body it out.\n\n" +
		"Decodes the SecTAG:\n" +
		"- The **TCI flags** — Version, End-Station, SCI-present, Single-Copy-Broadcast, **Encryption** (E) " +
		"and Changed-text (C) — and the 2-bit **Association Number**.\n" +
		"- The **Short Length** and the 32-bit **Packet Number** (replay protection / GCM IV input).\n" +
		"- When SC is set, the 64-bit **Secure Channel Identifier**, split into its 48-bit system identifier " +
		"(a MAC address) and 16-bit port identifier.\n" +
		"- The trailing user data split into the **Secure Data** (encrypted when E=1, authenticated " +
		"cleartext when E=0) and the 16-octet **ICV**.\n\n" +
		"Pass the bytes as hex — beginning at the SecTAG, or as a **full Ethernet frame** whose EtherType is " +
		"0x88E5 (the outer dst/src MACs are then surfaced too); ':' / '-' / '_' / whitespace separators and " +
		"a '0x' prefix tolerated. The Secure Data is **not decrypted** and the ICV is **not verified** — " +
		"both need the Secure Association Key (SAK), which is derived by MKA and never on the wire, so it is " +
		"surfaced opaque (no confidently-wrong output); the 16-octet ICV split assumes the mandatory " +
		"GCM-AES cipher suite. No network, no device, transmits nothing, so it is Low risk.\n\n" +
		"Source: docs/catalog/gap-analysis.md (wired-L2 security decode — the 0x88E5 EtherType the VLAN/LLDP " +
		"decoders only named). Wrap-vs-native: native — fixed public bit/byte layout, stdlib only, no new " +
		"go.mod dep. Verified field-for-field against scapy's MACsec layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"A MACsec frame as hex — the SecTAG onward, or a full Ethernet frame with EtherType 0x88E5. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   macsecDecodeHandler,
}

func macsecDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("macsec_decode: 'hex' is required")
	}
	res, err := macsec.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("macsec_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
