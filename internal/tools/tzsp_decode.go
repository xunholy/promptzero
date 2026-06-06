// tzsp_decode.go — host-side TZSP (TaZmen Sniffer Protocol, remote
// wireless-capture encapsulation) decoder Spec, delegating to internal/tzsp.
//
// Wrap-vs-native: native — a 4-byte header + a type/len/value tag walk
// terminated by an END tag, then the raw encapsulated frame; byte-field
// reads, stdlib only. Surfaces the radio metadata (channel / RSSI / SNR /
// rate / FCS) a MikroTik/Aruba sensor streamed + the sniffed frame.
// Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/tzsp"
)

func init() { //nolint:gochecknoinits
	Register(tzspDecodeSpec)
}

var tzspDecodeSpec = Spec{
	Name: "tzsp_decode",
	Description: "Decode **TZSP** (TaZmen Sniffer Protocol) — the UDP encapsulation (default port 37008 / " +
		"0x9090) that **MikroTik RouterOS**, Aruba and other gear use to **stream sniffed wireless frames to " +
		"a remote analyser**. A captured TZSP stream is a remote packet-capture feed: each datagram wraps one " +
		"sniffed frame (802.11 / Ethernet / Prism / AVS) together with the radio metadata the sensor " +
		"observed — the RX **channel**, **RSSI**, SNR, link rate and FCS-error flag — so decoding it surfaces " +
		"both the wireless-recon metadata and the encapsulated frame. Joins the project's wireless tooling " +
		"(`ieee80211`, `marauder`) and tunnel-decap decoders (`gre`, `geneve`, `vxlan`).\n\n" +
		"Decodes the 4-byte header (version, **packet type** — RX / TX / CONFIG / KEEPALIVE / PORT, " +
		"**encapsulated protocol**) and the tag list: RAW_RSSI, SNR (both signed), DATA_RATE (named Mb/s), " +
		"TIMESTAMP, CONTENTION_FREE, DECRYPTED, **FCS_ERROR**, **RX_CHANNEL**, PACKET_COUNT, RX_FRAME_LENGTH " +
		"and the WLAN sensor id — with the most recon-relevant tags (RSSI / SNR / rate / channel / FCS) also " +
		"lifted to top-level fields. The encapsulated frame is surfaced as raw hex with its protocol named.\n\n" +
		"No confidently-wrong output: standard tags are decoded by type; the complete encapsulated frame is " +
		"left as raw hex for the matching decoder (e.g. `ieee80211_decode`) rather than partially parsed " +
		"here, and unknown tags are surfaced as raw hex. No network, no device, transmits nothing, so it is " +
		"Low risk. ':' / '-' / '_' / whitespace separators and a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (remote wireless-capture / MikroTik sniffer recon). " +
		"Wrap-vs-native: native — a byte-field read + a tag walk, stdlib only, no new go.mod dep. Verified " +
		"field-for-field against scapy's TZSP layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The TZSP datagram (the UDP-37008 payload) as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   tzspDecodeHandler,
}

func tzspDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("tzsp_decode: 'hex' is required")
	}
	res, err := tzsp.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("tzsp_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
