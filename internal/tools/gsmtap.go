// gsmtap.go — host-side GSMTAP cellular protocol tap decoder
// Spec. Wraps the internal/gsmtap walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/gsmtap"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(gsmtapDecodeSpec)
}

var gsmtapDecodeSpec = Spec{
	Name: "gsmtap_decode",
	Description: "Decode a GSMTAP pseudo-header per the Osmocom GSMTAP specification " +
		"(osmo-bts / osmo-pcap-server / gsmtap.h reference). GSMTAP is the " +
		"canonical encapsulation for cellular protocol captures — every Osmocom " +
		"tool (osmo-bts, osmo-bsc, osmo-pcu, osmo-msc, osmo-sgsn, osmo-hnbgw, " +
		"OpenBTS, srsRAN, YateBTS) prepends a 16-byte GSMTAP header to captured " +
		"layer-2 / layer-3 cellular frames and ships them via UDP/4729 (default) " +
		"for Wireshark to dissect with the right dissector per payload type. " +
		"Operationally appears in DEF CON / Black Hat / HITB cellular CTF " +
		"challenges (the canonical 'decode the GSM/UMTS/LTE air-interface trace' " +
		"format); SDR cellular research (RTL-SDR + grgsm_livemon + Wireshark " +
		"live-decode; airprobe + Kraken A5/1 cracking; LimeSDR + srsUE fronthaul " +
		"captures); Osmocom development (gsmtap.h streams of internal protocol " +
		"state across BTS → BSC → MSC → HLR → VLR); 5G research (SUCI/SUPI " +
		"extraction from LTE/5G NR RRC captures, IMSI catcher forensics, gNB/eNB " +
		"fingerprinting). Decodes:\n\n" +
		"- **16-byte fixed pseudo-header** (multi-byte fields big-endian): " +
		"Version (0x02 current; 0x01 legacy) + HeaderLen (in 32-bit words, " +
		"usually 4 → 16 bytes total) + PayloadType (1-byte discriminator) + " +
		"Timeslot (TDMA slot 0-7) + ARFCN (16-bit field: bottom 14 bits = " +
		"Absolute Radio Frequency Channel Number; bit 14 = PCS band; bit 15 = " +
		"uplink — surfaced as separate arfcn / arfcn_pcs_band / arfcn_uplink " +
		"fields) + Signal level (int8 dBm) + SNR (int8 dB) + Frame Number " +
		"(uint32 BE; GSM TDMA frame counter) + SubType (1 byte; payload-type-" +
		"specific) + Antenna + SubSlot + Reserved.\n" +
		"- **15+ entry PayloadType name table**: 0x00 UM (legacy alias) / 0x01 " +
		"UM_L2 (GSM L2 frame on Um air interface — the most common GSMTAP-" +
		"wrapped traffic) / 0x02 ABIS (BTS↔BSC LAPD) / 0x03 UM_BURST (raw GSM " +
		"burst bits) / 0x04 SIM (SIM APDU exchange — common in SIM-pentest " +
		"captures) / 0x05 TETRA_I1 / 0x06 TETRA_I1_BURST / 0x07 WMX_BURST / " +
		"0x08 GB_LLC / 0x09 GB_SNDCP / 0x0A GMR1_UM / 0x0D UMTS_RLC_MAC / 0x0E " +
		"LTE_RRC / 0x0F LTE_MAC / 0x10 LTE_MAC_FRAMED / 0x11 OSMOCORE_LOG / " +
		"0x12 QC_DIAG.\n" +
		"- **17-entry GSM Um L2 channel name table** (used when PayloadType = " +
		"UM_L2): 0x01 BCCH / 0x02 CCCH / 0x03 RACH / 0x04 AGCH / 0x05 PCH / " +
		"0x06 SDCCH / 0x07 SDCCH4 / 0x08 SDCCH8 / 0x09 TCH_F / 0x0A TCH_H / " +
		"0x0B PACCH / 0x0C CBCH52 / 0x0D PDCH / 0x0E PTCCH / 0x0F CBCH51 / " +
		"0x10 VOICE_F / 0x11 VOICE_H.\n" +
		"- **LTE RRC channel direction** (used when PayloadType = LTE_RRC): " +
		"even sub-type = Downlink, odd = Uplink (Osmocom convention).\n" +
		"- **Encapsulated cellular payload** — bytes after the 16-byte header " +
		"are the raw cellular L2/L3 frame; surfaced as payload_hex for " +
		"downstream cellular-protocol decoders (LAPDm / RR / MM / CM / RANAP / " +
		"RRC / NAS).\n\n" +
		"Pure offline parser — operators paste GSMTAP bytes (starting at the " +
		"Version byte 0x02; default UDP port 4729) from a `tcpdump -X port " +
		"4729` line, an Osmocom grgsm_livemon stream capture, or a Wireshark " +
		"GSMTAP dissector view and get the documented header + per-PayloadType " +
		"SubType breakdown.\n\n" +
		"Out of scope (deferred): network framing (feed bytes after the UDP-" +
		"datagram header strip; default UDP port 4729); encapsulated cellular " +
		"protocol bodies (the PayloadType + SubType discriminate which cellular " +
		"protocol is wrapped — GSM RR / GSM MM / GSM CM / GSM SS / GPRS LLC / " +
		"UMTS RRC / LTE RRC / LTE NAS / 5G NAS; per-protocol decoders are " +
		"dataset-specific and surfaced as payload_hex for follow-on walkers); " +
		"GSMTAPv1 (the obsolete v1 header is rare in modern captures — the " +
		"decoder reports the version byte but only walks v2 fields); burst " +
		"data decoding (PayloadType 0x03 UM_BURST carries raw GSM burst bits — " +
		"surfaced as hex but GMSK modulation symbol decoding is out of scope); " +
		"Osmocore log text decoding (PayloadType 0x11 OSMOCORE_LOG carries " +
		"free-form text — surfaced as payload_hex; UTF-8 decoding is a follow-" +
		"on step); TETRA / WiMAX / GMR-1 payload-type-specific decoders (non-" +
		"3GPP cellular sidebands surfaced as opaque payload_hex).\n\n" +
		"Source: docs/catalog/gap-analysis.md (cellular protocol tap dissector " +
		"— the canonical wrapper format for cellular research captures; common " +
		"in DEF CON / Black Hat / HITB cellular CTFs + SDR cellular research + " +
		"Osmocom development + 5G IMSI-catcher forensics). Wrap-vs-native: " +
		"native — the Osmocom gsmtap.h header is publicly documented; 16-byte " +
		"fixed pseudo-header with deterministic field layout; no crypto at the " +
		"parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"GSMTAP message bytes starting at the Version byte 0x02 (the UDP payload; default UDP port 4729). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   gsmtapDecodeHandler,
}

func gsmtapDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("gsmtap_decode: 'hex' is required")
	}
	res, err := gsmtap.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("gsmtap_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
