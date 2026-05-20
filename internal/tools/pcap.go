// pcap.go — host-side libpcap classic-format file inspector Spec.
// Wraps the internal/pcap.Inspect walker.

package tools

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/pcap"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(pcapDecodeSpec)
}

var pcapDecodeSpec = Spec{
	Name: "pcap_decode",
	Description: "Decode a classic libpcap file (the universal `.pcap` packet-capture " +
		"container behind every tcpdump capture, every Wireshark save, every " +
		"aircrack-ng dump, every PMKID capture from a Marauder, every Sub-GHz " +
		"RTL-SDR recording converted to pcap). Operators routinely get handed a " +
		"`.pcap` and need to extract the link type + time window + record count " +
		"*before* pulling individual frames out for one of the 80+ existing " +
		"protocol decoders. Returns a structured metadata view:\n\n" +
		"- **Global header (24 bytes)**: 4-byte **magic** dispatching on " +
		"endianness + timestamp resolution (0xA1B2C3D4 LE-µs / 0xD4C3B2A1 BE-µs " +
		"/ 0xA1B23C4D LE-ns / 0x4D3CB2A1 BE-ns) + 2-byte **Version Major** + " +
		"2-byte **Version Minor** (expected 2.4 for classic libpcap) + 4-byte " +
		"this_zone (GMT-to-local offset; always 0 in practice) + 4-byte sig_figs " +
		"(accuracy of timestamps; always 0) + 4-byte **Snap Length** (max " +
		"captured bytes per record) + 4-byte **Network** (LINKTYPE_*).\n" +
		"- **~35-entry LINKTYPE name table**: NULL / ETHERNET / IEEE802_5 " +
		"(Token Ring) / ARCNET / SLIP / PPP / FDDI / PPP_HDLC / PPP_ETHER / " +
		"ATM / RAW (raw IPv4/v6) / C_HDLC / IEEE802_11 / FRELAY / LOOP / " +
		"LINUX_SLL (cooked v1) / LTALK / PRISM_HEADER / IEEE802_11_RADIOTAP / " +
		"MTP2/MTP3 / SCCP / DOCSIS / IEEE802_15_4_WITHFCS / BLUETOOTH_HCI_H4 / " +
		"USB_LINUX / PPI / SITA / LAPD / IEEE802_15_4_NOFCS / IPV4 / IPV6 / " +
		"NFLOG / DBUS / USBPCAP / INFINIBAND / ZIGBEE_PSI / IEEE802_15_4_TAP / " +
		"LINUX_SLL2 (cooked v2) / ZWAVE_TAP. Uncatalogued values surface as " +
		"`LINKTYPE_<n> (uncatalogued)` with the raw number preserved.\n" +
		"- **Per-record header (16 bytes)** repeated: 4-byte ts_sec + 4-byte " +
		"ts_frac (µs or ns per magic) + 4-byte **captured length** (bytes " +
		"actually in this record) + 4-byte **original length** (original packet " +
		"length on wire).\n" +
		"- **Record summary view** — per-record timestamp (decoded to RFC 3339 " +
		"nanosecond ISO form), captured + original lengths, and a configurable " +
		"hex preview of the first N bytes of payload (default 32 bytes).\n" +
		"- **Aggregate fields** — RecordCount + TotalRecordBytes + first/last " +
		"timestamp + DurationSeconds (computed across the full file walk, even " +
		"when the per-record summary list is capped for output size).\n" +
		"- **Truncation detection** — a record whose declared captured_length " +
		"runs off the end of the file is flagged via `truncated: true` plus a " +
		"Note, rather than rejecting the file; trailing bytes after the last " +
		"complete record header are also flagged.\n\n" +
		"Pure offline parser — operators paste the full hex of a `.pcap` file " +
		"(typically up to a few MB worth, given hex doubles the size). Output " +
		"caps default to the first 50 records and 32 bytes of payload preview " +
		"per record so that big captures still produce bounded output; both caps " +
		"can be raised via `max_records` and `max_payload_bytes`.\n\n" +
		"Out of scope (deferred): PCAPng (the newer block-based format used by " +
		"Wireshark since 2018 — different envelope, different block-walker; " +
		"would warrant its own Spec); per-record dissection (the operator pulls " +
		"individual frames out of the hex preview and feeds them into the " +
		"existing 80+ protocol-specific decoders — `ip_packet_decode`, " +
		"`wifi_80211_decode`, `bluetooth_cod_decode`, `ieee802154_decode`, " +
		"etc., chosen by the LINKTYPE); pcap capture (this is a *file* reader, " +
		"not a live-capture interface).\n\n" +
		"Source: docs/catalog/gap-analysis.md (universal packet-capture " +
		"container — every other decoder in the catalog ultimately consumes " +
		"bytes that came out of a pcap file). Wrap-vs-native: native — the " +
		"libpcap classic file format is fully public; uses a 24-byte global " +
		"header with a 4-magic endianness/resolution dispatch and a 16-byte " +
		"per-record header followed by raw payload bytes; no crypto, no " +
		"compression.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Full raw bytes of a libpcap classic '.pcap' file. Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."},
			"max_records":{"type":"integer","description":"Cap the number of per-record summaries returned (default 50). RecordCount + TotalRecordBytes still reflect the full file walk. Zero = no cap."},
			"max_payload_bytes":{"type":"integer","description":"Cap the per-record hex payload preview (default 32). Zero = no preview."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   pcapDecodeHandler,
}

func pcapDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("pcap_decode: 'hex' is required")
	}
	clean := stripPcapHex(raw)
	if len(clean)%2 != 0 {
		return "", fmt.Errorf("pcap_decode: hex must have even length, got %d", len(clean))
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return "", fmt.Errorf("pcap_decode: hex decode: %w", err)
	}
	opts := pcap.DefaultInspectOpts()
	if v, ok := p["max_records"]; ok {
		if n, ok := intArg(v); ok {
			opts.MaxRecords = n
		}
	}
	if v, ok := p["max_payload_bytes"]; ok {
		if n, ok := intArg(v); ok {
			opts.MaxPayloadBytes = n
		}
	}
	res, err := pcap.Inspect(b, opts)
	if err != nil {
		return "", fmt.Errorf("pcap_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}

func stripPcapHex(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	var sb strings.Builder
	for _, r := range s {
		switch r {
		case ':', '-', '_', ' ', '\t', '\n', '\r':
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

func intArg(v any) (int, bool) {
	switch x := v.(type) {
	case int:
		return x, true
	case int64:
		return int(x), true
	case float64:
		return int(x), true
	}
	return 0, false
}
