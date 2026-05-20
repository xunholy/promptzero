// pcapng.go — host-side PCAPng file inspector Spec.
// Wraps the internal/pcapng.Inspect walker.

package tools

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/pcapng"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(pcapngDecodeSpec)
}

var pcapngDecodeSpec = Spec{
	Name: "pcapng_decode",
	Description: "Decode a PCAPng (next-generation packet capture) file. PCAPng has " +
		"been Wireshark's default capture format since 2018 and the emitted format " +
		"of most modern tcpdump builds; operators increasingly get .pcapng files " +
		"instead of classic .pcap. Sits alongside `pcap_decode` (classic libpcap) " +
		"for complete packet-capture container coverage. Returns a structured " +
		"per-section + per-block summary:\n\n" +
		"- **Block framing** — every block has a tight 4-byte Block Type + 4-byte " +
		"Block Total Length + body + trailing repeated 4-byte Block Total Length " +
		"(back-pointer for reverse navigation). Endianness is detected once per " +
		"section via the SHB Byte-Order Magic and held for every subsequent block " +
		"in that section.\n" +
		"- **9-entry block type table** (per the IANA pcapng-block-types " +
		"registry): 0x0A0D0D0A Section Header Block (SHB; palindrome — also the " +
		"endianness-detection token); 0x00000001 Interface Description Block " +
		"(IDB); 0x00000003 Simple Packet Block (SPB; obsolete); 0x00000004 Name " +
		"Resolution Block (NRB); 0x00000005 Interface Statistics Block (ISB); " +
		"0x00000006 Enhanced Packet Block (EPB; the canonical packet record); " +
		"0x00000007 IRIG Timestamp Block; 0x00000009 Decryption Secrets Block " +
		"(DSB; TLS / SSH key log materials); 0x0BAD0001 Custom Block.\n" +
		"- **SHB body**: 4-byte Byte-Order Magic + 2-byte Major Version + 2-byte " +
		"Minor Version + 8-byte Section Length (int64; -1 = not specified) + " +
		"options.\n" +
		"- **IDB body**: 2-byte LinkType (resolved via the existing libpcap " +
		"LINKTYPE_* name table — same one `pcap_decode` uses) + 2-byte Reserved " +
		"+ 4-byte SnapLen + options (if_name / if_description / if_IPv4addr / " +
		"if_MACaddr / if_speed / if_tsresol / if_os / etc.).\n" +
		"- **EPB body**: 4-byte Interface ID (index into the section's IDB list) " +
		"+ 4-byte Timestamp High + 4-byte Timestamp Low (joined to a 64-bit " +
		"count; resolution depends on the referenced IDB's if_tsresol option, " +
		"default 10⁻⁶ s) + 4-byte Captured Length + 4-byte Original Length + " +
		"Packet Data (padded to 4-byte boundary) + options.\n" +
		"- **Options walker** — (Code uint16, Length uint16, Value padded to " +
		"4-byte boundary), ending at the opt_endofopt sentinel (Code 0, Length " +
		"0). Plausible-text values surfaced as decoded UTF-8 alongside raw hex.\n" +
		"- **Per-section aggregate** — BlockSummary (counts of each block type), " +
		"Interfaces list (every IDB), Records list (up to MaxRecords EPBs with " +
		"hex preview).\n\n" +
		"Pure offline parser — operators paste the full hex of a `.pcapng` file. " +
		"Output caps default to the first 50 EPB records per section and a 32-" +
		"byte hex preview per record so that big captures still produce bounded " +
		"output; both caps can be raised via `max_records` and " +
		"`max_payload_bytes`.\n\n" +
		"Out of scope (deferred): classic libpcap `.pcap` (use `pcap_decode`); " +
		"per-record protocol dissection (operator pulls individual frames out of " +
		"the EPB hex preview and feeds them into the existing 80+ protocol-" +
		"specific decoders chosen by the IDB LinkType); PCAPng capture (this is " +
		"a *file* reader, not a live-capture interface); DSB payload parsing " +
		"(TLS / SSH key-log materials inside DSB deserve their own dissector — " +
		"surfaced as block-type counts only).\n\n" +
		"Source: docs/catalog/gap-analysis.md (universal packet-capture " +
		"container — every modern Wireshark save and most tcpdump captures are " +
		"PCAPng; classic libpcap is increasingly the legacy format). Wrap-vs-" +
		"native: native — the PCAPng spec is fully public; uses a block-based " +
		"envelope with a 4-byte Type + 4-byte Length + body + 4-byte trailing " +
		"Length validating back-navigation; no crypto, no compression.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Full raw bytes of a PCAPng '.pcapng' file. Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."},
			"max_records":{"type":"integer","description":"Cap the number of EPB summaries returned per section (default 50). BlockSummary counts still reflect the full file walk."},
			"max_payload_bytes":{"type":"integer","description":"Cap the per-EPB hex payload preview (default 32). Zero = no preview."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   pcapngDecodeHandler,
}

func pcapngDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("pcapng_decode: 'hex' is required")
	}
	clean := stripPcapHex(raw)
	if len(clean)%2 != 0 {
		return "", fmt.Errorf("pcapng_decode: hex must have even length, got %d", len(clean))
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return "", fmt.Errorf("pcapng_decode: hex decode: %w", err)
	}
	opts := pcapng.DefaultInspectOpts()
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
	res, err := pcapng.Inspect(b, opts)
	if err != nil {
		return "", fmt.Errorf("pcapng_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
