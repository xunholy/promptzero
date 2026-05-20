// tftp.go — host-side TFTP packet decoder Spec.
// Wraps the internal/tftp walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/tftp"
)

func init() { //nolint:gochecknoinits
	Register(tftpDecodeSpec)
}

var tftpDecodeSpec = Spec{
	Name: "tftp_decode",
	Description: "Decode a TFTP (Trivial File Transfer Protocol) packet per RFC 1350, " +
		"with the Option Extension family from RFC 2347 (envelope) + RFC 2348 " +
		"(blksize) + RFC 2349 (timeout + tsize) + RFC 7440 (windowsize). TFTP is " +
		"the canonical minimal file-transfer protocol; despite its 1981 vintage " +
		"it remains the dominant transport for **PXE / network boot** (every PXE-" +
		"booting machine fetches its boot loader, kernel, and initrd over TFTP); " +
		"**IoT firmware updates** (most embedded devices fetch firmware via TFTP " +
		"because it fits in 2 KB of ROM); and **network device config push** " +
		"(every Cisco / Juniper / Arista shop uses TFTP for `copy running-config " +
		"tftp:` workflows). Decodes:\n\n" +
		"- **2-byte Opcode** (RFC 1350 §5) with **6-entry name table**: 1 RRQ " +
		"(Read Request), 2 WRQ (Write Request), 3 DATA, 4 ACK, 5 ERROR, 6 OACK " +
		"(Option Acknowledgment; RFC 2347).\n" +
		"- **RRQ / WRQ body** (Types 1 + 2): Filename (null-terminated UTF-8) + " +
		"Mode (null-terminated UTF-8 — RFC 1350 defines 'netascii', 'octet', and " +
		"the deprecated 'mail') + zero or more null-terminated (name, value) " +
		"option pairs. **4-entry option name table**: blksize (RFC 2348 — block " +
		"size override, default 512), timeout (RFC 2349 — retransmit timeout in " +
		"seconds), tsize (RFC 2349 — transfer size in bytes; client sends 0 to " +
		"request the server's value), windowsize (RFC 7440 — DATA blocks before " +
		"ACK).\n" +
		"- **DATA body** (Type 3): Block Number (uint16 BE; starts at 1, wraps " +
		"to 0 after 65535 — the rollover is silently the reason for the long-" +
		"standing 32 MB classic TFTP transfer cap, lifted by the windowsize + " +
		"blksize options) + Payload (variable, up to negotiated blksize — default " +
		"512 bytes; a short payload signals the last block). Payload is surfaced " +
		"as hex (capped) and, when plausibly text, as decoded UTF-8.\n" +
		"- **ACK body** (Type 4): Block Number being acknowledged.\n" +
		"- **ERROR body** (Type 5): Error Code (uint16 BE) with **9-entry name " +
		"table** (0 Not defined / 1 File not found / 2 Access violation / 3 Disk " +
		"full or allocation exceeded / 4 Illegal TFTP operation / 5 Unknown " +
		"transfer ID / 6 File already exists / 7 No such user / 8 Option " +
		"negotiation failure) + Error Message (null-terminated UTF-8).\n" +
		"- **OACK body** (Type 6) — same option-list layout as the options " +
		"portion of RRQ/WRQ; the server replies with the option values it has " +
		"agreed to.\n\n" +
		"Pure offline parser — operators paste TFTP bytes (UDP destination port " +
		"69 server-side, or the ephemeral port the server picked for active " +
		"transfer continuation) from a `tcpdump -X udp port 69` line or a " +
		"Wireshark Follow-UDP-Stream view and get the documented opcode + body " +
		"breakdown.\n\n" +
		"Out of scope (deferred): UDP framing (feed TFTP bytes after the UDP " +
		"header strip — TFTP runs on UDP destination port 69 server-side or the " +
		"ephemeral port the server picked for transfer-data continuation); TFTP " +
		"state-machine reasoning (block-number windowing, retransmit-after-" +
		"timeout logic, lockstep ACK ordering — higher-level analysis); " +
		"reassembly of the file payload across DATA blocks (each DATA block is " +
		"decoded standalone; concatenating them is collector-side work).\n\n" +
		"Source: docs/catalog/gap-analysis.md (foundational minimal file-transfer " +
		"protocol — universal in PXE boot, IoT firmware update, and Cisco / " +
		"Juniper / Arista config-push workflows; often overlooked in security " +
		"tooling despite its omnipresence). Wrap-vs-native: native — RFC 1350 + " +
		"2347 are fully public; TFTP packets have a tight 2-byte opcode + per-" +
		"opcode body, no crypto, no compression, no fancy framing.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"TFTP packet bytes (after UDP header strip; UDP destination port 69 server-side or the ephemeral port the server picked for transfer continuation). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."},
			"max_payload_bytes":{"type":"integer","description":"Cap the per-DATA hex preview (default 256). Zero surfaces the entire payload."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   tftpDecodeHandler,
}

func tftpDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("tftp_decode: 'hex' is required")
	}
	opts := tftp.DefaultDecodeOpts()
	if v, ok := p["max_payload_bytes"]; ok {
		if n, ok := intArg(v); ok {
			opts.MaxPayloadBytes = n
		}
	}
	res, err := tftp.Decode(raw, opts)
	if err != nil {
		return "", fmt.Errorf("tftp_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
