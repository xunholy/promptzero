// nbns.go — host-side NBNS (NetBIOS Name Service) decoder Spec.
// Wraps the internal/nbns walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/nbns"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(nbnsDecodeSpec)
}

var nbnsDecodeSpec = Spec{
	Name: "nbns_decode",
	Description: "Decode an NBNS (NetBIOS Name Service) message per RFC 1001 + RFC 1002 " +
		"(NetBIOS over TCP/UDP). NBNS is the legacy Windows name-resolution " +
		"protocol that runs over UDP/137 and predates DNS in the Microsoft " +
		"ecosystem. Interesting because (i) NBNS is the canonical target of " +
		"Responder.py poisoning attacks — when a Windows host looks up an " +
		"unqualified short name and DNS fails, it broadcasts a UDP/137 NBNS " +
		"QUERY to the local subnet and an attacker can reply with their own IP " +
		"to capture inbound NTLMv2 challenge/response for offline cracking; " +
		"(ii) observing NBNS QUERY traffic reveals every short hostname / file-" +
		"server / printer users are searching for, leaking the entire NetBIOS " +
		"namespace; (iii) NBNS REGISTRATION / REFRESH traffic from domain " +
		"controllers (suffix 0x1C) leaks the AD domain name + every DC's " +
		"NetBIOS name. Decodes:\n\n" +
		"- **DNS-style header** (RFC 1002 §4.2, 12 bytes, big-endian): " +
		"TransactionID + Flags + QD/AN/NS/AR counts.\n" +
		"- **Flags field** (16 bits BE): bit 15 QR (response indicator) + bits " +
		"11-14 Opcode + bit 10 AA (Authoritative Answer) + bit 9 TC (Truncated) " +
		"+ bit 8 RD (Recursion Desired) + bit 7 RA (Recursion Available) + " +
		"bit 5 B (Broadcast) + bits 0-3 RCODE.\n" +
		"- **5-entry Opcode name table** (§4.2.1.1): 0 QUERY / 5 REGISTRATION " +
		"/ 6 RELEASE / 7 WACK (Wait for Acknowledgement) / 8 REFRESH.\n" +
		"- **8-entry RCODE name table** (§4.2.6): 0 No_Error / 1 Format_Error " +
		"/ 2 Server_Failure / 3 Name_Error / 4 Not_Implemented / 5 " +
		"Refused_Error / 6 Active_Error (the canonical NetBIOS name-conflict " +
		"response — name already in use) / 7 Conflict_Error.\n" +
		"- **NetBIOS name decoder** (§4.2.1.2): a NetBIOS name is 15 bytes of " +
		"name (right-padded with spaces) + 1 byte of name-service suffix; " +
		"encoded by splitting each name byte into two nibbles, each offset by " +
		"0x41 ('A'), to produce a 32-byte sequence of letters A-P. The decoder " +
		"de-encodes the wire format back to the original 15-byte name + 1-byte " +
		"suffix byte. Handles RFC 1035 §4.1.4 compression pointers (bits 11 in " +
		"the first name byte → bottom 14 bits = offset from message start) up " +
		"to 5 hops deep.\n" +
		"- **20+ entry NetBIOS suffix name table** (Microsoft KB 163409 + " +
		"Samba documentation): 0x00 Workstation / 0x01 Master_Browser / 0x03 " +
		"Messenger / 0x06 RAS_Server / 0x1B Domain_Master_Browser (PDC " +
		"emulator FSMO role) / 0x1C Domain_Controllers (every DC registers " +
		"this for the domain name; canonical AD-enumeration fingerprint) / " +
		"0x1D Master_Browser_per_Subnet / 0x1E Browser_Election / 0x1F NetDDE " +
		"/ 0x20 File_Server / 0x21 RAS_Client / 0x22 MS_Exchange_Interchange " +
		"/ 0x23 MS_Exchange_Store / 0x24 MS_Exchange_Directory / 0x2B " +
		"Lotus_Notes / 0x30 Modem_Sharing_Server / 0x31 Modem_Sharing_Client " +
		"/ 0x43 SMS_Client_Remote_Control / 0x44 SMS_Admin_Remote_Control / " +
		"0x45 SMS_Client_Remote_Chat / 0x46 SMS_Client_Remote_Xfer / 0x6A " +
		"MS_Exchange_IMC / 0x87 MS_Exchange_MTA / 0xBE Network_Monitor_Agent " +
		"/ 0xBF Network_Monitor_Application.\n" +
		"- **Question record** (§4.2.1.3): encoded NetBIOS name + 2-byte Type " +
		"+ 2-byte Class. Type 0x0020 (NB) is the common case; 0x0021 (NBSTAT) " +
		"requests a NetBIOS adapter status table. Class 0x0001 (IN) is near-" +
		"universal.\n" +
		"- **NB resource record body** (§4.2.13): when the answer is type NB " +
		"(0x0020), the RDATA carries one or more (2-byte Flags + 4-byte IPv4 " +
		"address) tuples. The decoder surfaces every IP claimed by the " +
		"responding node.\n\n" +
		"Pure offline parser — operators paste NBNS bytes (the UDP payload as " +
		"hex; default UDP port 137) from a `tcpdump -X port 137` line or a " +
		"Wireshark NBNS dissector view and get the documented header + per-" +
		"record breakdown.\n\n" +
		"Out of scope (deferred): network framing (feed bytes after the UDP-" +
		"datagram header strip; default UDP port 137 for NBNS); NetBIOS " +
		"Datagram Service NBDS (UDP/138 — used for SMB browser elections + " +
		"workgroup announcements; separate decoder); NetBIOS Session Service " +
		"NBSS (TCP/139 — TCP framing layer underneath classic SMB1 file-share " +
		"traffic; separate decoder); NBSTAT response decoder (Type 0x0021 " +
		"NBSTAT answers carry a NetBIOS-name table + per-name flags + 6-byte " +
		"unit ID MAC address; per-name walker is dataset-specific and surfaced " +
		"as rdata_hex for future decoders); WINS replication (NBNS-over-WINS " +
		"adds replication PDUs to the base spec — higher-level analysis).\n\n" +
		"Source: docs/catalog/gap-analysis.md (Windows AD reconnaissance " +
		"dissector — pairs with future LLMNR / mDNS decoders for the full " +
		"Windows name-resolution trio; canonical target of Responder.py " +
		"poisoning; common in DEF CON Recon Village CTFs + AD pentest " +
		"engagements). Wrap-vs-native: native — RFC 1002 is publicly " +
		"available; the wire format is a tight 12-byte DNS-style header + " +
		"per-record encoding with NetBIOS-specific name encoding; no crypto " +
		"at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"NBNS message bytes (the UDP payload; default UDP port 137). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   nbnsDecodeHandler,
}

func nbnsDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("nbns_decode: 'hex' is required")
	}
	res, err := nbns.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("nbns_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
