// ipmi.go — host-side IPMI/RMCP wire-protocol decoder Spec.
// Wraps the internal/ipmi walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ipmi"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(ipmiDecodeSpec)
}

var ipmiDecodeSpec = Spec{
	Name: "ipmi_decode",
	Description: "Decode an IPMI (Intelligent Platform Management Interface) " +
		"message carried over RMCP (Remote Management Control Protocol) on " +
		"UDP/623. Covers IPMI 1.5 session headers (auth_type != 0x06) and " +
		"IPMI 2.0 / RMCP+ session headers (auth_type == 0x06), plus the " +
		"inner IPMI LAN message frame. Compatible with iLO (HPE), iDRAC " +
		"(Dell), IMM/XCC (Lenovo), ASMB (ASUS), and Supermicro BMC — " +
		"every server BMC deployed in the datacenter speaks UDP/623. " +
		"Critical-severity out-of-band management surface — the BMC runs " +
		"independently of the host OS, persists across reboots, and has " +
		"full power-cycle, firmware-flash, and console-redirection access.\n\n" +
		"The wire format leaks: **Get Channel Auth Capabilities " +
		"(NetFn 0x06 / cmd 0x38)** — THE canonical IPMI recon command; " +
		"every IPMI scanner (ipmitool, metasploit ipmi_version, ipmi-scan) " +
		"sends this first; response reveals supported auth types (None / " +
		"MD2 / MD5 / Password / OEM) and whether IPMI 2.0 is supported; " +
		"auth type None = unauthenticated BMC access; **Cipher Suite 0 " +
		"(CVE-2013-4786)** — IPMI 2.0 mandates cipher suite 0 (RAKP-None, " +
		"no integrity, no confidentiality) be supported; many BMCs accept " +
		"commands via suite 0 without credentials; flagged by " +
		"Get Channel Cipher Suites (cmd 0x54); **RAKP Message 2 " +
		"(payload_type 0x13)** — during RMCP+ auth the BMC sends a " +
		"HMAC-SHA1 hash offline-crackable with hashcat mode 7300 " +
		"(IPMI2 RAKP HMAC-SHA1); any unauthenticated client can trigger " +
		"RAKP-2 and capture the hash; **Get Device ID (cmd 0x01)** — " +
		"firmware version fingerprint: device ID, firmware revision, IPMI " +
		"version, manufacturer ID (IANA PEN), product ID; canonical " +
		"pre-exploit version check; **default credentials** — iDRAC 6/7/8 " +
		"ships root/calvin, iLO ships Administrator/<serial>, Supermicro " +
		"ships ADMIN/ADMIN, many IMM/XCC ship USERID/PASSW0RD.\n\n" +
		"Decodes:\n\n" +
		"- **RMCP header**: version (validated as 0x06) + reserved + " +
		"sequence + message class (0x07=IPMI / 0x06=ASF).\n" +
		"- **IPMI 1.5 session header**: auth_type (None / MD2 / MD5 / " +
		"Password / OEM) + session_seq + session_id (4-byte LE each) + " +
		"optional 16-byte auth_code when auth_type != 0 + " +
		"message_length.\n" +
		"- **IPMI 2.0 / RMCP+ session header**: auth_type=0x06 + " +
		"payload_type byte (encrypted bit + authenticated bit + 6-bit " +
		"payload type: 0x00=IPMI / 0x10=Open Session Request / " +
		"0x11=Open Session Response / 0x12=RAKP-1 / 0x13=RAKP-2 / " +
		"0x14=RAKP-3 / 0x15=RAKP-4) + session_id + session_seq + " +
		"payload_length (2-byte LE).\n" +
		"- **IPMI message**: rsAddr (target address, 0x20=BMC) + " +
		"netFn/rsLUN (upper 6 bits netFn + lower 2 rsLUN) + checksum1 + " +
		"rqAddr (source) + rqSeq/rqLUN + command + data + checksum2.\n" +
		"- **NetFn + command name table**: NetFn 0x06 App (Get Device ID " +
		"0x01 / Get System GUID 0x06 / Get Channel Auth Capabilities 0x38 " +
		"/ Get Session Challenge 0x39 / Activate Session 0x3A / Close " +
		"Session 0x3C / Get Channel Cipher Suites 0x54); NetFn 0x0A " +
		"Storage (Get SEL Info 0x44).\n" +
		"- **Security classification**: is_auth_probe (cmd 0x38 — THE " +
		"IPMI recon command); is_version_probe (cmd 0x01 — firmware " +
		"fingerprint); is_rakp_exchange (payload_type 0x12-0x15 — offline " +
		"hash capture window); is_cipher_suite_zero (cmd 0x54 — " +
		"CVE-2013-4786 no-auth enumeration).\n\n" +
		"Pure offline parser — paste IPMI/RMCP bytes (UDP/623 payload hex " +
		"from tcpdump / Wireshark IPMI dissector) and get per-message " +
		"breakdown.\n\n" +
		"Out of scope: response parsing (command-specific body formats); " +
		"payload decryption (AES-CBC-128 / xRC4 encrypted RMCP+ payloads " +
		"surfaced as byte counts only); RAKP hash extraction (HMAC-SHA1 " +
		"material in RAKP-2 identified but not extracted — use hashcat " +
		"mode 7300 on the raw capture); ASF Presence Ping/Pong (class " +
		"0x06 surfaced as class_name only); Serial-over-LAN (payload " +
		"type 0x01, complex framing).\n\n" +
		"Source: gap analysis (critical datacenter BMC surface — canonical " +
		"IPMI pentest dissector for Get Channel Auth Capabilities recon + " +
		"RAKP-2 offline hash capture + cipher suite 0 no-auth detection + " +
		"firmware version fingerprint). Wrap-vs-native: native — RMCP " +
		"(ASF 2.0) and IPMI v1.5/v2.0 specifications are publicly " +
		"available; fixed binary header formats with LE integers; no " +
		"crypto at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"IPMI/RMCP datagram bytes as hex (the UDP/623 payload). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ipmiDecodeHandler,
}

func ipmiDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("ipmi_decode: 'hex' is required")
	}
	res, err := ipmi.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("ipmi_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
