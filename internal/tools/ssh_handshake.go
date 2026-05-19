// ssh_handshake.go — host-side SSH wire-protocol dissector
// Spec, delegating to the internal/sshdecode package for the
// walker proper.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/sshdecode"
)

func init() { //nolint:gochecknoinits
	Register(sshHandshakeDecodeSpec)
}

var sshHandshakeDecodeSpec = Spec{
	Name: "ssh_handshake_decode",
	Description: "Decode the cleartext portions of an SSH session — the version-exchange " +
		"banner and the SSH_MSG_KEXINIT message that lists the algorithms each peer " +
		"supports. Per RFC 4253 (Transport Layer Protocol) + RFC 4250-4256. The SSH " +
		"counterpart to tls_handshake_decode: HASSH / HASSHServer fingerprints " +
		"(Salesforce, ben-aaron-bowers, 2018) identify SSH client / server stacks the " +
		"same way JA3 / JA3S identifies TLS clients/servers. Decodes:\n\n" +
		"- **Version exchange line** (RFC 4253 §4.2): `SSH-protoversion-softwareversion " +
		"[SP comment]` — broken out into protocol version (1.x / 1.99 / 2.0), software " +
		"version (OpenSSH_8.9p1 / dropbear_2022.83 / libssh2_1.10.0 / Cisco-1.25 / etc.), " +
		"and optional comment field.\n" +
		"- **Binary packet envelope** (RFC 4253 §6): `[packet_length:4][padding_length:1]" +
		"[payload][padding][MAC]`. Length validation against the buffer + minimum-size " +
		"checks per the spec.\n" +
		"- **Message type dispatch** (27-entry table from RFC 4250 §4.1.2): " +
		"DISCONNECT (1) / IGNORE (2) / UNIMPLEMENTED (3) / DEBUG (4) / SERVICE_REQUEST " +
		"(5) / SERVICE_ACCEPT (6) / EXT_INFO (7) / NEWCOMPRESS (8) / KEXINIT (20) / " +
		"NEWKEYS (21) / KEXDH_INIT (30) / KEXDH_REPLY (31) / USERAUTH_REQUEST (50) / " +
		"USERAUTH_FAILURE (51) / USERAUTH_SUCCESS (52) / USERAUTH_BANNER (53) / " +
		"USERAUTH_INFO_REQUEST (60) / USERAUTH_INFO_RESPONSE (61) / GLOBAL_REQUEST (80) " +
		"/ REQUEST_SUCCESS (81) / REQUEST_FAILURE (82) / CHANNEL_OPEN (90) / " +
		"CHANNEL_OPEN_CONFIRMATION (91) / CHANNEL_OPEN_FAILURE (92) / " +
		"CHANNEL_WINDOW_ADJUST (93) / CHANNEL_DATA (94) / CHANNEL_EXTENDED_DATA (95) / " +
		"CHANNEL_EOF (96) / CHANNEL_CLOSE (97) / CHANNEL_REQUEST (98) / CHANNEL_SUCCESS " +
		"(99) / CHANNEL_FAILURE (100).\n" +
		"- **SSH_MSG_KEXINIT decode** (RFC 4253 §7.1): 16-byte cookie + 10 SSH name-" +
		"lists (kex_algorithms / server_host_key_algorithms / encryption_algorithms_c2s " +
		"+ _s2c / mac_algorithms_c2s + _s2c / compression_algorithms_c2s + _s2c / " +
		"languages_c2s + _s2c) + first_kex_packet_follows + 4-byte reserved.\n" +
		"- **HASSH** fingerprint (per the Salesforce spec): the semicolon-separated " +
		"string `kex_algos;encryption_algos_c2s;mac_algos_c2s;compression_algos_c2s` " +
		"with comma-separated list elements, plus its MD5 hash. Identifies the SSH " +
		"client stack (OpenSSH version, PuTTY, libssh, JSch, ParamPro, etc.) across " +
		"thousands of distinct signatures.\n" +
		"- **HASSHServer** fingerprint: same string format but using server-side " +
		"(_s2c) lists. Identifies the SSH server stack.\n\n" +
		"Pure offline parser — operators paste either a banner line (from " +
		"`echo | nc host 22`, an nmap -sV scan, or a Wireshark Telnet-style view) or " +
		"a hex blob of the binary KEXINIT packet (from tshark `ssh.packet_length` " +
		"extraction or a tcpdump-of-22 capture) and inspect every field. Complements " +
		"tls_handshake_decode + ip_packet_decode for the full encrypted-transport " +
		"fingerprinting stack: JA3 for TLS clients, HASSH for SSH clients.\n\n" +
		"Out of scope (deferred to future iterations): encrypted body decode for post-" +
		"KEXINIT packets (USERAUTH_* / CHANNEL_* are sent over the encrypted session; " +
		"envelope is decoded but body is raw hex); SSH-1 protocol (deprecated since " +
		"~2006); JA4SSH (newer FoxIO scheme); host-key extraction from KEXDH_REPLY " +
		"(public-key blob surfaced as hex but not parsed into structured form).\n\n" +
		"Source: docs/catalog/gap-analysis.md (encrypted-transport fingerprinting " +
		"space). Wrap-vs-native: native — RFC 4253 + 4250-4256 are fully public, the " +
		"banner is plain ASCII, the binary packet is a fixed-format envelope + name-" +
		"list walker, HASSH is a documented MD5-of-semicolon-string algorithm.\n\n" +
		"Accepts ':' / '-' / '_' / whitespace separators (in hex input only) and a " +
		"leading '0x' prefix.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"input":{"type":"string","description":"Either an SSH version banner (line starting with 'SSH-') or a hex-encoded SSH binary packet ([packet_length:4][padding_length:1][payload][padding][MAC]). Auto-detected by the 'SSH-' prefix."}
		},
		"required":["input"]
	}`),
	Required:  []string{"input"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   sshHandshakeDecodeHandler,
}

func sshHandshakeDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "input")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("ssh_handshake_decode: 'input' is required")
	}
	res, err := sshdecode.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("ssh_handshake_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
