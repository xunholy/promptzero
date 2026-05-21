// rdpx224.go — host-side RDP initial-handshake decoder Spec.
// Wraps the internal/rdpx224 walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/rdpx224"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(rdpx224DecodeSpec)
}

var rdpx224DecodeSpec = Spec{
	Name: "rdp_x224_decode",
	Description: "Decode the initial-handshake frames of Microsoft RDP (Remote " +
		"Desktop Protocol) per [MS-RDPBCGR] — specifically the TPKT-" +
		"wrapped X.224 (COTP) Connection Request / Connection Confirm " +
		"PDUs plus the embedded RDP_NEG_REQ / RDP_NEG_RSP / " +
		"RDP_NEG_FAILURE structures. TCP/3389 default. The **universal " +
		"Windows pentest entry point** — every Windows Server + Windows " +
		"desktop deployment exposes 3389 at some layer (LAN, jump host, " +
		"Citrix gateway, Microsoft Remote Desktop Gateway, AWS " +
		"Workspaces, Azure Virtual Desktop). The X.224 + RDP_NEG_REQ " +
		"initial handshake completes within the first two TCP segments " +
		"— observing these reveals the username + security-posture " +
		"intent without ever needing to attempt authentication. The " +
		"wire format leaks: **username cleartext via RDP Cookie** " +
		"(`Cookie: mstshash=<username>\\r\\n` sent by mstsc.exe / " +
		"Remmina / FreeRDP / rdesktop / AWS Workspaces client / " +
		"Microsoft Remote Desktop for Mac — used historically by RD " +
		"Connection Broker for load balancing, still emitted by default; " +
		"observing one CR PDU enumerates an authenticated username " +
		"without sending credentials!); **routing token disclosure** " +
		"(alternative `Cookie: msts=<base64-token>\\r\\n` form carries " +
		"RD Connection Broker routing token); **NLA / CredSSP hardening " +
		"posture via requestedProtocols** (0x00 PROTOCOL_RDP = standard " +
		"RDP, no TLS, **vulnerable to passive MITM credential capture, " +
		"pre-Windows 2003**; 0x01 PROTOCOL_SSL = TLS 1.0+; 0x02 " +
		"PROTOCOL_HYBRID = CredSSP NLA — **modern hardened default**, " +
		"protects against CVE-2019-0708 BlueKeep + DejaBlue + credential-" +
		"relay attacks; 0x04 PROTOCOL_RDSTLS; 0x08 PROTOCOL_HYBRID_EX = " +
		"CredSSP + EarlyUserAuthorizationResult; 0x10 PROTOCOL_RDSAAD = " +
		"Microsoft Entra ID AAD); **server hardening enforcement via " +
		"NEG_FAILURE** (0x01 SSL_REQUIRED_BY_SERVER = TLS hardening; " +
		"0x05 HYBRID_REQUIRED_BY_SERVER = **canonical NLA-hardened " +
		"response** — CredSSP mandated, pre-auth credential check " +
		"enforced); **selected-protocol confirmation via NEG_RSP** " +
		"(selectedProtocol=0 on internet-reachable server = high-" +
		"severity BlueKeep candidate); **Restricted Admin Mode " +
		"detection** (NEG_REQ flags 0x01 = Windows 8.1+ RDP Restricted " +
		"Admin — login without sending creds to remote host, protects " +
		"against credential theft on compromised server but enables " +
		"PtH). Decodes:\n\n" +
		"- **4-byte TPKT header** (RFC 1006): version=3 / reserved / " +
		"length (BE — total including TPKT header).\n" +
		"- **X.224 COTP header** (ITU-T X.224 / RFC 905): LI length-" +
		"indicator / PDU-type+credit / dst-ref / src-ref / class+option.\n" +
		"- **5-entry X.224 PDU-type name table**: 0xE0 CR Connection " +
		"Request (client → server initial probe) / 0xD0 CC Connection " +
		"Confirm (server → client reply) / 0xF0 DT Data / 0x80 DR " +
		"Disconnect Request / 0x70 ER Error.\n" +
		"- **RDP Cookie extraction** — for CR PDUs walks the post-X.224-" +
		"header user data looking for `Cookie: ` prefix terminated by " +
		"`\\r\\n`. Extracts `mstshash_username` (cleartext!) or " +
		"`msts_routing_token` depending on cookie form.\n" +
		"- **RDP_NEG_REQ walker** ([MS-RDPBCGR] §2.2.1.1.1): type=0x01 " +
		"/ flags / length=8 / requestedProtocols (4 LE). Surfaces " +
		"`neg_req_requested_protocols` bitmask + " +
		"`neg_req_requested_protocols_names` array + `neg_req_flags` + " +
		"`neg_req_flags_names`.\n" +
		"- **6-entry requestedProtocols name table** with vulnerability " +
		"flagging: 0x00 PROTOCOL_RDP (standard — no TLS, vulnerable to " +
		"passive MITM!) / 0x01 PROTOCOL_SSL (TLS 1.0+) / 0x02 " +
		"PROTOCOL_HYBRID (CredSSP NLA — modern hardened default) / 0x04 " +
		"PROTOCOL_RDSTLS / 0x08 PROTOCOL_HYBRID_EX (CredSSP + " +
		"EarlyUserAuthorizationResult) / 0x10 PROTOCOL_RDSAAD " +
		"(Microsoft Entra ID AAD).\n" +
		"- **3-entry NEG_REQ flags name table**: 0x01 " +
		"RESTRICTED_ADMIN_MODE_REQUIRED / 0x02 " +
		"REDIRECTED_AUTHENTICATION_MODE_REQUIRED / 0x08 " +
		"CORRELATION_INFO_PRESENT.\n" +
		"- **RDP_NEG_RSP walker** ([MS-RDPBCGR] §2.2.1.2.1): type=0x02 " +
		"/ flags / length=8 / selectedProtocol. Surfaces " +
		"`neg_rsp_selected_protocol` + name + `neg_rsp_flags_names`.\n" +
		"- **3-entry NEG_RSP flags name table**: 0x01 " +
		"EXTENDED_CLIENT_DATA_SUPPORTED / 0x02 " +
		"DYNVC_GFX_PROTOCOL_SUPPORTED / 0x04 RDP_NEGRSP_RESERVED.\n" +
		"- **RDP_NEG_FAILURE walker** ([MS-RDPBCGR] §2.2.1.2.2): " +
		"type=0x03 / flags / length=8 / failureCode. Surfaces " +
		"`neg_failure_code` + name.\n" +
		"- **6-entry failureCode name table** with hardening-posture " +
		"flagging: 0x01 SSL_REQUIRED_BY_SERVER (hardening applied — " +
		"refuses standard RDP) / 0x02 SSL_NOT_ALLOWED_BY_SERVER (very " +
		"rare) / 0x03 SSL_CERT_NOT_ON_SERVER (TLS misconfig) / 0x04 " +
		"INCONSISTENT_FLAGS / 0x05 HYBRID_REQUIRED_BY_SERVER (canonical " +
		"NLA-hardened response — CredSSP mandated, pre-auth credential " +
		"check enforced) / 0x06 SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER.\n\n" +
		"Pure offline parser — operators paste RDP bytes (the TCP-" +
		"segment payload as hex; default TCP/3389) from a `tcpdump -X " +
		"port 3389` line or a Wireshark RDP dissector view and get the " +
		"documented per-PDU breakdown.\n\n" +
		"Out of scope (deferred): MCS Connect Initial / Connect Response " +
		"(GCC ConferenceCreateRequest payload with ClientCoreData / " +
		"ClientSecurityData / ClientNetworkData / ClientClusterData / " +
		"ClientMonitorData TLV blocks — large nested structures); " +
		"CredSSP TSRequest (TLS-wrapped CredSSP carries SPNEGO-wrapped " +
		"NTLM / Kerberos auth blobs — already handled by `ntlm_decode` " +
		"+ `kerberos_decode`); RDP Security Layer (Standard RDP Security " +
		"key exchange + per-frame encryption — legacy); RDP virtual " +
		"channels (RDPDR drive redirection / RDPSND audio / CLIPRDR " +
		"clipboard / RAIL RemoteApp / RemoteFX graphics codec / DYNVC " +
		"dynamic virtual channels); RDP licensing protocol (pre-session " +
		"licensing exchange with Terminal Server / RDS deployment); " +
		"FastPath input/output PDUs (alternative wire format skipping " +
		"TPKT + X.224 used post-handshake for keyboard/mouse input + " +
		"screen-update output); multi-segment fragmented X.224 data " +
		"(decoder handles single-segment CR / CC / DT / DR / ER PDUs " +
		"only); NeGEx2 / EAP-TTLS / SCard authentication variants.\n\n" +
		"Source: docs/catalog/gap-analysis.md (Windows-protocol " +
		"foundational decoder — canonical RDP pentest dissector for " +
		"username pre-auth enumeration + NLA hardening detection + " +
		"BlueKeep / DejaBlue candidate identification; pairs with the " +
		"AD-pentest quintet for the complete Windows-stack pentest " +
		"surface; common in DEF CON + Black Hat + HITB + OffSec " +
		"internal red-team engagements + every nmap rdp-* NSE / " +
		"metasploit auxiliary/scanner/rdp + impacket rdp_check / " +
		"crowbar rdesktop-guru / hydra rdp-driven RDP attack workflow). " +
		"Wrap-vs-native: native — TPKT + X.224 framing is RFC 1006 + " +
		"ITU-T X.224 (both publicly available); RDP_NEG_REQ / NEG_RSP " +
		"/ NEG_FAILURE are documented in [MS-RDPBCGR] §2.2.1 — fixed " +
		"8-byte structures with named flag bits; Cookie extraction is a " +
		"simple cstring-prefix walk; post-CC MCS + CredSSP + virtual " +
		"channels deliberately out of scope; for CredSSP the inner " +
		"NTLM/Kerberos is already handled by ntlm_decode + " +
		"kerberos_decode; no crypto at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"RDP initial-handshake PDU bytes as hex (the TCP-segment payload; default TCP/3389). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   rdpx224DecodeHandler,
}

func rdpx224DecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("rdp_x224_decode: 'hex' is required")
	}
	res, err := rdpx224.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("rdp_x224_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
