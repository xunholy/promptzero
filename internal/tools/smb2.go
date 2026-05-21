// smb2.go — host-side SMB2 / SMB3 message decoder Spec. Wraps
// the internal/smb2 walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/smb2"
)

func init() { //nolint:gochecknoinits
	Register(smb2DecodeSpec)
}

var smb2DecodeSpec = Spec{
	Name: "smb2_decode",
	Description: "Decode an SMB2 / SMB3 (Server Message Block v2/v3) message " +
		"per Microsoft Open Specifications [MS-SMB2] — the canonical " +
		"Windows file-share and lateral-movement protocol. Runs over " +
		"TCP/445 (direct host) + TCP/139 (NetBIOS Session Service " +
		"framing). The lateral-movement decoder for every Windows " +
		"pentest engagement; the wire format leaks: **NTLM-relay " +
		"vulnerability** (NEGOTIATE_RESPONSE SecurityMode without " +
		"SIGNING_REQUIRED = relay-vulnerable; impacket ntlmrelayx -t " +
		"smb://target); **SMB1 fallback / EternalBlue candidates** " +
		"(NEGOTIATE_REQUEST dialect 0x02FF wildcard advertises SMB1 " +
		"capability — servers responding to SMB1 are MS17-010 " +
		"EternalBlue / WannaCry candidates); **admin-share access** " +
		"(TREE_CONNECT \\\\<host>\\ADMIN$ / \\\\<host>\\C$ / \\\\<host>" +
		"\\IPC$); **named-pipe lateral-movement vectors** (CREATE " +
		"\\pipe\\spoolss = PrintNightmare CVE-2021-1675/34527, " +
		"\\pipe\\netlogon = ZeroLogon CVE-2020-1472, \\pipe\\lsarpc = " +
		"LSA-policy / SAM secrets dump, \\pipe\\samr = AD account " +
		"enumeration, \\pipe\\srvsvc = NetSessionEnum); **authentication " +
		"feedback** (SESSION_SETUP_RESPONSE STATUS_LOGON_FAILURE " +
		"0xC000006D / STATUS_WRONG_PASSWORD 0xC000006A / STATUS_" +
		"ACCOUNT_LOCKED_OUT 0xC0000234 / STATUS_PASSWORD_EXPIRED " +
		"0xC0000071 = password-spray feedback consumed by cme + " +
		"kerbrute; STATUS_MORE_PROCESSING_REQUIRED 0xC0000016 = multi-" +
		"step NTLMSSP / Kerberos); **server/client GUID disclosure** " +
		"(stable endpoint fingerprint). Decodes:\n\n" +
		"- **64-byte SMB2 header** ([MS-SMB2] §2.2.1): ProtocolId " +
		"discriminator (`0xFE` 'S' 'M' 'B' Sync or `0xFD` 'S' 'M' 'B' " +
		"Encrypted Transform Header surfaced as `transform_header_" +
		"present` flag); Command (2) / Flags (4 incl. " +
		"`SMB2_FLAGS_SERVER_TO_REDIR` 0x01 response indicator, " +
		"`SMB2_FLAGS_ASYNC_COMMAND` 0x02, `SMB2_FLAGS_RELATED_OPS` " +
		"0x04 compound chain, `SMB2_FLAGS_SIGNED` 0x08) / NextCommand " +
		"/ MessageId / TreeId / SessionId / Signature.\n" +
		"- **19-entry command name table** (§2.2.1.2): NEGOTIATE / " +
		"SESSION_SETUP / LOGOFF / TREE_CONNECT / TREE_DISCONNECT / " +
		"CREATE / CLOSE / FLUSH / READ / WRITE / LOCK / IOCTL / CANCEL " +
		"/ ECHO / QUERY_DIRECTORY / CHANGE_NOTIFY / QUERY_INFO / " +
		"SET_INFO / OPLOCK_BREAK.\n" +
		"- **6-entry SMB2 dialect name table** (§2.2.3): 0x0202 SMB " +
		"2.0.2 / 0x0210 SMB 2.1 / 0x0300 SMB 3.0 / 0x0302 SMB 3.0.2 / " +
		"0x0311 SMB 3.1.1 / 0x02FF SMB2 wildcard (SMB1 also offered — " +
		"EternalBlue candidate indicator!).\n" +
		"- **NEGOTIATE_REQUEST body** (§2.2.3): DialectCount + " +
		"SecurityMode + Dialects[] walker. Surfaces `dialects` + " +
		"`dialect_names` + `signing_enabled` + `signing_required` + " +
		"`smb1_offered` (presence of 0x02FF wildcard).\n" +
		"- **NEGOTIATE_RESPONSE body** (§2.2.4): SecurityMode + " +
		"DialectRevision + SecurityBufferLength. Surfaces " +
		"`dialect_chosen` + `dialect_chosen_name` + `signing_required` " +
		"+ `signing_enabled` + `security_buffer_bytes` (length of " +
		"GSS-API / SPNEGO blob).\n" +
		"- **TREE_CONNECT_REQUEST body** (§2.2.9): UNC path (UTF-16LE) " +
		"surfaced as `tree_connect_path`.\n" +
		"- **CREATE_REQUEST body** (§2.2.13): file/pipe name (UTF-16LE) " +
		"surfaced as `create_name`.\n" +
		"- **15-entry NTSTATUS name table** ([MS-ERREF] §2.3): " +
		"STATUS_SUCCESS / STATUS_PENDING (async) / STATUS_MORE_PROC" +
		"ESSING_REQUIRED (multi-step auth) / STATUS_ACCESS_DENIED / " +
		"STATUS_OBJECT_NAME_NOT_FOUND / STATUS_PRIVILEGE_NOT_HELD / " +
		"STATUS_WRONG_PASSWORD / STATUS_LOGON_FAILURE (password-spray " +
		"feedback!) / STATUS_PASSWORD_EXPIRED / STATUS_INVALID_IMAGE_" +
		"FORMAT / STATUS_NOT_SUPPORTED / STATUS_NETWORK_NAME_DELETED " +
		"/ STATUS_FILE_CLOSED / STATUS_INSUFF_SERVER_RESOURCES / " +
		"STATUS_ACCOUNT_LOCKED_OUT.\n\n" +
		"Pure offline parser — operators paste SMB2 bytes (the TCP " +
		"segment payload as hex; default ports TCP/445 + TCP/139 NBSS) " +
		"from a `tcpdump -X port 445` line or a Wireshark SMB2 " +
		"dissector view and get the documented per-command breakdown.\n\n" +
		"Out of scope (deferred): NetBIOS Session Service framing (when " +
		"riding TCP/139, each PDU has a 4-byte NBSS header type=0x00 " +
		"SESSION_MESSAGE — strip first; TCP/445 has no NBSS prefix); " +
		"NTLMSSP / Kerberos inner blob (SESSION_SETUP_REQUEST carries " +
		"SPNEGO-wrapped NTLM NEGOTIATE/CHALLENGE/AUTHENTICATE OR " +
		"Kerberos AP-REQ; already handled by `ntlm_decode` and " +
		"`kerberos_decode` — surfaced here as `security_buffer_bytes` " +
		"length only); compound message chain (NextCommand pointer " +
		"chains multiple commands — decoder reports first only); SMB3 " +
		"encryption Transform header (`0xFD` 'S' 'M' 'B' — §2.2.41 — " +
		"surfaced as `transform_header_present` flag only; encrypted " +
		"payload opaque without session key); per-command body decode " +
		"beyond NEGOTIATE / TREE_CONNECT / CREATE / SESSION_SETUP " +
		"(READ/WRITE/IOCTL/QUERY_INFO bodies surfaced as header fields " +
		"only); lease + durable + persistent handle state.\n\n" +
		"Source: docs/catalog/gap-analysis.md (Windows-protocol " +
		"foundational decoder — lateral-movement dissector that pairs " +
		"with kerberos_decode + ldap_decode + ntlm_decode for the " +
		"complete AD-pentest dissector quartet; canonical decode for " +
		"Windows Server / SMB-on-Linux Samba / macOS SMB / NetApp / " +
		"EMC Isilon / Synology SMB servers; common in DEF CON + Black " +
		"Hat + HITB + OffSec internal red-team engagements + every " +
		"impacket / cme / kerbrute-driven lateral-movement workflow). " +
		"Wrap-vs-native: native — MS-SMB2 is publicly documented; the " +
		"SMB2 header is a fixed-shape 64-byte struct, little-endian " +
		"throughout (unlike most network protocols which are BE); per-" +
		"command body decoding for NEGOTIATE / TREE_CONNECT / CREATE / " +
		"SESSION_SETUP is straightforward; no crypto at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"SMB2 message bytes as hex (the TCP-segment payload; default ports TCP/445 + TCP/139 NBSS). For TCP/139 strip the 4-byte NBSS header first. Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   smb2DecodeHandler,
}

func smb2DecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("smb2_decode: 'hex' is required")
	}
	res, err := smb2.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("smb2_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
