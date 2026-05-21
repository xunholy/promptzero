// Package smb2 decodes SMB2 / SMB3 (Server Message Block v2/v3)
// messages per [MS-SMB2] — the canonical Windows file-share and
// lateral-movement protocol. Runs over TCP/445 (direct host) +
// TCP/139 (NetBIOS Session Service framing).
//
// Operationally, SMB2 is the **lateral-movement decoder** for
// every Windows pentest engagement. The wire format leaks:
//
//   - **NTLM-relay vulnerability** — `NEGOTIATE_RESPONSE.
//     SecurityMode` carries `SMB2_NEGOTIATE_SIGNING_ENABLED`
//     (0x01) and `SMB2_NEGOTIATE_SIGNING_REQUIRED` (0x02).
//     **When `SIGNING_REQUIRED` is NOT set, the server is
//     vulnerable to NTLM relay attacks** (impacket
//     `ntlmrelayx -t smb://target`). The decoder surfaces a
//     `signing_required` boolean; canonical hardening audit
//     primitive.
//
//   - **SMB1 fallback / dialect downgrade** —
//     NEGOTIATE_REQUEST dialect list often contains `0x0202`
//     (SMB 2.0.2 — the lowest SMB2 dialect) alongside the
//     wildcard `0x02FF` (`SMB2 ???`) indicator that the
//     client also speaks SMB1. **Servers that respond to
//     SMB1 are EternalBlue / WannaCry candidates** (MS17-010
//     — patched 2017 but lab + legacy environments still
//     run unpatched). The decoder enumerates the offered
//     dialects with name strings; presence of `0x02FF`
//     flags the SMB1 advertise.
//
//   - **Admin share access** — TREE_CONNECT_REQUEST carries
//     the UNC path being mounted. Paths matching
//     `\\<host>\ADMIN$` (Windows administrative root share),
//     `\\<host>\C$` (full filesystem), `\\<host>\IPC$`
//     (inter-process — required for MS-RPC over named
//     pipes), or `\\<host>\<share>$` (any `$`-suffixed admin
//     share) indicate privileged operations. The decoder
//     surfaces `tree_connect_path`.
//
//   - **Named-pipe lateral-movement vectors** —
//     CREATE_REQUEST opens a file or named pipe under the
//     mounted tree. Pipe paths reveal the attack: `\pipe\
//     spoolss` = PrintNightmare (CVE-2021-1675 /
//     CVE-2021-34527 — abused for SYSTEM RCE on print
//     spooler); `\pipe\netlogon` = ZeroLogon (CVE-2020-1472
//     — DC password reset); `\pipe\lsarpc` = LSA-policy
//     access (used for SAM secrets dump via
//     `lsadump::secrets`); `\pipe\samr` = AD account
//     enumeration (`net user /domain` equivalent via
//     MS-RPC); `\pipe\srvsvc` = Server Service (NetSessionEnum
//     for session enum). The decoder surfaces `create_name`.
//
//   - **Authentication failure feedback** —
//     SESSION_SETUP_RESPONSE returns Status =
//     `STATUS_LOGON_FAILURE` (0xC000006D),
//     `STATUS_WRONG_PASSWORD` (0xC000006A),
//     `STATUS_ACCOUNT_LOCKED_OUT` (0xC0000234), or
//     `STATUS_PASSWORD_EXPIRED` (0xC0000071) on bad creds.
//     Password-spray tools (cme, kerbrute) consume these
//     directly. `STATUS_MORE_PROCESSING_REQUIRED`
//     (0xC0000016) indicates a multi-step NTLMSSP /
//     Kerberos exchange — keep reading. The decoder surfaces
//     `status` + `status_name`.
//
//   - **Server / Client GUID disclosure** — NEGOTIATE
//     request + response carry a 16-byte GUID identifying
//     the SMB endpoint. Combined with the SessionId, this
//     is a stable fingerprint for tracking which client
//     authenticated as which user.
//
// Wrap-vs-native judgement
//
//	Native. MS-SMB2 is publicly documented (Microsoft Open
//	Specifications); the SMB2 header is a fixed-shape 64-byte
//	struct, little-endian throughout (unlike most network
//	protocols which are BE). Per-command body decoding for
//	NEGOTIATE / TREE_CONNECT / CREATE / SESSION_SETUP is
//	straightforward; the remaining commands surface header
//	fields only (sufficient for command-flow analysis). NTLM
//	+ Kerberos inner blobs are already handled by
//	`ntlm_decode` + `kerberos_decode`. Compound-message
//	chains, SMB3 encryption transform header, and lease /
//	durable-handle state are out of scope.
//
// What this package covers
//
//   - **64-byte SMB2 header** ([MS-SMB2] §2.2.1): ProtocolId
//     0xFE 'S' 'M' 'B' (Sync) or 0xFD 'S' 'M' 'B' (Encrypted
//     — Transform Header, surfaced as type-flag only) /
//     StructureSize=64 / CreditCharge / Status (response) or
//     ChannelSequence+Reserved (request) / Command (2) /
//     CreditRequest|Response (2) / Flags (4) (incl.
//     `SMB2_FLAGS_SERVER_TO_REDIR` 0x01 = response indicator,
//     `SMB2_FLAGS_ASYNC_COMMAND` 0x02, `SMB2_FLAGS_RELATED_
//     OPERATIONS` 0x04 = compound chain, `SMB2_FLAGS_SIGNED`
//     0x08, `SMB2_FLAGS_PRIORITY_MASK` 0x70,
//     `SMB2_FLAGS_DFS_OPERATIONS` 0x10000000,
//     `SMB2_FLAGS_REPLAY_OPERATION` 0x20000000) / NextCommand
//     (4) / MessageId (8) / AsyncId|(Reserved+TreeId) (8) /
//     SessionId (8) / Signature (16).
//
//   - **19-entry command name table** ([MS-SMB2] §2.2.1.2):
//     0x00 NEGOTIATE / 0x01 SESSION_SETUP / 0x02 LOGOFF /
//     0x03 TREE_CONNECT / 0x04 TREE_DISCONNECT / 0x05 CREATE
//     / 0x06 CLOSE / 0x07 FLUSH / 0x08 READ / 0x09 WRITE /
//     0x0A LOCK / 0x0B IOCTL / 0x0C CANCEL / 0x0D ECHO /
//     0x0E QUERY_DIRECTORY / 0x0F CHANGE_NOTIFY / 0x10
//     QUERY_INFO / 0x11 SET_INFO / 0x12 OPLOCK_BREAK.
//
//   - **6-entry SMB2 dialect name table** ([MS-SMB2]
//     §2.2.3): 0x0202 SMB 2.0.2 / 0x0210 SMB 2.1 / 0x0300
//     SMB 3.0 / 0x0302 SMB 3.0.2 / 0x0311 SMB 3.1.1 / 0x02FF
//     SMB2 wildcard (client advertises SMB1 capability —
//     EternalBlue candidate indicator!).
//
//   - **NEGOTIATE_REQUEST body** (§2.2.3): DialectCount (2)
//     / SecurityMode (2) / Reserved (2) / Capabilities (4)
//     / ClientGuid (16) / ClientStartTime|NegotiateContext
//     OPTIONAL (8) / Dialects[DialectCount] (2 each).
//     Surfaces `dialects` + `dialect_names` + `security_mode`
//
//   - `signing_required` + `signing_enabled` +
//     `smb1_offered` (presence of 0x02FF).
//
//   - **NEGOTIATE_RESPONSE body** (§2.2.4): StructureSize (2)
//     / SecurityMode (2) / DialectRevision (2) /
//     NegotiateContextCount|Reserved (2) / ServerGuid (16) /
//     Capabilities (4) / MaxTransactSize (4) / MaxReadSize
//     (4) / MaxWriteSize (4) / SystemTime (8) / ServerStart
//     Time (8) / SecurityBufferOffset (2) / SecurityBuffer
//     Length (2) / NegotiateContextOffset|Reserved2 (4) /
//     Buffer[]. Surfaces `dialect_chosen` + `dialect_chosen_
//     name` + `signing_required` + `signing_enabled` +
//     `security_buffer_bytes` (length of GSS-API / SPNEGO
//     blob).
//
//   - **TREE_CONNECT_REQUEST body** (§2.2.9):
//     StructureSize=9 / Flags|Reserved (2) / PathOffset (2)
//     / PathLength (2) / Buffer[] (UNC path UTF-16LE).
//     Surfaces `tree_connect_path` (decoded UTF-16LE; e.g.
//     `\\dc01\ADMIN$`).
//
//   - **CREATE_REQUEST body** (§2.2.13): StructureSize=57 /
//     SecurityFlags / RequestedOplockLevel / ImpersonationL
//     evel / SmbCreateFlags / Reserved / DesiredAccess /
//     FileAttributes / ShareAccess / CreateDisposition /
//     CreateOptions / NameOffset / NameLength / Create
//     ContextsOffset / CreateContextsLength / Buffer[] (file
//     name UTF-16LE). Surfaces `create_name` (decoded
//     UTF-16LE; e.g. `pipe\spoolss`).
//
//   - **15-entry NTSTATUS name table** ([MS-ERREF] §2.3):
//     0x00000000 STATUS_SUCCESS / 0x00000103 STATUS_PENDING
//     (async I/O in progress) / 0xC0000016 STATUS_MORE_PROC
//     ESSING_REQUIRED (multi-step NTLMSSP/Kerberos — keep
//     reading) / 0xC0000022 STATUS_ACCESS_DENIED / 0xC0000034
//     STATUS_OBJECT_NAME_NOT_FOUND / 0xC0000061 STATUS_PRIV
//     ILEGE_NOT_HELD / 0xC000006A STATUS_WRONG_PASSWORD /
//     0xC000006D STATUS_LOGON_FAILURE (canonical bad-creds
//     response — password-spray feedback!) / 0xC0000071
//     STATUS_PASSWORD_EXPIRED / 0xC000007B STATUS_INVALID_I
//     MAGE_FORMAT / 0xC00000BB STATUS_NOT_SUPPORTED /
//     0xC00000C9 STATUS_NETWORK_NAME_DELETED / 0xC0000128
//     STATUS_FILE_CLOSED / 0xC0000205 STATUS_INSUFF_SERVER
//     _RESOURCES / 0xC0000234 STATUS_ACCOUNT_LOCKED_OUT.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **NetBIOS Session Service framing** — when SMB2 rides
//     over TCP/139 (NBSS), each PDU is prefixed with a 4-byte
//     NBSS header (type=0x00 SESSION_MESSAGE, flags=0x00,
//     length 17-bit BE). Strip the 4-byte NBSS header before
//     feeding the decoder. TCP/445 has no NBSS prefix.
//   - **NTLMSSP / Kerberos inner blob** — SESSION_SETUP_
//     REQUEST carries the security-mechanism blob in the
//     SecurityBuffer (typically SPNEGO-wrapped NTLM
//     NEGOTIATE / CHALLENGE / AUTHENTICATE OR Kerberos
//     AP-REQ). Already handled by `ntlm_decode` and
//     `kerberos_decode` — surfaced here as
//     `security_buffer_bytes` length only.
//   - **Compound message chain** — NextCommand pointer
//     chains multiple SMB2 commands in one packet; the
//     decoder reports the first command only.
//   - **SMB3 encryption Transform header** (0xFD 'S' 'M'
//     'B' — [MS-SMB2] §2.2.41) — surfaced as
//     `transform_header_present` flag only; the encrypted
//     payload is opaque without the session key.
//   - **Per-command body decode beyond NEGOTIATE /
//     TREE_CONNECT / CREATE** — READ / WRITE / IOCTL /
//     QUERY_INFO bodies surfaced as header fields only.
//   - **Lease / durable / persistent handle state** — out
//     of scope for the dissector pass.
package smb2

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf16"
)

const headerSize = 64

// Result is the structured decode of an SMB2 message.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	TransformHeaderPresent bool `json:"transform_header_present"`

	StructureSize int    `json:"structure_size,omitempty"`
	Command       int    `json:"command,omitempty"`
	CommandName   string `json:"command_name,omitempty"`
	Flags         uint32 `json:"flags,omitempty"`
	IsResponse    bool   `json:"is_response"`
	IsAsync       bool   `json:"is_async"`
	IsCompound    bool   `json:"is_compound"`
	IsSigned      bool   `json:"is_signed"`
	NextCommand   uint32 `json:"next_command,omitempty"`
	MessageID     uint64 `json:"message_id,omitempty"`
	SessionID     uint64 `json:"session_id,omitempty"`
	TreeID        uint32 `json:"tree_id,omitempty"`

	Status     uint32 `json:"status,omitempty"`
	StatusName string `json:"status_name,omitempty"`

	// NEGOTIATE
	Dialects            []uint16 `json:"dialects,omitempty"`
	DialectNames        []string `json:"dialect_names,omitempty"`
	DialectChosen       uint16   `json:"dialect_chosen,omitempty"`
	DialectChosenName   string   `json:"dialect_chosen_name,omitempty"`
	SecurityMode        uint16   `json:"security_mode,omitempty"`
	SigningEnabled      bool     `json:"signing_enabled"`
	SigningRequired     bool     `json:"signing_required"`
	SMB1Offered         bool     `json:"smb1_offered"`
	SecurityBufferBytes int      `json:"security_buffer_bytes,omitempty"`

	// TREE_CONNECT
	TreeConnectPath string `json:"tree_connect_path,omitempty"`

	// CREATE
	CreateName string `json:"create_name,omitempty"`
}

// Decode parses an SMB2 message from a hex string.
func Decode(hexStr string) (*Result, error) {
	clean := stripSeparators(hexStr)
	if len(clean) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("odd-length hex (%d nibbles)", len(clean))
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	if len(b) < 4 {
		return nil, fmt.Errorf("smb2 message truncated (%d bytes)", len(b))
	}

	r := &Result{TotalBytes: len(b)}

	// ProtocolId discriminator
	switch {
	case b[0] == 0xFD && b[1] == 'S' && b[2] == 'M' && b[3] == 'B':
		r.TransformHeaderPresent = true
		return r, nil
	case b[0] == 0xFE && b[1] == 'S' && b[2] == 'M' && b[3] == 'B':
		// sync header — fall through
	default:
		return r, fmt.Errorf("not an SMB2 message (ProtocolId 0x%02X%02X%02X%02X)",
			b[0], b[1], b[2], b[3])
	}

	if len(b) < headerSize {
		return r, fmt.Errorf("smb2 header truncated (%d bytes; need 64)", len(b))
	}

	r.StructureSize = int(binary.LittleEndian.Uint16(b[4:6]))
	// Status / ChannelSequence direction — disambiguated by
	// the response flag later. We read Status into the
	// uint32 unconditionally; for requests it's
	// (ChannelSequence | Reserved<<16) which is informational.
	r.Status = binary.LittleEndian.Uint32(b[8:12])
	r.Command = int(binary.LittleEndian.Uint16(b[12:14]))
	r.CommandName = commandName(r.Command)
	r.Flags = binary.LittleEndian.Uint32(b[16:20])
	r.IsResponse = (r.Flags & 0x01) != 0
	r.IsAsync = (r.Flags & 0x02) != 0
	r.IsCompound = (r.Flags & 0x04) != 0
	r.IsSigned = (r.Flags & 0x08) != 0
	r.NextCommand = binary.LittleEndian.Uint32(b[20:24])
	r.MessageID = binary.LittleEndian.Uint64(b[24:32])
	if r.IsAsync {
		// AsyncId at offset 32, 8 bytes — informational; skip
	} else {
		// Reserved (4) + TreeId (4) at 32..40
		r.TreeID = binary.LittleEndian.Uint32(b[36:40])
	}
	r.SessionID = binary.LittleEndian.Uint64(b[40:48])
	if r.IsResponse {
		r.StatusName = statusName(r.Status)
	}

	body := b[headerSize:]
	switch r.Command {
	case 0x00:
		if r.IsResponse {
			decodeNegotiateResponse(r, body)
		} else {
			decodeNegotiateRequest(r, body)
		}
	case 0x03:
		if !r.IsResponse {
			decodeTreeConnectRequest(r, body, b)
		}
	case 0x05:
		if !r.IsResponse {
			decodeCreateRequest(r, body, b)
		}
	}
	return r, nil
}

func decodeNegotiateRequest(r *Result, body []byte) {
	if len(body) < 36 {
		return
	}
	dialectCount := int(binary.LittleEndian.Uint16(body[2:4]))
	r.SecurityMode = binary.LittleEndian.Uint16(body[4:6])
	r.SigningEnabled = (r.SecurityMode & 0x01) != 0
	r.SigningRequired = (r.SecurityMode & 0x02) != 0
	// Dialects begin at body[36], 2 bytes each.
	dStart := 36
	for i := 0; i < dialectCount; i++ {
		off := dStart + i*2
		if off+2 > len(body) {
			break
		}
		d := binary.LittleEndian.Uint16(body[off : off+2])
		r.Dialects = append(r.Dialects, d)
		r.DialectNames = append(r.DialectNames, dialectName(d))
		if d == 0x02FF {
			r.SMB1Offered = true
		}
	}
}

func decodeNegotiateResponse(r *Result, body []byte) {
	if len(body) < 64 {
		return
	}
	r.SecurityMode = binary.LittleEndian.Uint16(body[2:4])
	r.SigningEnabled = (r.SecurityMode & 0x01) != 0
	r.SigningRequired = (r.SecurityMode & 0x02) != 0
	r.DialectChosen = binary.LittleEndian.Uint16(body[4:6])
	r.DialectChosenName = dialectName(r.DialectChosen)
	// SecurityBufferOffset (2) at body[56], SecurityBufferLength
	// (2) at body[58].
	r.SecurityBufferBytes = int(binary.LittleEndian.Uint16(body[58:60]))
}

func decodeTreeConnectRequest(r *Result, body []byte, full []byte) {
	if len(body) < 8 {
		return
	}
	pathOffset := int(binary.LittleEndian.Uint16(body[4:6]))
	pathLength := int(binary.LittleEndian.Uint16(body[6:8]))
	if pathOffset < headerSize || pathOffset+pathLength > len(full) {
		return
	}
	r.TreeConnectPath = decodeUTF16LE(full[pathOffset : pathOffset+pathLength])
}

func decodeCreateRequest(r *Result, body []byte, full []byte) {
	if len(body) < 56 {
		return
	}
	nameOffset := int(binary.LittleEndian.Uint16(body[44:46]))
	nameLength := int(binary.LittleEndian.Uint16(body[46:48]))
	if nameOffset < headerSize || nameOffset+nameLength > len(full) {
		return
	}
	r.CreateName = decodeUTF16LE(full[nameOffset : nameOffset+nameLength])
}

func decodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u16 := make([]uint16, 0, len(b)/2)
	for i := 0; i < len(b); i += 2 {
		u16 = append(u16, binary.LittleEndian.Uint16(b[i:i+2]))
	}
	return string(utf16.Decode(u16))
}

func commandName(c int) string {
	switch c {
	case 0x00:
		return "NEGOTIATE"
	case 0x01:
		return "SESSION_SETUP"
	case 0x02:
		return "LOGOFF"
	case 0x03:
		return "TREE_CONNECT"
	case 0x04:
		return "TREE_DISCONNECT"
	case 0x05:
		return "CREATE"
	case 0x06:
		return "CLOSE"
	case 0x07:
		return "FLUSH"
	case 0x08:
		return "READ"
	case 0x09:
		return "WRITE"
	case 0x0A:
		return "LOCK"
	case 0x0B:
		return "IOCTL"
	case 0x0C:
		return "CANCEL"
	case 0x0D:
		return "ECHO"
	case 0x0E:
		return "QUERY_DIRECTORY"
	case 0x0F:
		return "CHANGE_NOTIFY"
	case 0x10:
		return "QUERY_INFO"
	case 0x11:
		return "SET_INFO"
	case 0x12:
		return "OPLOCK_BREAK"
	}
	return fmt.Sprintf("uncatalogued command 0x%02X", c)
}

func dialectName(d uint16) string {
	switch d {
	case 0x0202:
		return "SMB 2.0.2"
	case 0x0210:
		return "SMB 2.1"
	case 0x0300:
		return "SMB 3.0"
	case 0x0302:
		return "SMB 3.0.2"
	case 0x0311:
		return "SMB 3.1.1"
	case 0x02FF:
		return "SMB2 wildcard (SMB1 also offered — EternalBlue candidate)"
	}
	return fmt.Sprintf("uncatalogued dialect 0x%04X", d)
}

func statusName(s uint32) string {
	switch s {
	case 0x00000000:
		return "STATUS_SUCCESS"
	case 0x00000103:
		return "STATUS_PENDING"
	case 0xC0000016:
		return "STATUS_MORE_PROCESSING_REQUIRED"
	case 0xC0000022:
		return "STATUS_ACCESS_DENIED"
	case 0xC0000034:
		return "STATUS_OBJECT_NAME_NOT_FOUND"
	case 0xC0000061:
		return "STATUS_PRIVILEGE_NOT_HELD"
	case 0xC000006A:
		return "STATUS_WRONG_PASSWORD"
	case 0xC000006D:
		return "STATUS_LOGON_FAILURE"
	case 0xC0000071:
		return "STATUS_PASSWORD_EXPIRED"
	case 0xC000007B:
		return "STATUS_INVALID_IMAGE_FORMAT"
	case 0xC00000BB:
		return "STATUS_NOT_SUPPORTED"
	case 0xC00000C9:
		return "STATUS_NETWORK_NAME_DELETED"
	case 0xC0000128:
		return "STATUS_FILE_CLOSED"
	case 0xC0000205:
		return "STATUS_INSUFF_SERVER_RESOURCES"
	case 0xC0000234:
		return "STATUS_ACCOUNT_LOCKED_OUT"
	}
	return fmt.Sprintf("uncatalogued NTSTATUS 0x%08X", s)
}

func stripSeparators(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for _, r := range s {
		switch r {
		case ' ', '\t', '\n', '\r', ':', '-', '_':
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
