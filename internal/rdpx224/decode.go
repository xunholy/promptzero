// Package rdpx224 decodes the initial-handshake frames of
// Microsoft RDP (Remote Desktop Protocol) per [MS-RDPBCGR] —
// specifically the TPKT-wrapped X.224 (COTP) Connection
// Request / Connection Confirm PDUs plus the embedded
// RDP_NEG_REQ / RDP_NEG_RSP / RDP_NEG_FAILURE structures.
// Runs on TCP/3389 default.
//
// Operationally, RDP is the **universal Windows pentest entry
// point** — every Windows Server + Windows desktop deployment
// exposes 3389 at some layer (LAN, jump host, Citrix gateway,
// Microsoft Remote Desktop Gateway, AWS Workspaces, Azure
// Virtual Desktop). The X.224 + RDP_NEG_REQ initial handshake
// completes within the first two TCP segments — observing
// these reveals the username + security-posture intent
// without ever needing to attempt authentication. The wire
// format leaks:
//
//   - **Username cleartext via RDP Cookie** — Windows RDP
//     clients (mstsc.exe, Remmina, FreeRDP, rdesktop, AWS
//     Workspaces client, Microsoft Remote Desktop for Mac)
//     send a routing cookie immediately after the X.224
//     header in the Connection Request:
//     `Cookie: mstshash=<username>\r\n`. The `mstshash`
//     username is the canonical RDP pre-auth username
//     disclosure — used historically by RD Connection
//     Broker for load balancing, and still emitted by
//     default by mstsc.exe even when not routed via a
//     broker. **Observing one CR PDU enumerates an
//     authenticated username without sending any
//     credentials.**
//
//   - **Routing token disclosure** — alternative cookie
//     form `Cookie: msts=<base64-token>\r\n` carries an
//     RD Connection Broker routing token (load-balancer
//     hint identifying the back-end session host).
//
//   - **NLA / CredSSP hardening posture via requestedProtocols** —
//     RDP_NEG_REQ.requestedProtocols is a 4-byte LE
//     bitmask:
//
//   - `0x00000000` PROTOCOL_RDP — standard RDP
//     (legacy; **no TLS upgrade**; vulnerable to passive
//     MITM credential capture; pre-Windows 2003).
//
//   - `0x00000001` PROTOCOL_SSL — TLS 1.0+ (encryption
//     only; no NLA — credentials sent inside TLS but
//     after the channel is established).
//
//   - `0x00000002` PROTOCOL_HYBRID — CredSSP NLA
//     (**modern hardened default** — credentials are
//     authenticated via SPNEGO + NTLM/Kerberos BEFORE
//     the RDP session is established; protects against
//     CVE-2019-0708 BlueKeep, CVE-2019-1181 / 1182 /
//     1222 / 1226 DejaBlue, and many credential-relay
//     attacks).
//
//   - `0x00000004` PROTOCOL_RDSTLS — Remote Desktop
//     Services TLS (RD Gateway / RemoteApp).
//
//   - `0x00000008` PROTOCOL_HYBRID_EX — CredSSP +
//     EarlyUserAuthorizationResult (improved NLA).
//
//   - `0x00000010` PROTOCOL_RDSAAD — Microsoft Entra ID
//     AAD authentication (modern Azure RDP).
//
//   - **Server hardening enforcement via NEG_FAILURE** —
//     when the client offers an insufficient protocol set,
//     the server returns a Connection Confirm carrying
//     RDP_NEG_FAILURE with failureCode:
//
//   - `0x00000001` SSL_REQUIRED_BY_SERVER — server
//     refuses standard RDP, requires TLS+ (hardening
//     applied).
//
//   - `0x00000002` SSL_NOT_ALLOWED_BY_SERVER — server
//     forbids TLS (very rare).
//
//   - `0x00000003` SSL_CERT_NOT_ON_SERVER — TLS
//     misconfiguration.
//
//   - `0x00000004` INCONSISTENT_FLAGS — malformed
//     request.
//
//   - `0x00000005` HYBRID_REQUIRED_BY_SERVER —
//     server mandates CredSSP NLA (**canonical
//     NLA-hardened response**; pre-auth credential
//     check enforced before any RDP frames).
//
//   - `0x00000006` SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER
//     — TLS + user-cert-based auth required.
//
//   - **Selected-protocol confirmation via NEG_RSP** —
//     when the server accepts, RDP_NEG_RSP carries the
//     `selectedProtocol` (same bitmask) — the final
//     security layer in use. `selectedProtocol = 0`
//     (standard RDP) on a server reachable from the
//     internet is a high-severity finding (legacy
//     BlueKeep target).
//
//   - **Restricted Admin Mode detection** — NEG_REQ.flags
//     bit `RESTRICTED_ADMIN_MODE_REQUIRED` (0x01) indicates
//     RDP Restricted Admin mode (introduced in Windows 8.1
//     / Server 2012 R2) — the client wants to log in
//     without sending credentials to the remote host
//     (protects against credential theft on a compromised
//     server but enables PtH attacks).
//
// Wrap-vs-native judgement
//
//	Native. The TPKT + X.224 framing is RFC 1006 + ITU-T
//	X.224 — both publicly available. RDP_NEG_REQ /
//	RDP_NEG_RSP / RDP_NEG_FAILURE are documented in
//	[MS-RDPBCGR] §2.2.1.1.1 / §2.2.1.2.1 / §2.2.1.2.2 —
//	fixed 8-byte structures with named flag bits. Cookie
//	extraction is a simple cstring-prefix walk. Post-CC
//	MCS Connect Initial / GCC ClientCoreData / RDP
//	Security Layer / CredSSP TSRequest / RDP virtual
//	channels are deep nested protocols and out of scope —
//	for CredSSP, the inner NTLM/Kerberos is already
//	handled by ntlm_decode + kerberos_decode.
//
// What this package covers
//
//   - **4-byte TPKT header** (RFC 1006): version (1) = 3 /
//     reserved (1) / length (2 BE — total including TPKT
//     header).
//
//   - **X.224 COTP header** (ITU-T X.224 / RFC 905): LI
//     length-indicator (1 — header length excluding LI) /
//     PDU-type+credit (1) / dst-ref (2) / src-ref (2) /
//     class+option (1).
//
//   - **5-entry X.224 PDU-type name table**: 0xE0 CR
//     Connection Request (client → server initial probe) /
//     0xD0 CC Connection Confirm (server → client reply) /
//     0xF0 DT Data (post-handshake data carrier) / 0x80 DR
//     Disconnect Request / 0x70 ER Error.
//
//   - **RDP Cookie extraction** — for CR PDUs, walks the
//     post-X.224-header user data looking for a leading
//     `Cookie: ` line terminated by `\r\n`. Extracts
//     `mstshash_username` (cleartext!) when the cookie is
//     `Cookie: mstshash=<username>` or `msts_routing_token`
//     when the cookie is `Cookie: msts=<token>`.
//
//   - **RDP_NEG_REQ walker** ([MS-RDPBCGR] §2.2.1.1.1):
//     type (1) = 0x01 / flags (1) / length (2 LE) = 8 /
//     requestedProtocols (4 LE). Surfaces
//     `neg_req_requested_protocols` bitmask +
//     `neg_req_requested_protocols_names` array +
//     `neg_req_flags` + `neg_req_flags_names`.
//
//   - **6-entry requestedProtocols name table**: 0x00
//     PROTOCOL_RDP (standard — no TLS, vulnerable!) /
//     0x01 PROTOCOL_SSL (TLS only) / 0x02 PROTOCOL_HYBRID
//     (CredSSP NLA — modern hardened default!) / 0x04
//     PROTOCOL_RDSTLS / 0x08 PROTOCOL_HYBRID_EX (CredSSP
//
//   - EarlyUserAuthorizationResult) / 0x10 PROTOCOL_RDSAAD
//     (Microsoft Entra ID AAD).
//
//   - **3-entry NEG_REQ flags name table**: 0x01
//     RESTRICTED_ADMIN_MODE_REQUIRED / 0x02
//     REDIRECTED_AUTHENTICATION_MODE_REQUIRED / 0x08
//     CORRELATION_INFO_PRESENT.
//
//   - **RDP_NEG_RSP walker** ([MS-RDPBCGR] §2.2.1.2.1):
//     type (1) = 0x02 / flags (1) / length (2 LE) = 8 /
//     selectedProtocol (4 LE). Surfaces
//     `neg_rsp_selected_protocol` + name +
//     `neg_rsp_flags_names`.
//
//   - **3-entry NEG_RSP flags name table**: 0x01
//     EXTENDED_CLIENT_DATA_SUPPORTED / 0x02
//     DYNVC_GFX_PROTOCOL_SUPPORTED / 0x04
//     RDP_NEGRSP_RESERVED.
//
//   - **RDP_NEG_FAILURE walker** ([MS-RDPBCGR] §2.2.1.2.2):
//     type (1) = 0x03 / flags (1) / length (2 LE) = 8 /
//     failureCode (4 LE). Surfaces `neg_failure_code` +
//     name.
//
//   - **6-entry failureCode name table**: 0x01
//     SSL_REQUIRED_BY_SERVER (hardening applied) / 0x02
//     SSL_NOT_ALLOWED_BY_SERVER (rare) / 0x03
//     SSL_CERT_NOT_ON_SERVER (TLS misconfig) / 0x04
//     INCONSISTENT_FLAGS / 0x05 HYBRID_REQUIRED_BY_SERVER
//     (canonical NLA-hardened response!) / 0x06
//     SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **MCS Connect Initial / Connect Response** — after
//     X.224 CR/CC, the client sends an MCS Connect Initial
//     PDU containing a Generic Conference Control (GCC)
//     ConferenceCreateRequest payload with ClientCoreData
//     / ClientSecurityData / ClientNetworkData /
//     ClientClusterData / ClientMonitorData TLV blocks.
//     Each of these is a large nested structure with
//     dozens of fields; out of scope.
//   - **CredSSP TSRequest** — when PROTOCOL_HYBRID is
//     negotiated, the TLS-wrapped CredSSP exchange carries
//     SPNEGO-wrapped NTLM / Kerberos auth blobs (the
//     NTLM/Kerberos inner blob is already handled by
//     ntlm_decode + kerberos_decode).
//   - **RDP Security Layer** — Standard RDP Security key
//     exchange + per-frame encryption (legacy; rare in
//     modern deployments after Server 2008 deprecation).
//   - **RDP virtual channels** — RDPDR (drive
//     redirection), RDPSND (audio), CLIPRDR (clipboard),
//     RAIL (RemoteApp), RemoteFX (graphics codec), DYNVC
//     dynamic virtual channels; each its own sub-protocol.
//   - **RDP licensing protocol** — pre-session licensing
//     exchange when connecting to a Terminal Server / RDS
//     deployment.
//   - **FastPath input/output PDUs** — alternative wire
//     format (skipping TPKT + X.224) used post-handshake
//     for keyboard/mouse input + screen-update output.
//   - **Multi-segment fragmented X.224 data** — the
//     decoder handles single-segment CR / CC / DT / DR /
//     ER PDUs only.
//   - **NeGEx2 / NLA / EAP-TTLS / SCard authentication
//     variants** — modern Microsoft additions covered
//     individually elsewhere.
package rdpx224

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the structured decode of an RDP initial-handshake
// PDU.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	// TPKT
	TPKTVersion int `json:"tpkt_version,omitempty"`
	TPKTLength  int `json:"tpkt_length,omitempty"`

	// X.224
	X224LengthIndicator int    `json:"x224_length_indicator,omitempty"`
	X224PDUType         int    `json:"x224_pdu_type,omitempty"`
	X224PDUTypeName     string `json:"x224_pdu_type_name,omitempty"`

	// RDP Cookie
	RDPCookieRaw     string `json:"rdp_cookie_raw,omitempty"`
	MSTSHashUsername string `json:"mstshash_username,omitempty"`
	MSTSRoutingToken string `json:"msts_routing_token,omitempty"`

	// RDP_NEG_REQ
	HasNegReq                     bool     `json:"has_neg_req"`
	NegReqFlags                   int      `json:"neg_req_flags,omitempty"`
	NegReqFlagsNames              []string `json:"neg_req_flags_names,omitempty"`
	NegReqRequestedProtocols      uint32   `json:"neg_req_requested_protocols,omitempty"`
	NegReqRequestedProtocolsNames []string `json:"neg_req_requested_protocols_names,omitempty"`

	// RDP_NEG_RSP
	HasNegRsp                  bool     `json:"has_neg_rsp"`
	NegRspFlags                int      `json:"neg_rsp_flags,omitempty"`
	NegRspFlagsNames           []string `json:"neg_rsp_flags_names,omitempty"`
	NegRspSelectedProtocol     uint32   `json:"neg_rsp_selected_protocol,omitempty"`
	NegRspSelectedProtocolName string   `json:"neg_rsp_selected_protocol_name,omitempty"`

	// RDP_NEG_FAILURE
	HasNegFailure      bool   `json:"has_neg_failure"`
	NegFailureCode     uint32 `json:"neg_failure_code,omitempty"`
	NegFailureCodeName string `json:"neg_failure_code_name,omitempty"`
}

// Decode parses an RDP initial-handshake PDU from a hex string.
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
	if len(b) < 7 {
		return nil, fmt.Errorf("rdp pdu truncated (%d bytes; need 7 minimum)", len(b))
	}

	r := &Result{TotalBytes: len(b)}

	// TPKT header
	r.TPKTVersion = int(b[0])
	if r.TPKTVersion != 3 {
		return r, fmt.Errorf("not a TPKT v3 packet (version=%d)", r.TPKTVersion)
	}
	r.TPKTLength = int(binary.BigEndian.Uint16(b[2:4]))

	// X.224 COTP header starts at b[4]
	r.X224LengthIndicator = int(b[4])
	r.X224PDUType = int(b[5] & 0xF0)
	r.X224PDUTypeName = x224PDUTypeName(r.X224PDUType)

	// User data starts after the X.224 header (4 + 1 + LI bytes)
	udStart := 4 + 1 + r.X224LengthIndicator
	if udStart > len(b) {
		return r, nil
	}
	ud := b[udStart:]

	switch r.X224PDUType {
	case 0xE0: // CR
		off := decodeCookie(r, ud)
		decodeNegReq(r, ud[off:])
	case 0xD0: // CC
		decodeNegRspOrFailure(r, ud)
	}
	return r, nil
}

// decodeCookie walks the optional Cookie line(s) at the start
// of CR user data. Returns the offset where the cookie ends
// (NEG_REQ starts there).
func decodeCookie(r *Result, ud []byte) int {
	if len(ud) < 9 {
		return 0
	}
	// "Cookie: " prefix
	if !strings.HasPrefix(string(ud[:8]), "Cookie: ") {
		return 0
	}
	// find \r\n
	end := 8
	for end+1 < len(ud) {
		if ud[end] == '\r' && ud[end+1] == '\n' {
			break
		}
		end++
	}
	if end+1 >= len(ud) {
		return 0
	}
	r.RDPCookieRaw = string(ud[8:end])
	if strings.HasPrefix(r.RDPCookieRaw, "mstshash=") {
		r.MSTSHashUsername = strings.TrimPrefix(r.RDPCookieRaw, "mstshash=")
	} else if strings.HasPrefix(r.RDPCookieRaw, "msts=") {
		r.MSTSRoutingToken = strings.TrimPrefix(r.RDPCookieRaw, "msts=")
	}
	return end + 2
}

// decodeNegReq walks the RDP_NEG_REQ structure (8 bytes).
func decodeNegReq(r *Result, ud []byte) {
	if len(ud) < 8 || ud[0] != 0x01 {
		return
	}
	r.HasNegReq = true
	r.NegReqFlags = int(ud[1])
	r.NegReqFlagsNames = negReqFlagsNames(r.NegReqFlags)
	r.NegReqRequestedProtocols = binary.LittleEndian.Uint32(ud[4:8])
	r.NegReqRequestedProtocolsNames = protocolNames(r.NegReqRequestedProtocols)
}

// decodeNegRspOrFailure walks the response — type byte
// discriminates NEG_RSP (0x02) vs NEG_FAILURE (0x03).
func decodeNegRspOrFailure(r *Result, ud []byte) {
	if len(ud) < 8 {
		return
	}
	switch ud[0] {
	case 0x02:
		r.HasNegRsp = true
		r.NegRspFlags = int(ud[1])
		r.NegRspFlagsNames = negRspFlagsNames(r.NegRspFlags)
		r.NegRspSelectedProtocol = binary.LittleEndian.Uint32(ud[4:8])
		names := protocolNames(r.NegRspSelectedProtocol)
		if len(names) > 0 {
			r.NegRspSelectedProtocolName = names[0]
		} else {
			r.NegRspSelectedProtocolName = "PROTOCOL_RDP (standard — no TLS, vulnerable to passive MITM!)"
		}
	case 0x03:
		r.HasNegFailure = true
		r.NegFailureCode = binary.LittleEndian.Uint32(ud[4:8])
		r.NegFailureCodeName = negFailureCodeName(r.NegFailureCode)
	}
}

func x224PDUTypeName(t int) string {
	switch t {
	case 0xE0:
		return "CR (Connection Request)"
	case 0xD0:
		return "CC (Connection Confirm)"
	case 0xF0:
		return "DT (Data)"
	case 0x80:
		return "DR (Disconnect Request)"
	case 0x70:
		return "ER (Error)"
	}
	return fmt.Sprintf("uncatalogued PDU type 0x%02X", t)
}

func protocolNames(p uint32) []string {
	type entry struct {
		bit  uint32
		name string
	}
	table := []entry{
		{0x00000001, "PROTOCOL_SSL (TLS 1.0+)"},
		{0x00000002, "PROTOCOL_HYBRID (CredSSP NLA — modern hardened default)"},
		{0x00000004, "PROTOCOL_RDSTLS"},
		{0x00000008, "PROTOCOL_HYBRID_EX (CredSSP + EarlyUserAuthorizationResult)"},
		{0x00000010, "PROTOCOL_RDSAAD (Microsoft Entra ID AAD)"},
	}
	var names []string
	for _, e := range table {
		if p&e.bit != 0 {
			names = append(names, e.name)
		}
	}
	if p == 0 {
		names = append(names, "PROTOCOL_RDP (standard — no TLS, vulnerable to passive MITM!)")
	}
	return names
}

func negReqFlagsNames(f int) []string {
	var names []string
	if f&0x01 != 0 {
		names = append(names, "RESTRICTED_ADMIN_MODE_REQUIRED")
	}
	if f&0x02 != 0 {
		names = append(names, "REDIRECTED_AUTHENTICATION_MODE_REQUIRED")
	}
	if f&0x08 != 0 {
		names = append(names, "CORRELATION_INFO_PRESENT")
	}
	return names
}

func negRspFlagsNames(f int) []string {
	var names []string
	if f&0x01 != 0 {
		names = append(names, "EXTENDED_CLIENT_DATA_SUPPORTED")
	}
	if f&0x02 != 0 {
		names = append(names, "DYNVC_GFX_PROTOCOL_SUPPORTED")
	}
	if f&0x04 != 0 {
		names = append(names, "RDP_NEGRSP_RESERVED")
	}
	return names
}

func negFailureCodeName(c uint32) string {
	switch c {
	case 0x00000001:
		return "SSL_REQUIRED_BY_SERVER (hardening applied — refuses standard RDP)"
	case 0x00000002:
		return "SSL_NOT_ALLOWED_BY_SERVER"
	case 0x00000003:
		return "SSL_CERT_NOT_ON_SERVER (TLS misconfig)"
	case 0x00000004:
		return "INCONSISTENT_FLAGS"
	case 0x00000005:
		return "HYBRID_REQUIRED_BY_SERVER (canonical NLA-hardened response — CredSSP mandated)"
	case 0x00000006:
		return "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER"
	}
	return fmt.Sprintf("uncatalogued failure code 0x%08X", c)
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
