// Package ntlm decodes NTLM (NT LAN Manager) messages per
// Microsoft Open Protocol Specifications MS-NLMP. NTLM is the
// challenge-response authentication protocol used pervasively
// on Windows networks:
//
//   - **SMB / CIFS** — SMB v1 / v2 / v3 sessions authenticate
//     by exchanging NTLM Type 1 / 2 / 3 messages embedded in
//     SESSION_SETUP_ANDX requests.
//   - **HTTP Negotiate / NTLM** — IIS, Exchange, SharePoint
//     authenticate browser clients via "Authorization: NTLM
//     <base64>" headers carrying NTLMSSP blobs.
//   - **LDAP / LDAPS** — Active Directory bind requests use
//     NTLM as a SASL mechanism when Kerberos is unavailable.
//   - **MS-RPC over named pipes / DCERPC** — legacy SAM /
//     LSAR / DRSUAPI traffic embeds NTLM in DCE bind PDUs.
//
// NTLM is universally observed in Windows-heavy enterprise +
// AD-joined infrastructure, even in deployments that prefer
// Kerberos (NTLM remains a fallback for non-domain access,
// legacy applications, and stale device caches).
//
// Wrap-vs-native judgement
//
//	Native. The MS-NLMP specification is public, and the
//	wire format is straightforward: every NTLM message
//	starts with the ASCII signature "NTLMSSP\x00" (8 bytes)
//	followed by a 4-byte little-endian MessageType (1, 2,
//	or 3) and a type-specific body. Each body is a fixed-
//	position header that references variable-length payload
//	data via (Length, MaxLength, Offset) field triples.
//	No crypto at the parse layer — challenge bytes and
//	responses are surfaced as hex; cryptographic
//	verification requires the user's NT hash + IK / domain
//	context.
//
// What this package covers
//
//   - **12-byte common header**: 8-byte ASCII signature
//     "NTLMSSP\x00" (validated; mismatches return error) +
//     4-byte **MessageType** (little-endian uint32) with
//     **3-entry name table**: 1 NEGOTIATE_MESSAGE (client →
//     server), 2 CHALLENGE_MESSAGE (server → client), 3
//     AUTHENTICATE_MESSAGE (client → server).
//
//   - **NEGOTIATE_MESSAGE (Type 1)** body:
//
//   - 4-byte **NegotiateFlags** (uint32 LE) decoded into
//     a **~22-entry named-bit set** (see below).
//
//   - 8-byte Domain fields (Len + MaxLen + Offset).
//
//   - 8-byte Workstation fields.
//
//   - Optional 8-byte **Version** (Major + Minor + Build
//     uint16 LE + Reserved 3 bytes + NTLMRevisionCurrent
//     byte = 0x0F).
//
//   - Payload: Domain + Workstation strings (encoding
//     per OEM/UNICODE flag).
//
//   - **CHALLENGE_MESSAGE (Type 2)** body:
//
//   - 8-byte TargetName fields.
//
//   - 4-byte NegotiateFlags.
//
//   - 8-byte **ServerChallenge** (surfaced as hex —
//     feeds into NTLM v1/v2 challenge-response hash
//     crackable with hashcat mode 5500 / 5600).
//
//   - 8-byte Reserved.
//
//   - 8-byte TargetInfo fields (AV pair list).
//
//   - Optional 8-byte Version.
//
//   - Payload: TargetName + TargetInfo.
//
//   - **AV Pair walker** (inside CHALLENGE_MESSAGE
//     TargetInfo): (AvId uint16 LE + AvLen uint16 LE +
//     Value) records ending at AvId 0 (MsvAvEOL).
//     **10-entry AvId name table**:
//     1 MsvAvNbComputerName / 2 MsvAvNbDomainName /
//     3 MsvAvDnsComputerName / 4 MsvAvDnsDomainName /
//     5 MsvAvDnsTreeName / 6 MsvAvFlags / 7 MsvAvTimestamp
//     / 8 MsvAvSingleHost / 9 MsvAvTargetName / 10
//     MsvAvChannelBindings.
//
//   - **AUTHENTICATE_MESSAGE (Type 3)** body:
//
//   - 8-byte LmChallengeResponse fields.
//
//   - 8-byte NtChallengeResponse fields (surfaced as
//     hex — feeds into NTLMv2 hash crackable with
//     hashcat mode 5600; the structure also carries
//     the NTProofStr that's the actual hash response).
//
//   - 8-byte DomainName fields.
//
//   - 8-byte UserName fields.
//
//   - 8-byte Workstation fields.
//
//   - 8-byte EncryptedRandomSessionKey fields.
//
//   - 4-byte NegotiateFlags.
//
//   - Optional 8-byte Version.
//
//   - Optional 16-byte MIC (Message Integrity Check).
//
//   - Payload: response blobs + Domain + User +
//     Workstation strings.
//
//   - **NegotiateFlags name table** (~22 entries, RFC-less
//     but well-documented in MS-NLMP §2.2.2.5):
//     0x00000001 NEGOTIATE_UNICODE / 0x00000002 NEGOTIATE_OEM
//     / 0x00000004 REQUEST_TARGET / 0x00000010 NEGOTIATE_SIGN
//     / 0x00000020 NEGOTIATE_SEAL / 0x00000040
//     NEGOTIATE_DATAGRAM / 0x00000080 NEGOTIATE_LM_KEY /
//     0x00000200 NEGOTIATE_NTLM / 0x00000800
//     ANONYMOUS_CONNECTION / 0x00001000
//     NEGOTIATE_OEM_DOMAIN_SUPPLIED / 0x00002000
//     NEGOTIATE_OEM_WORKSTATION_SUPPLIED / 0x00008000
//     NEGOTIATE_ALWAYS_SIGN / 0x00010000
//     TARGET_TYPE_DOMAIN / 0x00020000 TARGET_TYPE_SERVER /
//     0x00080000 NEGOTIATE_EXTENDED_SESSIONSECURITY /
//     0x00100000 NEGOTIATE_TARGET_INFO / 0x00200000
//     NEGOTIATE_IDENTIFY / 0x00400000
//     REQUEST_NON_NT_SESSION_KEY / 0x00800000
//     NEGOTIATE_TARGET_INFO_AV_PAIRS / 0x02000000
//     NEGOTIATE_VERSION / 0x20000000 NEGOTIATE_128 /
//     0x40000000 NEGOTIATE_KEY_EXCH / 0x80000000
//     NEGOTIATE_56.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - Transport framing — feed the raw NTLMSSP bytes
//     (already extracted from SMB SESSION_SETUP, HTTP
//     "Authorization: NTLM <base64>", LDAP bind, or DCE
//     bind PDU). Base64 decoding is the caller's job for
//     HTTP-encoded blobs.
//
//   - Cryptographic verification of NT/LM responses —
//     surfaced as hex; verifying an NTLMv1 / NTLMv2
//     response requires the user's NT hash and the
//     challenge from the matching Type 2 message
//     (operators use hashcat mode 5500 / 5600 against the
//     surfaced ServerChallenge + NtChallengeResponse).
//
//   - MIC verification — surfaced as hex; verification
//     requires the session key derived from KXKEY +
//     SIGNKEY material that's not in the wire payload.
//
//   - SPNEGO wrapper (when NTLM is the inner mechanism in
//     a GSS-API negotiation) — strip the outer SPNEGO
//     ASN.1 first; this decoder expects an NTLMSSP blob
//     not wrapped in SPNEGO.
package ntlm

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf16"
)

// Result is the top-level decoded view of an NTLM message.
type Result struct {
	MessageType     int    `json:"message_type"`
	MessageTypeName string `json:"message_type_name"`
	TotalBytes      int    `json:"total_bytes"`

	Negotiate    *NegotiateBody    `json:"negotiate_message,omitempty"`
	Challenge    *ChallengeBody    `json:"challenge_message,omitempty"`
	Authenticate *AuthenticateBody `json:"authenticate_message,omitempty"`

	Notes []string `json:"notes,omitempty"`
}

// NegotiateBody is the decoded body of a Type 1 NEGOTIATE
// message.
type NegotiateBody struct {
	NegotiateFlags     uint32   `json:"negotiate_flags"`
	NegotiateFlagsHex  string   `json:"negotiate_flags_hex"`
	NegotiateFlagNames []string `json:"negotiate_flag_names"`
	Domain             string   `json:"domain,omitempty"`
	DomainHex          string   `json:"domain_hex,omitempty"`
	Workstation        string   `json:"workstation,omitempty"`
	WorkstationHex     string   `json:"workstation_hex,omitempty"`
	Version            *Version `json:"version,omitempty"`
}

// ChallengeBody is the decoded body of a Type 2 CHALLENGE
// message.
type ChallengeBody struct {
	TargetName         string   `json:"target_name,omitempty"`
	TargetNameHex      string   `json:"target_name_hex,omitempty"`
	NegotiateFlags     uint32   `json:"negotiate_flags"`
	NegotiateFlagsHex  string   `json:"negotiate_flags_hex"`
	NegotiateFlagNames []string `json:"negotiate_flag_names"`
	ServerChallenge    string   `json:"server_challenge_hex"`
	ReservedHex        string   `json:"reserved_hex"`
	TargetInfoHex      string   `json:"target_info_hex,omitempty"`
	TargetInfoAVPairs  []AVPair `json:"target_info_av_pairs,omitempty"`
	Version            *Version `json:"version,omitempty"`
}

// AuthenticateBody is the decoded body of a Type 3 AUTHENTICATE
// message.
type AuthenticateBody struct {
	LmChallengeResponseHex   string   `json:"lm_challenge_response_hex,omitempty"`
	LmChallengeResponseBytes int      `json:"lm_challenge_response_bytes"`
	NtChallengeResponseHex   string   `json:"nt_challenge_response_hex,omitempty"`
	NtChallengeResponseBytes int      `json:"nt_challenge_response_bytes"`
	DomainName               string   `json:"domain_name,omitempty"`
	UserName                 string   `json:"user_name,omitempty"`
	Workstation              string   `json:"workstation,omitempty"`
	EncryptedSessionKeyHex   string   `json:"encrypted_session_key_hex,omitempty"`
	NegotiateFlags           uint32   `json:"negotiate_flags"`
	NegotiateFlagsHex        string   `json:"negotiate_flags_hex"`
	NegotiateFlagNames       []string `json:"negotiate_flag_names"`
	Version                  *Version `json:"version,omitempty"`
	MICHex                   string   `json:"mic_hex,omitempty"`
}

// AVPair is one (AvId, AvLen, Value) record from the
// CHALLENGE TargetInfo list.
type AVPair struct {
	AvID      int    `json:"av_id"`
	AvIDName  string `json:"av_id_name"`
	AvLength  int    `json:"av_length"`
	ValueHex  string `json:"value_hex,omitempty"`
	ValueText string `json:"value_text,omitempty"`
}

// Version is the decoded 8-byte VERSION structure.
type Version struct {
	Major    int    `json:"major"`
	Minor    int    `json:"minor"`
	Build    int    `json:"build"`
	Revision int    `json:"ntlm_revision_current"`
	String   string `json:"string"`
}

// Decode parses a single NTLM message from hex.
func Decode(hexStr string) (*Result, error) {
	clean := stripSeparators(hexStr)
	if clean == "" {
		return nil, fmt.Errorf("empty input")
	}
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("hex must have even length, got %d", len(clean))
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	if len(b) < 12 {
		return nil, fmt.Errorf("NTLM message truncated (%d bytes; need ≥12 for signature + type)",
			len(b))
	}
	sig := string(b[0:8])
	if sig != "NTLMSSP\x00" {
		return nil, fmt.Errorf("invalid NTLM signature (got %q; expected NTLMSSP\\x00)", sig)
	}
	msgType := binary.LittleEndian.Uint32(b[8:12])
	r := &Result{
		TotalBytes:      len(b),
		MessageType:     int(msgType),
		MessageTypeName: messageTypeName(int(msgType)),
	}
	switch msgType {
	case 1:
		r.Negotiate = decodeNegotiate(b)
	case 2:
		r.Challenge = decodeChallenge(b)
	case 3:
		r.Authenticate = decodeAuthenticate(b)
	default:
		r.Notes = append(r.Notes, fmt.Sprintf(
			"uncatalogued NTLM message type %d (MS-NLMP defines 1, 2, 3)", msgType))
	}
	return r, nil
}

func decodeNegotiate(b []byte) *NegotiateBody {
	if len(b) < 32 {
		return nil
	}
	flags := binary.LittleEndian.Uint32(b[12:16])
	n := &NegotiateBody{
		NegotiateFlags:     flags,
		NegotiateFlagsHex:  fmt.Sprintf("0x%08X", flags),
		NegotiateFlagNames: decodeNegotiateFlags(flags),
	}
	domLen := int(binary.LittleEndian.Uint16(b[16:18]))
	domOff := int(binary.LittleEndian.Uint32(b[20:24]))
	wsLen := int(binary.LittleEndian.Uint16(b[24:26]))
	wsOff := int(binary.LittleEndian.Uint32(b[28:32]))
	if flags&0x02000000 != 0 && len(b) >= 40 {
		n.Version = decodeVersion(b[32:40])
	}
	n.Domain, n.DomainHex = readField(b, domOff, domLen, flags&0x00000001 != 0)
	n.Workstation, n.WorkstationHex = readField(b, wsOff, wsLen, flags&0x00000001 != 0)
	return n
}

func decodeChallenge(b []byte) *ChallengeBody {
	if len(b) < 48 {
		return nil
	}
	tnLen := int(binary.LittleEndian.Uint16(b[12:14]))
	tnOff := int(binary.LittleEndian.Uint32(b[16:20]))
	flags := binary.LittleEndian.Uint32(b[20:24])
	c := &ChallengeBody{
		NegotiateFlags:     flags,
		NegotiateFlagsHex:  fmt.Sprintf("0x%08X", flags),
		NegotiateFlagNames: decodeNegotiateFlags(flags),
		ServerChallenge:    strings.ToUpper(hex.EncodeToString(b[24:32])),
		ReservedHex:        strings.ToUpper(hex.EncodeToString(b[32:40])),
	}
	tiLen := int(binary.LittleEndian.Uint16(b[40:42]))
	tiOff := int(binary.LittleEndian.Uint32(b[44:48]))
	if flags&0x02000000 != 0 && len(b) >= 56 {
		c.Version = decodeVersion(b[48:56])
	}
	c.TargetName, c.TargetNameHex = readField(b, tnOff, tnLen, flags&0x00000001 != 0)
	if tiLen > 0 && tiOff+tiLen <= len(b) {
		c.TargetInfoHex = strings.ToUpper(hex.EncodeToString(b[tiOff : tiOff+tiLen]))
		c.TargetInfoAVPairs = decodeAVPairs(b[tiOff : tiOff+tiLen])
	}
	return c
}

func decodeAuthenticate(b []byte) *AuthenticateBody {
	if len(b) < 64 {
		return nil
	}
	lmLen := int(binary.LittleEndian.Uint16(b[12:14]))
	lmOff := int(binary.LittleEndian.Uint32(b[16:20]))
	ntLen := int(binary.LittleEndian.Uint16(b[20:22]))
	ntOff := int(binary.LittleEndian.Uint32(b[24:28]))
	domLen := int(binary.LittleEndian.Uint16(b[28:30]))
	domOff := int(binary.LittleEndian.Uint32(b[32:36]))
	userLen := int(binary.LittleEndian.Uint16(b[36:38]))
	userOff := int(binary.LittleEndian.Uint32(b[40:44]))
	wsLen := int(binary.LittleEndian.Uint16(b[44:46]))
	wsOff := int(binary.LittleEndian.Uint32(b[48:52]))
	skLen := int(binary.LittleEndian.Uint16(b[52:54]))
	skOff := int(binary.LittleEndian.Uint32(b[56:60]))
	flags := binary.LittleEndian.Uint32(b[60:64])
	a := &AuthenticateBody{
		LmChallengeResponseBytes: lmLen,
		NtChallengeResponseBytes: ntLen,
		NegotiateFlags:           flags,
		NegotiateFlagsHex:        fmt.Sprintf("0x%08X", flags),
		NegotiateFlagNames:       decodeNegotiateFlags(flags),
	}
	if flags&0x02000000 != 0 && len(b) >= 72 {
		a.Version = decodeVersion(b[64:72])
	}
	// MIC: 16 bytes after Version, when present.
	micOff := 64
	if a.Version != nil {
		micOff = 72
	}
	if micOff+16 <= len(b) && micOff+16 <= lmOff && micOff+16 <= ntOff &&
		micOff+16 <= domOff && micOff+16 <= userOff && micOff+16 <= wsOff &&
		micOff+16 <= skOff {
		// Only treat as MIC if it fits before any payload.
		a.MICHex = strings.ToUpper(hex.EncodeToString(b[micOff : micOff+16]))
	}
	if lmLen > 0 && lmOff+lmLen <= len(b) {
		a.LmChallengeResponseHex = strings.ToUpper(hex.EncodeToString(b[lmOff : lmOff+lmLen]))
	}
	if ntLen > 0 && ntOff+ntLen <= len(b) {
		a.NtChallengeResponseHex = strings.ToUpper(hex.EncodeToString(b[ntOff : ntOff+ntLen]))
	}
	a.DomainName, _ = readField(b, domOff, domLen, flags&0x00000001 != 0)
	a.UserName, _ = readField(b, userOff, userLen, flags&0x00000001 != 0)
	a.Workstation, _ = readField(b, wsOff, wsLen, flags&0x00000001 != 0)
	if skLen > 0 && skOff+skLen <= len(b) {
		a.EncryptedSessionKeyHex = strings.ToUpper(hex.EncodeToString(b[skOff : skOff+skLen]))
	}
	return a
}

func decodeAVPairs(b []byte) []AVPair {
	var out []AVPair
	off := 0
	for off+4 <= len(b) {
		id := int(binary.LittleEndian.Uint16(b[off : off+2]))
		ln := int(binary.LittleEndian.Uint16(b[off+2 : off+4]))
		if id == 0 && ln == 0 {
			break
		}
		if off+4+ln > len(b) {
			break
		}
		val := b[off+4 : off+4+ln]
		av := AVPair{
			AvID:     id,
			AvIDName: avIDName(id),
			AvLength: ln,
			ValueHex: strings.ToUpper(hex.EncodeToString(val)),
		}
		// Most AV pairs are UTF-16LE strings.
		if id >= 1 && id <= 5 {
			av.ValueText = utf16LEString(val)
		}
		out = append(out, av)
		off += 4 + ln
	}
	return out
}

func decodeVersion(b []byte) *Version {
	if len(b) < 8 {
		return nil
	}
	major := int(b[0])
	minor := int(b[1])
	build := int(binary.LittleEndian.Uint16(b[2:4]))
	return &Version{
		Major:    major,
		Minor:    minor,
		Build:    build,
		Revision: int(b[7]),
		String:   fmt.Sprintf("%d.%d build %d (NTLM revision %d)", major, minor, build, b[7]),
	}
}

func decodeNegotiateFlags(f uint32) []string {
	type bitNamed struct {
		mask uint32
		name string
	}
	flags := []bitNamed{
		{0x00000001, "NEGOTIATE_UNICODE"},
		{0x00000002, "NEGOTIATE_OEM"},
		{0x00000004, "REQUEST_TARGET"},
		{0x00000010, "NEGOTIATE_SIGN"},
		{0x00000020, "NEGOTIATE_SEAL"},
		{0x00000040, "NEGOTIATE_DATAGRAM"},
		{0x00000080, "NEGOTIATE_LM_KEY"},
		{0x00000200, "NEGOTIATE_NTLM"},
		{0x00000800, "ANONYMOUS_CONNECTION"},
		{0x00001000, "NEGOTIATE_OEM_DOMAIN_SUPPLIED"},
		{0x00002000, "NEGOTIATE_OEM_WORKSTATION_SUPPLIED"},
		{0x00008000, "NEGOTIATE_ALWAYS_SIGN"},
		{0x00010000, "TARGET_TYPE_DOMAIN"},
		{0x00020000, "TARGET_TYPE_SERVER"},
		{0x00080000, "NEGOTIATE_EXTENDED_SESSIONSECURITY"},
		{0x00100000, "NEGOTIATE_TARGET_INFO"},
		{0x00200000, "NEGOTIATE_IDENTIFY"},
		{0x00400000, "REQUEST_NON_NT_SESSION_KEY"},
		{0x00800000, "NEGOTIATE_TARGET_INFO_AV_PAIRS"},
		{0x02000000, "NEGOTIATE_VERSION"},
		{0x20000000, "NEGOTIATE_128"},
		{0x40000000, "NEGOTIATE_KEY_EXCH"},
		{0x80000000, "NEGOTIATE_56"},
	}
	var out []string
	for _, fb := range flags {
		if f&fb.mask != 0 {
			out = append(out, fb.name)
		}
	}
	return out
}

// readField resolves a (Offset, Length) field reference,
// returning the value as a UTF-16LE string (when Unicode flag
// is set) or OEM string, plus the raw hex.
func readField(b []byte, off, ln int, unicode bool) (string, string) {
	if ln == 0 || off+ln > len(b) {
		return "", ""
	}
	v := b[off : off+ln]
	hx := strings.ToUpper(hex.EncodeToString(v))
	if unicode {
		return utf16LEString(v), hx
	}
	return string(v), hx
}

// utf16LEString decodes a UTF-16LE byte slice to a Go string.
func utf16LEString(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[2*i : 2*i+2])
	}
	return string(utf16.Decode(u16))
}

func messageTypeName(t int) string {
	switch t {
	case 1:
		return "NEGOTIATE_MESSAGE"
	case 2:
		return "CHALLENGE_MESSAGE"
	case 3:
		return "AUTHENTICATE_MESSAGE"
	}
	return fmt.Sprintf("uncatalogued message type %d", t)
}

func avIDName(id int) string {
	switch id {
	case 0:
		return "MsvAvEOL"
	case 1:
		return "MsvAvNbComputerName"
	case 2:
		return "MsvAvNbDomainName"
	case 3:
		return "MsvAvDnsComputerName"
	case 4:
		return "MsvAvDnsDomainName"
	case 5:
		return "MsvAvDnsTreeName"
	case 6:
		return "MsvAvFlags"
	case 7:
		return "MsvAvTimestamp"
	case 8:
		return "MsvAvSingleHost"
	case 9:
		return "MsvAvTargetName"
	case 10:
		return "MsvAvChannelBindings"
	}
	return fmt.Sprintf("uncatalogued AV ID %d", id)
}

func stripSeparators(s string) string {
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
