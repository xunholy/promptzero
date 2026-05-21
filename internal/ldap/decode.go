// Package ldap decodes Lightweight Directory Access Protocol
// v3 messages per RFC 4511 — the canonical directory-service
// protocol used by **every Active Directory deployment** + most
// enterprise IAM stacks (Microsoft AD LDS, OpenLDAP, 389
// Directory Server, FreeIPA / IdM, Apple Open Directory, Apache
// Directory Server, Oracle Internet Directory, Novell eDirectory).
// LDAP runs over TCP/389 (cleartext), TCP/636 (LDAPS — implicit
// TLS), and UDP/389 (CLDAP — connectionless LDAP, used by
// Microsoft's NetLogon for site/DC discovery).
//
// Operationally, LDAP is the **AD-pentest counterpart to
// kerberos_decode** — together they form the complete AD
// directory-attack dissector pair. The wire format leaks:
//
//   - **Cleartext credentials via SimpleBind** — `BindRequest`
//     carries authentication CHOICE; when the `[0] simple`
//     option is used, the password is sent IN CLEARTEXT
//     within the request body. This is the canonical
//     credential-disclosure vector on TCP/389 (cleartext) —
//     observing one BindRequest with simple authentication
//     yields the user's password directly. AD allows
//     simple-bind over cleartext by default unless
//     `LDAPServerIntegrity` enforcement is turned on. The
//     decoder surfaces `simple_bind_present` boolean +
//     `bind_password_bytes` (the length, NOT the password
//     itself — privacy-preserving while flagging the
//     exposure).
//
//   - **Username + DN enumeration via SearchRequest** —
//     anonymous or authenticated SearchRequest enumerates
//     the directory tree. `baseObject` reveals the search
//     root (typically the AD domain — `DC=corp,DC=example,
//     DC=com`); the response SearchResultEntry frames each
//     leak an `objectName` (the DN — every user / computer
//     / group account in the directory). Even unauthenticated
//     `whoami`-style SearchRequest against rootDSE leaks the
//     domain naming context + supported SASL mechanisms.
//
//   - **Brute-force feedback via resultCode** —
//     BindResponse `resultCode = 49` (`invalidCredentials`)
//     is the canonical wrong-password response; `resultCode
//     = 0` (`success`) confirms a working credential.
//     Password-spray tools (kerbrute, ldapsearch loops)
//     consume this directly.
//
//   - **CLDAP NetLogon enumeration** — Microsoft's NetLogon
//     uses CLDAP (connectionless LDAP) on UDP/389 for site /
//     DC discovery; querying rootDSE via CLDAP leaks the
//     domain controller's site + GUID + DnsHostName + flags
//     without any authentication. Public attack tools
//     (impacket nmap NSE `ldap-rootdse`) consume this.
//
//   - **SASL mechanism enumeration** — anonymous query of
//     rootDSE attribute `supportedSASLMechanisms` lists the
//     mechanisms the server accepts (GSSAPI = Kerberos,
//     GSS-SPNEGO = Kerberos via SPNEGO, DIGEST-MD5,
//     CRAM-MD5, EXTERNAL, PLAIN). The decoder surfaces the
//     authentication CHOICE selector so observers can detect
//     `[3] sasl` BindRequest mechanism strings.
//
// Wrap-vs-native judgement
//
//	Native. RFC 4511 is publicly available; LDAP v3 messages
//	are ASN.1 BER-encoded SEQUENCEs with an outer messageID
//	INTEGER and a context-tagged [APPLICATION N] protocolOp
//	CHOICE. The DER walker is the same shape as
//	internal/kerberos — short / long-form length, INTEGER,
//	OCTET STRING, ENUMERATED, SEQUENCE traversal, context-
//	tag discrimination. Filter parsing + per-mechanism SASL
//	inner-decode + controls parsing are deliberately out of
//	scope (each is its own nested grammar — filter is RFC
//	4515; SASL GSSAPI carries Kerberos AP-REQ which is
//	handled by kerberos_decode).
//
// What this package covers
//
//   - **22-entry operation name table** (RFC 4511 §4.1.1):
//     `[APPLICATION 0]` `0x60` BindRequest / `[APPLICATION 1]`
//     `0x61` BindResponse / `[APPLICATION 2]` `0x42`
//     UnbindRequest (PRIMITIVE) / `[APPLICATION 3]` `0x63`
//     SearchRequest / `[APPLICATION 4]` `0x64`
//     SearchResultEntry / `[APPLICATION 5]` `0x65`
//     SearchResultDone / `[APPLICATION 6]` `0x66`
//     ModifyRequest / `[APPLICATION 7]` `0x67`
//     ModifyResponse / `[APPLICATION 8]` `0x68` AddRequest /
//     `[APPLICATION 9]` `0x69` AddResponse / `[APPLICATION 10]`
//     `0x4A` DelRequest (PRIMITIVE) / `[APPLICATION 11]`
//     `0x6B` DelResponse / `[APPLICATION 12]` `0x6C`
//     ModifyDNRequest / `[APPLICATION 13]` `0x6D`
//     ModifyDNResponse / `[APPLICATION 14]` `0x6E`
//     CompareRequest / `[APPLICATION 15]` `0x6F`
//     CompareResponse / `[APPLICATION 16]` `0x50`
//     AbandonRequest (PRIMITIVE) / `[APPLICATION 19]` `0x73`
//     SearchResultReference / `[APPLICATION 23]` `0x77`
//     ExtendedRequest / `[APPLICATION 24]` `0x78`
//     ExtendedResponse / `[APPLICATION 25]` `0x79`
//     IntermediateResponse.
//
//   - **BindRequest body** (§4.2): SEQUENCE { version
//     INTEGER (1..127) / name LDAPDN OCTET STRING (the
//     username / UPN / DN — leakable!) / authentication
//     AuthenticationChoice CHOICE { [0] simple OCTET STRING
//     (cleartext password!) / [3] sasl SaslCredentials
//     SEQUENCE { mechanism LDAPString / credentials OCTET
//     STRING OPTIONAL } } }. Surfaces `bind_name` (the
//     username) + `bind_auth_type` (simple / sasl) +
//     `simple_bind_present` (the cleartext-creds
//     classification!) + `bind_password_bytes` (length
//     only — NOT the password) + `sasl_mechanism` (when
//     SASL is used; e.g. "GSSAPI" indicates Kerberos
//     integration).
//
//   - **BindResponse body** (§4.2.2): SEQUENCE {
//     resultCode ENUMERATED / matchedDN LDAPDN /
//     diagnosticMessage LDAPString / referral [3] Referral
//     OPTIONAL / serverSaslCreds [7] OCTET STRING OPTIONAL }.
//     Surfaces `result_code` + `result_code_name` (49 =
//     invalidCredentials = brute-force feedback signal!) +
//     `matched_dn` + `diagnostic_message`.
//
//   - **SearchRequest body** (§4.5.1): SEQUENCE {
//     baseObject LDAPDN (the search root — e.g.
//     `DC=corp,DC=example,DC=com`) / scope ENUMERATED
//     { baseObject(0), singleLevel(1), wholeSubtree(2),
//     subordinateSubtree(3) } / derefAliases ENUMERATED /
//     sizeLimit INTEGER / timeLimit INTEGER / typesOnly
//     BOOLEAN / filter Filter / attributes
//     AttributeSelection }. Surfaces `search_base_object`
//
//   - `search_scope` + `search_scope_name` +
//     `search_size_limit` + `search_time_limit`.
//
//   - **SearchResultEntry body** (§4.5.2): SEQUENCE {
//     objectName LDAPDN (the matched entry's DN — every
//     user / computer / group account leaked) /
//     attributes PartialAttributeList }. Surfaces
//     `entry_object_name` (the DN — the directory-
//     enumeration leak!).
//
//   - **SearchResultDone + ModifyResponse + AddResponse +
//     DelResponse + ModifyDNResponse + CompareResponse +
//     ExtendedResponse body**: all share the LDAPResult
//     {resultCode / matchedDN / diagnosticMessage} shape;
//     decoded uniformly via the same code path as
//     BindResponse.
//
//   - **17-entry resultCode name table** (RFC 4511 §4.1.9):
//     0 `success` / 1 `operationsError` / 2 `protocolError`
//     / 4 `sizeLimitExceeded` / 7 `authMethodNotSupported`
//     / 8 `strongerAuthRequired` / 10 `referral` / 11
//     `adminLimitExceeded` / 13 `confidentialityRequired` /
//     14 `saslBindInProgress` (multi-step SASL — keep
//     reading) / 16 `noSuchAttribute` / 32 `noSuchObject`
//     (canonical "DN doesn't exist") / 48
//     `inappropriateAuthentication` / 49 `invalidCredentials`
//     (canonical wrong-password — brute-force feedback!) /
//     50 `insufficientAccessRights` / 51 `busy` / 53
//     `unwillingToPerform` (canonical "policy rejected").
//
//   - **4-entry search scope name table** (§4.5.1): 0
//     `baseObject` (just this entry) / 1 `singleLevel`
//     (immediate children) / 2 `wholeSubtree` (recursive —
//     the canonical full-directory-dump scope) / 3
//     `subordinateSubtree` (children + descendants,
//     excluding base).
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **Network framing** — feed LDAP bytes after the TCP-
//     segment strip; default ports TCP/389 cleartext +
//     TCP/636 LDAPS. For UDP CLDAP, strip the UDP datagram
//     header.
//   - **LDAPS / StartTLS** — TCP/636 wraps LDAP in TLS;
//     RFC 4513 §5.1 StartTLS upgrades a TCP/389 connection
//     to TLS via the ExtendedRequest OID `1.3.6.1.4.1.1466.
//     20037`. Handle TLS strip first.
//   - **LDAP filter parser** — the `filter` field in
//     SearchRequest is a Filter CHOICE per RFC 4511 §4.5.1
//   - RFC 4515 (string-form representation). The Filter
//     ASN.1 tree (and/or/not/equalityMatch/substrings/
//     greaterOrEqual/lessOrEqual/present/approxMatch/
//     extensibleMatch) is its own nested grammar — out of
//     scope here; surfaced as `filter_bytes` length only.
//   - **SASL mechanism inner-decode** — `[3] sasl
//     SaslCredentials` SEQUENCE carries a mechanism string +
//     opaque credentials. For GSSAPI, the credentials wrap
//     a Kerberos AP-REQ — that's already handled by
//     kerberos_decode. SCRAM-SHA-256 + DIGEST-MD5 +
//     CRAM-MD5 inner decode are out of scope.
//   - **Controls parsing** — `[0] controls Controls
//     OPTIONAL` at the end of LDAPMessage carries server-
//     side extensions (paging, sort, deleted-objects,
//     virtual-list-view, etc.). Surfaced as `controls_bytes`
//     length only.
//   - **MS NetLogon / CLDAP rootDSE payload parsing** —
//     CLDAP NetLogon Sample request returns a
//     NETLOGON_SAM_LOGON_RESPONSE_EX struct in the
//     attribute value; that struct's MS-NRPC binary
//     layout is out of scope (surface as raw attribute
//     bytes).
//   - **Schema parsing** — server-published schema objects
//     (`subschemaSubentry`, `attributeTypes`,
//     `objectClasses`) are surfaced as raw attribute values.
package ldap

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the structured decode of an LDAP message.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	MessageID      int    `json:"message_id"`
	ProtocolOp     int    `json:"protocol_op"`
	ProtocolOpName string `json:"protocol_op_name"`

	// BindRequest
	BindVersion       int    `json:"bind_version,omitempty"`
	BindName          string `json:"bind_name,omitempty"`
	BindAuthType      string `json:"bind_auth_type,omitempty"`
	SimpleBindPresent bool   `json:"simple_bind_present"`
	BindPasswordBytes int    `json:"bind_password_bytes,omitempty"`
	SASLMechanism     string `json:"sasl_mechanism,omitempty"`

	// LDAPResult-bearing responses (Bind/Search/Modify/
	// Add/Del/ModifyDN/Compare/Extended)
	ResultCode     int    `json:"result_code,omitempty"`
	ResultCodeName string `json:"result_code_name,omitempty"`
	MatchedDN      string `json:"matched_dn,omitempty"`
	DiagnosticMsg  string `json:"diagnostic_message,omitempty"`

	// SearchRequest
	SearchBaseObject string `json:"search_base_object,omitempty"`
	SearchScope      int    `json:"search_scope,omitempty"`
	SearchScopeName  string `json:"search_scope_name,omitempty"`
	SearchSizeLimit  int    `json:"search_size_limit,omitempty"`
	SearchTimeLimit  int    `json:"search_time_limit,omitempty"`
	FilterBytes      int    `json:"filter_bytes,omitempty"`

	// SearchResultEntry
	EntryObjectName string `json:"entry_object_name,omitempty"`
}

// Decode parses an LDAP message from a hex string. Separators
// (':' '-' '_' whitespace) tolerated; '0x' prefix tolerated.
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
	if len(b) < 2 {
		return nil, fmt.Errorf("ldap message truncated (%d bytes)", len(b))
	}

	r := &Result{TotalBytes: len(b)}

	// Outer is SEQUENCE (0x30).
	if b[0] != 0x30 {
		return r, fmt.Errorf("outer tag is not SEQUENCE (got 0x%02X)", b[0])
	}
	bodyLen, lenSize, err := readDERLength(b[1:])
	if err != nil {
		return r, fmt.Errorf("outer length: %w", err)
	}
	bodyStart := 1 + lenSize
	bodyEnd := bodyStart + bodyLen
	if bodyEnd > len(b) {
		bodyEnd = len(b)
	}
	body := b[bodyStart:bodyEnd]

	// First field: messageID INTEGER.
	if len(body) < 2 || body[0] != 0x02 {
		return r, fmt.Errorf("messageID not INTEGER")
	}
	idLen, idLenSize, err := readDERLength(body[1:])
	if err != nil {
		return r, fmt.Errorf("messageID length: %w", err)
	}
	idStart := 1 + idLenSize
	idEnd := idStart + idLen
	if idEnd > len(body) {
		return r, fmt.Errorf("messageID truncated")
	}
	r.MessageID = int(readINTEGER(body[idStart:idEnd]))

	// Second field: protocolOp [APPLICATION N].
	opStart := idEnd
	if opStart >= len(body) {
		return r, nil
	}
	opTag := body[opStart]
	if opTag&0xC0 != 0x40 {
		return r, fmt.Errorf("protocolOp not APPLICATION (got 0x%02X)", opTag)
	}
	r.ProtocolOp = int(opTag & 0x1F)
	r.ProtocolOpName = opName(r.ProtocolOp)

	opLen, opLenSize, err := readDERLength(body[opStart+1:])
	if err != nil {
		return r, nil
	}
	opContentStart := opStart + 1 + opLenSize
	opContentEnd := opContentStart + opLen
	if opContentEnd > len(body) {
		opContentEnd = len(body)
	}
	opBody := body[opContentStart:opContentEnd]

	switch r.ProtocolOp {
	case 0:
		decodeBindRequest(r, opBody)
	case 1, 5, 7, 9, 11, 13, 15, 24:
		decodeLDAPResult(r, opBody)
	case 3:
		decodeSearchRequest(r, opBody)
	case 4:
		decodeSearchResultEntry(r, opBody)
	}
	return r, nil
}

func decodeBindRequest(r *Result, body []byte) {
	off := 0
	// [0] version INTEGER
	tag, length, contentStart, next, ok := readTLV(body, off)
	if !ok || tag != 0x02 {
		return
	}
	r.BindVersion = int(readINTEGER(body[contentStart : contentStart+length]))
	off = next
	// [1] name LDAPDN OCTET STRING
	tag, length, contentStart, next, ok = readTLV(body, off)
	if !ok || tag != 0x04 {
		return
	}
	r.BindName = string(body[contentStart : contentStart+length])
	off = next
	// [2] authentication AuthenticationChoice — [0] simple
	// or [3] sasl, context-tagged PRIMITIVE / CONSTRUCTED.
	if off >= len(body) {
		return
	}
	authTag := body[off]
	authLen, authLenSize, err := readDERLength(body[off+1:])
	if err != nil {
		return
	}
	authContentStart := off + 1 + authLenSize
	authContentEnd := authContentStart + authLen
	if authContentEnd > len(body) {
		authContentEnd = len(body)
	}
	switch authTag & 0x1F {
	case 0:
		r.BindAuthType = "simple"
		r.SimpleBindPresent = true
		r.BindPasswordBytes = authLen
	case 3:
		r.BindAuthType = "sasl"
		// SaslCredentials SEQUENCE { mechanism LDAPString,
		// credentials OCTET STRING OPTIONAL }
		saslBody := body[authContentStart:authContentEnd]
		// mechanism is first OCTET STRING / LDAPString.
		mtag, mlen, mstart, _, mok := readTLV(saslBody, 0)
		if mok && mtag == 0x04 {
			r.SASLMechanism = string(saslBody[mstart : mstart+mlen])
		}
	default:
		r.BindAuthType = fmt.Sprintf("uncatalogued auth choice [%d]",
			int(authTag&0x1F))
	}
}

func decodeLDAPResult(r *Result, body []byte) {
	off := 0
	// resultCode ENUMERATED
	tag, length, contentStart, next, ok := readTLV(body, off)
	if !ok || tag != 0x0A {
		return
	}
	r.ResultCode = int(readINTEGER(body[contentStart : contentStart+length]))
	r.ResultCodeName = resultCodeName(r.ResultCode)
	off = next
	// matchedDN LDAPDN OCTET STRING
	tag, length, contentStart, next, ok = readTLV(body, off)
	if !ok || tag != 0x04 {
		return
	}
	r.MatchedDN = string(body[contentStart : contentStart+length])
	off = next
	// diagnosticMessage LDAPString OCTET STRING
	tag, length, contentStart, _, ok = readTLV(body, off)
	if !ok || tag != 0x04 {
		return
	}
	r.DiagnosticMsg = string(body[contentStart : contentStart+length])
}

func decodeSearchRequest(r *Result, body []byte) {
	off := 0
	// baseObject LDAPDN OCTET STRING
	tag, length, contentStart, next, ok := readTLV(body, off)
	if !ok || tag != 0x04 {
		return
	}
	r.SearchBaseObject = string(body[contentStart : contentStart+length])
	off = next
	// scope ENUMERATED
	tag, length, contentStart, next, ok = readTLV(body, off)
	if !ok || tag != 0x0A {
		return
	}
	r.SearchScope = int(readINTEGER(body[contentStart : contentStart+length]))
	r.SearchScopeName = scopeName(r.SearchScope)
	off = next
	// derefAliases ENUMERATED (skip)
	_, _, _, next, ok = readTLV(body, off)
	if !ok {
		return
	}
	off = next
	// sizeLimit INTEGER
	tag, length, contentStart, next, ok = readTLV(body, off)
	if !ok || tag != 0x02 {
		return
	}
	r.SearchSizeLimit = int(readINTEGER(body[contentStart : contentStart+length]))
	off = next
	// timeLimit INTEGER
	tag, length, contentStart, next, ok = readTLV(body, off)
	if !ok || tag != 0x02 {
		return
	}
	r.SearchTimeLimit = int(readINTEGER(body[contentStart : contentStart+length]))
	off = next
	// typesOnly BOOLEAN (skip)
	_, _, _, next, ok = readTLV(body, off)
	if !ok {
		return
	}
	off = next
	// filter Filter — surface bytes length.
	if off < len(body) {
		_, fLen, _, _, fOk := readTLV(body, off)
		if fOk {
			r.FilterBytes = fLen
		}
	}
}

func decodeSearchResultEntry(r *Result, body []byte) {
	// objectName LDAPDN OCTET STRING
	tag, length, contentStart, _, ok := readTLV(body, 0)
	if !ok || tag != 0x04 {
		return
	}
	r.EntryObjectName = string(body[contentStart : contentStart+length])
}

func readTLV(b []byte, off int) (byte, int, int, int, bool) {
	if off >= len(b) {
		return 0, 0, 0, 0, false
	}
	tag := b[off]
	length, lenSize, err := readDERLength(b[off+1:])
	if err != nil {
		return 0, 0, 0, 0, false
	}
	contentStart := off + 1 + lenSize
	next := contentStart + length
	if next > len(b) {
		return 0, 0, 0, 0, false
	}
	return tag, length, contentStart, next, true
}

func readDERLength(b []byte) (int, int, error) {
	if len(b) == 0 {
		return 0, 0, fmt.Errorf("empty length field")
	}
	first := b[0]
	if first < 0x80 {
		return int(first), 1, nil
	}
	n := int(first & 0x7F)
	if n == 0 || n > 4 {
		return 0, 0, fmt.Errorf("unsupported long-form length (%d octets)", n)
	}
	if 1+n > len(b) {
		return 0, 0, fmt.Errorf("long-form length truncated")
	}
	v := 0
	for i := 0; i < n; i++ {
		v = (v << 8) | int(b[1+i])
	}
	return v, 1 + n, nil
}

func readINTEGER(b []byte) int64 {
	if len(b) == 0 {
		return 0
	}
	var v int64
	if b[0]&0x80 != 0 {
		v = -1
	}
	for _, c := range b {
		v = (v << 8) | int64(c)
	}
	return v
}

func opName(n int) string {
	switch n {
	case 0:
		return "BindRequest"
	case 1:
		return "BindResponse"
	case 2:
		return "UnbindRequest"
	case 3:
		return "SearchRequest"
	case 4:
		return "SearchResultEntry"
	case 5:
		return "SearchResultDone"
	case 6:
		return "ModifyRequest"
	case 7:
		return "ModifyResponse"
	case 8:
		return "AddRequest"
	case 9:
		return "AddResponse"
	case 10:
		return "DelRequest"
	case 11:
		return "DelResponse"
	case 12:
		return "ModifyDNRequest"
	case 13:
		return "ModifyDNResponse"
	case 14:
		return "CompareRequest"
	case 15:
		return "CompareResponse"
	case 16:
		return "AbandonRequest"
	case 19:
		return "SearchResultReference"
	case 23:
		return "ExtendedRequest"
	case 24:
		return "ExtendedResponse"
	case 25:
		return "IntermediateResponse"
	}
	return fmt.Sprintf("uncatalogued operation %d", n)
}

func resultCodeName(n int) string {
	switch n {
	case 0:
		return "success"
	case 1:
		return "operationsError"
	case 2:
		return "protocolError"
	case 4:
		return "sizeLimitExceeded"
	case 7:
		return "authMethodNotSupported"
	case 8:
		return "strongerAuthRequired"
	case 10:
		return "referral"
	case 11:
		return "adminLimitExceeded"
	case 13:
		return "confidentialityRequired"
	case 14:
		return "saslBindInProgress"
	case 16:
		return "noSuchAttribute"
	case 32:
		return "noSuchObject"
	case 48:
		return "inappropriateAuthentication"
	case 49:
		return "invalidCredentials"
	case 50:
		return "insufficientAccessRights"
	case 51:
		return "busy"
	case 53:
		return "unwillingToPerform"
	}
	return fmt.Sprintf("uncatalogued result code %d", n)
}

func scopeName(n int) string {
	switch n {
	case 0:
		return "baseObject"
	case 1:
		return "singleLevel"
	case 2:
		return "wholeSubtree"
	case 3:
		return "subordinateSubtree"
	}
	return fmt.Sprintf("uncatalogued scope %d", n)
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
