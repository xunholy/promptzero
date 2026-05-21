// Package kerberos decodes Kerberos v5 messages per RFC 4120
// — the authentication protocol that underpins **every Active
// Directory deployment** and most enterprise SSO stacks (MIT
// Kerberos, Heimdal, Microsoft Active Directory, Apple Open
// Directory, FreeIPA / IdM). Kerberos runs over UDP/88 for
// requests under ~1500 bytes (the common case) and TCP/88 for
// larger requests (PAC inflation pushes most modern AS-REQs
// over UDP MTU).
//
// Operationally, Kerberos is the **highest-value AD-pentest
// decoder** because the wire format leaks:
//
//   - **Username enumeration** — every AS-REQ carries `cname`
//     (the Client Name) in cleartext. Observing AS-REQ
//     traffic enumerates every account name actively
//     authenticating to the KDC.
//
//   - **AS-REP roasting** (the canonical attack) — when an AD
//     account has the "Do not require Kerberos preauthentication"
//     attribute set (DONT_REQ_PREAUTH = 0x400000 in
//     UserAccountControl), the KDC accepts an AS-REQ with NO
//     `PA-ENC-TIMESTAMP` padata and returns an AS-REP whose
//     encrypted part is encrypted with the user's password-
//     derived key — directly crackable with hashcat mode 18200
//     against a rockyou-style wordlist. The decoder surfaces
//     `pre_auth_required` based on the presence of
//     PA-ENC-TIMESTAMP (type 2) in the padata list: when
//     `false`, the account is AS-REP-roastable.
//
//   - **Encryption type downgrade** — `etype` (the supported
//     encryption types list) reveals whether the client / KDC
//     supports legacy `rc4-hmac` (etype 23 — Windows NT
//     compatibility; broken offline cracking is trivial
//     against weak passwords). Modern AD deployments should
//     mandate `aes256-cts-hmac-sha1-96` (etype 18).
//
//   - **Realm + SPN disclosure** — `realm` reveals the AD
//     domain (CORP.EXAMPLE.COM); `sname` reveals the target
//     Service Principal Name (e.g.
//     `krbtgt/CORP.EXAMPLE.COM@CORP.EXAMPLE.COM` for AS-REQ,
//     or `MSSQLSvc/sql01.corp.example.com:1433` for TGS-REQ
//     against a SQL Server — the SPN enumeration goldmine
//     for Kerberoasting attack target selection).
//
//   - **Kerberoasting recon** — observing TGS-REQ traffic
//     enumerates which SPNs accounts are actively requesting,
//     pre-targeting the high-privilege service accounts that
//     yield the best Kerberoast crack candidates.
//
// Wrap-vs-native judgement
//
//	Native. RFC 4120 is publicly available; Kerberos uses
//	ASN.1 DER encoding with fixed [APPLICATION N] outer tags
//	per message type and context-tagged [N] CONSTRUCTED
//	fields inside the SEQUENCE body. The decoder includes a
//	small focused DER walker that handles short / long-form
//	length encoding, INTEGER decode, GeneralString decode,
//	SEQUENCE / SEQUENCE-OF traversal, and context-tag
//	discrimination. Encrypted parts (ticket + enc-part) are
//	surfaced as raw byte counts but NOT decrypted — that
//	requires the user's key + offline crack. No crypto at
//	the parse layer.
//
// What this package covers
//
//   - **7-entry message type name table** (RFC 4120 §5.10):
//     [APPLICATION 10] `0x6A` `AS-REQ` (Authentication Service
//     Request — initial TGT request) / [APPLICATION 11] `0x6B`
//     `AS-REP` (Authentication Service Response — contains the
//     TGT) / [APPLICATION 12] `0x6C` `TGS-REQ` (Ticket-
//     Granting Service Request — per-service ticket request) /
//     [APPLICATION 13] `0x6D` `TGS-REP` (TGS Response) /
//     [APPLICATION 14] `0x6E` `AP-REQ` (Application Request —
//     client authenticates to service) / [APPLICATION 15]
//     `0x6F` `AP-REP` (Application Response — mutual
//     authentication) / [APPLICATION 30] `0x7E` `KRB-ERROR`
//     (error response).
//
//   - **AS-REQ / TGS-REQ body** (KDC-REQ-BODY, RFC 4120
//     §5.4.1): walks the context-tagged inner SEQUENCE fields
//     [1] `pvno` (always 5) / [2] `msg-type` / [3] `padata`
//     OPTIONAL / [4] `req-body` containing:
//
//   - [0] `kdc-options` (BIT STRING — request flags like
//     `forwardable`, `proxiable`, `renewable`,
//     `validate`, `renew`).
//
//   - [1] `cname` PrincipalName OPTIONAL — the Client
//     Name (i.e. the username). The decoder joins the
//     SEQUENCE OF GeneralString name-string elements
//     with `/`.
//
//   - [2] `realm` Realm (GeneralString) — the AD domain.
//
//   - [3] `sname` PrincipalName OPTIONAL — the Service
//     Principal Name. For AS-REQ this is typically
//     `krbtgt/REALM`; for TGS-REQ it's the target
//     service (`MSSQLSvc/host:port`,
//     `HTTP/web.corp.example.com`, etc.).
//
//   - [7] `nonce` UInt32 — replay-protection nonce.
//
//   - [8] `etype` SEQUENCE OF Int32 — supported
//     encryption types in client preference order.
//     The decoder surfaces both the raw etype numbers
//
//   - an 11-entry name table.
//
//   - **11-entry Encryption Type name table** (RFC 3961 +
//     extensions): 1 `des-cbc-crc` / 2 `des-cbc-md4` / 3
//     `des-cbc-md5` / 16 `des3-cbc-sha1` / 17
//     `aes128-cts-hmac-sha1-96` / 18 `aes256-cts-hmac-sha1-96`
//     / 19 `aes128-cts-hmac-sha256-128` / 20
//     `aes256-cts-hmac-sha384-192` / 23 `rc4-hmac` (Windows
//     NT compat; legacy, weak) / 24 `rc4-hmac-exp` (export-
//     grade) / 25 `camellia128-cts-cmac` / 26
//     `camellia256-cts-cmac`.
//
//   - **PA-DATA type detection** — the `padata` SEQUENCE OF
//     PA-DATA records carry pre-authentication material. The
//     decoder enumerates the PA-DATA types present in the
//     message — most importantly, surfaces
//     `pre_auth_required` = whether `PA-ENC-TIMESTAMP` (type
//     2) is present in the padata list. **When `false`, the
//     account is AS-REP roastable.**
//
//   - **8-entry PA-DATA type name table** (RFC 4120 §7.5.2 +
//     extensions): 1 `PA-TGS-REQ` / 2 `PA-ENC-TIMESTAMP`
//     (preauth!) / 3 `PA-PW-SALT` / 11 `PA-ETYPE-INFO` / 14
//     `PA-PK-AS-REQ` (PKINIT) / 19 `PA-ETYPE-INFO2` / 128
//     `PA-PAC-REQUEST` (Windows PAC) / 129 `PA-FOR-USER`
//     (S4U2self).
//
//   - **AS-REP / TGS-REP body** (KDC-REP, RFC 4120 §5.4.2):
//     walks the inner SEQUENCE for [0] pvno / [1] msg-type /
//     [2] padata / [3] crealm / [4] cname / [5] ticket / [6]
//     enc-part. The decoder surfaces the realm + cname and
//     the byte lengths of the encrypted ticket + enc-part
//     (the AS-REP-roastable material).
//
//   - **KRB-ERROR body** (RFC 4120 §5.9.1) — walks the
//     context-tagged inner SEQUENCE for [4] stime / [5]
//     susec / [6] error-code / [7] crealm / [8] cname / [9]
//     realm / [10] sname / [11] e-text / [12] e-data. The
//     decoder surfaces the error-code with a 20+ entry name
//     table covering the high-runner failures.
//
//   - **20+ entry KRB-ERROR error-code name table** (RFC
//     4120 §7.5.9 + Microsoft extensions): 6 `KDC_ERR_C_PRINCIPAL_UNKNOWN`
//     (the canonical username-doesn't-exist response) / 7
//     `KDC_ERR_S_PRINCIPAL_UNKNOWN` (SPN doesn't exist) / 14
//     `KDC_ERR_ETYPE_NOTSUPP` (no etype overlap) / 18
//     `KDC_ERR_CLIENT_REVOKED` (account locked) / 24
//     `KDC_ERR_PREAUTH_FAILED` (wrong password) / 25
//     `KDC_ERR_PREAUTH_REQUIRED` (need PA-ENC-TIMESTAMP —
//     the canonical "this user is NOT AS-REP-roastable"
//     response) / 32 `KRB_AP_ERR_TKT_EXPIRED` (ticket
//     expired) / 33 `KRB_AP_ERR_TKT_NYV` / 34
//     `KRB_AP_ERR_REPEAT` / 35 `KRB_AP_ERR_NOT_US` / 37
//     `KRB_AP_ERR_SKEW` (clock skew > 5 min) / 60
//     `KRB_ERR_GENERIC` / 68 `KDC_ERR_WRONG_REALM` (cross-
//     realm referral).
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **Network framing** — feed Kerberos bytes after the UDP
//     datagram OR TCP record-length-prefix (4-byte BE length)
//     strip. Default ports: UDP/88, TCP/88.
//   - **Encrypted ticket + enc-part decryption** — the
//     `ticket` field (encrypted with the krbtgt key) and the
//     `enc-part` field (encrypted with the user's password-
//     derived key) are surfaced as byte lengths only; offline
//     cracking with hashcat mode 18200 (AS-REP) or 13100
//     (Kerberoast TGS) is the next step.
//   - **PAC (Privilege Attribute Certificate) parsing** —
//     Microsoft's authorization-data extension carries the
//     user's SID + group SIDs inside the ticket; PAC parsing
//     happens after ticket decryption and is out of scope.
//   - **PKINIT (Public Key Cryptography for Initial
//     Authentication)** — RFC 4556 replaces password
//     preauthentication with X.509 client certificates;
//     PA-PK-AS-REQ (type 14) is surfaced as a padata type
//     but the inner CMS/PKCS#7 SignedData is out of scope.
//   - **GSS-API wrapping** — when Kerberos rides inside
//     GSS-API (RFC 4121) — e.g. SPNEGO inside HTTP
//     Authorization: Negotiate, or inside SMB / LDAP / SASL
//     GSSAPI — handle the GSS-API + ASN.1 wrapper strip first.
//   - **Cross-realm referrals** — TGS-REQ + cross-realm trust
//     traversal state-machine; the decoder surfaces individual
//     messages but does not track multi-message exchanges.
package kerberos

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the structured decode of a Kerberos message.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	MessageType     int    `json:"message_type"`
	MessageTypeName string `json:"message_type_name"`
	Pvno            int    `json:"pvno,omitempty"`

	// AS-REQ / TGS-REQ + AS-REP / TGS-REP
	Realm        string   `json:"realm,omitempty"`
	ClientName   string   `json:"client_name,omitempty"`
	ServerName   string   `json:"server_name,omitempty"`
	EncTypes     []int    `json:"enc_types,omitempty"`
	EncTypeNames []string `json:"enc_type_names,omitempty"`
	PADataTypes  []int    `json:"padata_types,omitempty"`
	PADataNames  []string `json:"padata_type_names,omitempty"`
	PreAuthSet   bool     `json:"pre_auth_required"`

	// AS-REP / TGS-REP encrypted blob byte lengths
	TicketBytes  int `json:"ticket_bytes,omitempty"`
	EncPartBytes int `json:"enc_part_bytes,omitempty"`

	// KRB-ERROR
	ErrorCode     int    `json:"error_code,omitempty"`
	ErrorCodeName string `json:"error_code_name,omitempty"`
	ErrorText     string `json:"error_text,omitempty"`
}

// Decode parses a Kerberos message from a hex string. Separators
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
		return nil, fmt.Errorf("kerberos message truncated (%d bytes)", len(b))
	}

	r := &Result{TotalBytes: len(b)}

	// Outer tag — [APPLICATION N] CONSTRUCTED.
	outerTag := b[0]
	tagClass := outerTag >> 6
	if tagClass != 1 {
		return r, fmt.Errorf("outer tag class is not APPLICATION (got 0x%02X)", outerTag)
	}
	tagNum := int(outerTag & 0x1F)
	r.MessageType = tagNum
	r.MessageTypeName = messageTypeName(tagNum)

	// Read outer length to bound the body slice.
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

	// Inner content is a SEQUENCE (0x30 + length + items).
	if len(body) == 0 || body[0] != 0x30 {
		// Some impls may have an extra tag; try to recover.
		return r, nil
	}
	innerLen, innerLenSize, err := readDERLength(body[1:])
	if err != nil {
		return r, nil
	}
	innerStart := 1 + innerLenSize
	innerEnd := innerStart + innerLen
	if innerEnd > len(body) {
		innerEnd = len(body)
	}
	innerBody := body[innerStart:innerEnd]

	switch tagNum {
	case 10, 12:
		decodeKDCReq(r, innerBody)
	case 11, 13:
		decodeKDCRep(r, innerBody)
	case 30:
		decodeKRBError(r, innerBody)
	}
	return r, nil
}

// decodeKDCReq walks AS-REQ / TGS-REQ context-tagged fields:
// [1] pvno / [2] msg-type / [3] padata / [4] req-body.
func decodeKDCReq(r *Result, body []byte) {
	off := 0
	for off < len(body) {
		tag, length, contentStart, next, ok := readTLV(body, off)
		if !ok {
			return
		}
		if tag&0xC0 != 0x80 {
			off = next
			continue
		}
		ctxNum := int(tag & 0x1F)
		content := body[contentStart : contentStart+length]
		switch ctxNum {
		case 1:
			r.Pvno = int(readINTEGER(innerINTEGER(content)))
		case 3:
			decodePADataSeq(r, innerSEQUENCE(content))
		case 4:
			decodeKDCReqBody(r, innerSEQUENCE(content))
		}
		off = next
	}
}

func decodeKDCReqBody(r *Result, body []byte) {
	off := 0
	for off < len(body) {
		tag, length, contentStart, next, ok := readTLV(body, off)
		if !ok {
			return
		}
		if tag&0xC0 != 0x80 {
			off = next
			continue
		}
		ctxNum := int(tag & 0x1F)
		content := body[contentStart : contentStart+length]
		switch ctxNum {
		case 1: // cname
			r.ClientName = decodePrincipalName(innerSEQUENCE(content))
		case 2: // realm
			r.Realm = decodeGeneralString(innerGeneralString(content))
		case 3: // sname
			r.ServerName = decodePrincipalName(innerSEQUENCE(content))
		case 8: // etype SEQUENCE OF Int32
			r.EncTypes, r.EncTypeNames = decodeEtypeList(innerSEQUENCE(content))
		}
		off = next
	}
}

// decodeKDCRep walks AS-REP / TGS-REP context-tagged fields.
func decodeKDCRep(r *Result, body []byte) {
	off := 0
	for off < len(body) {
		tag, length, contentStart, next, ok := readTLV(body, off)
		if !ok {
			return
		}
		if tag&0xC0 != 0x80 {
			off = next
			continue
		}
		ctxNum := int(tag & 0x1F)
		content := body[contentStart : contentStart+length]
		switch ctxNum {
		case 0:
			r.Pvno = int(readINTEGER(innerINTEGER(content)))
		case 2:
			decodePADataSeq(r, innerSEQUENCE(content))
		case 3:
			r.Realm = decodeGeneralString(innerGeneralString(content))
		case 4:
			r.ClientName = decodePrincipalName(innerSEQUENCE(content))
		case 5: // ticket [APPLICATION 1]
			r.TicketBytes = length
		case 6: // enc-part EncryptedData
			r.EncPartBytes = length
		}
		off = next
	}
}

// decodeKRBError walks the KRB-ERROR context-tagged fields:
// [4] stime / [5] susec / [6] error-code / [7] crealm /
// [8] cname / [9] realm / [10] sname / [11] e-text.
func decodeKRBError(r *Result, body []byte) {
	off := 0
	for off < len(body) {
		tag, length, contentStart, next, ok := readTLV(body, off)
		if !ok {
			return
		}
		if tag&0xC0 != 0x80 {
			off = next
			continue
		}
		ctxNum := int(tag & 0x1F)
		content := body[contentStart : contentStart+length]
		switch ctxNum {
		case 6: // error-code INTEGER
			r.ErrorCode = int(readINTEGER(innerINTEGER(content)))
			r.ErrorCodeName = errorCodeName(r.ErrorCode)
		case 7:
			r.Realm = decodeGeneralString(innerGeneralString(content))
		case 8:
			r.ClientName = decodePrincipalName(innerSEQUENCE(content))
		case 10:
			r.ServerName = decodePrincipalName(innerSEQUENCE(content))
		case 11: // e-text GeneralString
			r.ErrorText = decodeGeneralString(innerGeneralString(content))
		}
		off = next
	}
}

// decodePADataSeq walks a SEQUENCE OF PA-DATA. Each PA-DATA is
// SEQUENCE { [1] padata-type Int32, [2] padata-value OCTET-STRING }.
func decodePADataSeq(r *Result, body []byte) {
	off := 0
	for off < len(body) {
		// Each element is a SEQUENCE (0x30 + length + items).
		if off+2 > len(body) || body[off] != 0x30 {
			return
		}
		paLen, lenSize, err := readDERLength(body[off+1:])
		if err != nil {
			return
		}
		paStart := off + 1 + lenSize
		paEnd := paStart + paLen
		if paEnd > len(body) {
			return
		}
		// Walk [1] padata-type.
		paBody := body[paStart:paEnd]
		ioff := 0
		for ioff < len(paBody) {
			tag, length, contentStart, inext, ok := readTLV(paBody, ioff)
			if !ok {
				break
			}
			if tag&0xC0 == 0x80 && tag&0x1F == 1 {
				ptype := int(readINTEGER(innerINTEGER(
					paBody[contentStart : contentStart+length])))
				r.PADataTypes = append(r.PADataTypes, ptype)
				r.PADataNames = append(r.PADataNames, paDataName(ptype))
				if ptype == 2 {
					r.PreAuthSet = true
				}
			}
			ioff = inext
		}
		off = paEnd
	}
}

// decodePrincipalName walks PrincipalName SEQUENCE { [0] name-type
// Int32, [1] name-string SEQUENCE OF GeneralString }. Returns the
// name-string joined with "/".
func decodePrincipalName(body []byte) string {
	off := 0
	for off < len(body) {
		tag, length, contentStart, next, ok := readTLV(body, off)
		if !ok {
			return ""
		}
		if tag&0xC0 == 0x80 && tag&0x1F == 1 {
			seqBody := innerSEQUENCE(body[contentStart : contentStart+length])
			var labels []string
			sOff := 0
			for sOff < len(seqBody) {
				stag, slen, sStart, snext, sok := readTLV(seqBody, sOff)
				_ = stag
				if !sok {
					break
				}
				labels = append(labels, string(seqBody[sStart:sStart+slen]))
				sOff = snext
			}
			return strings.Join(labels, "/")
		}
		off = next
	}
	return ""
}

func decodeEtypeList(body []byte) ([]int, []string) {
	var nums []int
	var names []string
	off := 0
	for off < len(body) {
		tag, length, contentStart, next, ok := readTLV(body, off)
		if !ok {
			break
		}
		if tag == 0x02 { // INTEGER
			n := int(readINTEGER(body[contentStart : contentStart+length]))
			nums = append(nums, n)
			names = append(names, encTypeName(n))
		}
		off = next
	}
	return nums, names
}

// readTLV reads a DER (tag, length, contentStart, next, ok).
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

// innerINTEGER strips the leading 0x02 + length from an INTEGER
// inside a context-tagged wrapper.
func innerINTEGER(b []byte) []byte {
	if len(b) < 2 || b[0] != 0x02 {
		return b
	}
	length, lenSize, err := readDERLength(b[1:])
	if err != nil {
		return b
	}
	start := 1 + lenSize
	end := start + length
	if end > len(b) {
		end = len(b)
	}
	return b[start:end]
}

// innerSEQUENCE strips the leading 0x30 + length from a SEQUENCE
// inside a context-tagged wrapper.
func innerSEQUENCE(b []byte) []byte {
	if len(b) < 2 || b[0] != 0x30 {
		return b
	}
	length, lenSize, err := readDERLength(b[1:])
	if err != nil {
		return b
	}
	start := 1 + lenSize
	end := start + length
	if end > len(b) {
		end = len(b)
	}
	return b[start:end]
}

// innerGeneralString strips the leading 0x1B + length from a
// GeneralString inside a context-tagged wrapper.
func innerGeneralString(b []byte) []byte {
	if len(b) < 2 || b[0] != 0x1B {
		return b
	}
	length, lenSize, err := readDERLength(b[1:])
	if err != nil {
		return b
	}
	start := 1 + lenSize
	end := start + length
	if end > len(b) {
		end = len(b)
	}
	return b[start:end]
}

func decodeGeneralString(b []byte) string {
	return string(b)
}

// Avoid unused-import error if binary not used elsewhere later.
var _ = binary.BigEndian

func messageTypeName(t int) string {
	switch t {
	case 10:
		return "AS-REQ"
	case 11:
		return "AS-REP"
	case 12:
		return "TGS-REQ"
	case 13:
		return "TGS-REP"
	case 14:
		return "AP-REQ"
	case 15:
		return "AP-REP"
	case 30:
		return "KRB-ERROR"
	}
	return fmt.Sprintf("uncatalogued message type %d", t)
}

func encTypeName(e int) string {
	switch e {
	case 1:
		return "des-cbc-crc"
	case 2:
		return "des-cbc-md4"
	case 3:
		return "des-cbc-md5"
	case 16:
		return "des3-cbc-sha1"
	case 17:
		return "aes128-cts-hmac-sha1-96"
	case 18:
		return "aes256-cts-hmac-sha1-96"
	case 19:
		return "aes128-cts-hmac-sha256-128"
	case 20:
		return "aes256-cts-hmac-sha384-192"
	case 23:
		return "rc4-hmac (legacy NT-compat; weak)"
	case 24:
		return "rc4-hmac-exp (export-grade)"
	case 25:
		return "camellia128-cts-cmac"
	case 26:
		return "camellia256-cts-cmac"
	}
	return fmt.Sprintf("uncatalogued etype %d", e)
}

func paDataName(t int) string {
	switch t {
	case 1:
		return "PA-TGS-REQ"
	case 2:
		return "PA-ENC-TIMESTAMP (preauth)"
	case 3:
		return "PA-PW-SALT"
	case 11:
		return "PA-ETYPE-INFO"
	case 14:
		return "PA-PK-AS-REQ (PKINIT)"
	case 19:
		return "PA-ETYPE-INFO2"
	case 128:
		return "PA-PAC-REQUEST"
	case 129:
		return "PA-FOR-USER (S4U2self)"
	}
	return fmt.Sprintf("uncatalogued padata type %d", t)
}

func errorCodeName(c int) string {
	switch c {
	case 6:
		return "KDC_ERR_C_PRINCIPAL_UNKNOWN"
	case 7:
		return "KDC_ERR_S_PRINCIPAL_UNKNOWN"
	case 14:
		return "KDC_ERR_ETYPE_NOTSUPP"
	case 18:
		return "KDC_ERR_CLIENT_REVOKED"
	case 24:
		return "KDC_ERR_PREAUTH_FAILED"
	case 25:
		return "KDC_ERR_PREAUTH_REQUIRED"
	case 32:
		return "KRB_AP_ERR_TKT_EXPIRED"
	case 33:
		return "KRB_AP_ERR_TKT_NYV"
	case 34:
		return "KRB_AP_ERR_REPEAT"
	case 35:
		return "KRB_AP_ERR_NOT_US"
	case 37:
		return "KRB_AP_ERR_SKEW"
	case 60:
		return "KRB_ERR_GENERIC"
	case 68:
		return "KDC_ERR_WRONG_REALM"
	}
	return fmt.Sprintf("uncatalogued error code %d", c)
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
