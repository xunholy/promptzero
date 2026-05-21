// kerberos.go — host-side Kerberos v5 message decoder Spec.
// Wraps the internal/kerberos walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/kerberos"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(kerberosDecodeSpec)
}

var kerberosDecodeSpec = Spec{
	Name: "kerberos_decode",
	Description: "Decode a Kerberos v5 message per RFC 4120 (the authentication " +
		"protocol underpinning **every Active Directory deployment** + most " +
		"enterprise SSO stacks: MIT Kerberos, Heimdal, Microsoft Active " +
		"Directory, Apple Open Directory, FreeIPA / IdM, Samba 4 KDC). " +
		"Kerberos rides over UDP/88 (the common case — requests under MTU) " +
		"and TCP/88 (large requests with PAC inflation). Canonical AD-pentest " +
		"decoder — **the highest-value AD dissector in the catalogue** — " +
		"because the wire format leaks: **username enumeration** (every " +
		"AS-REQ carries `cname` in cleartext — observe AS-REQ traffic to " +
		"enumerate every account actively authenticating); **AS-REP " +
		"roasting** (when an account has DONT_REQ_PREAUTH = 0x400000 in " +
		"UserAccountControl, the KDC accepts an AS-REQ with NO " +
		"PA-ENC-TIMESTAMP padata and returns an AS-REP whose enc-part is " +
		"encrypted with the user's password-derived key — directly crackable " +
		"with hashcat mode 18200 against rockyou); **encryption type " +
		"downgrade** (`etype` reveals whether the client / KDC supports " +
		"legacy rc4-hmac = etype 23 — Windows NT compat, weak offline " +
		"cracking); **realm + SPN disclosure** (`realm` reveals the AD " +
		"domain like CORP.EXAMPLE.COM; `sname` reveals the target SPN — " +
		"`krbtgt/CORP.EXAMPLE.COM` for AS-REQ, or " +
		"`MSSQLSvc/sql01.corp.example.com:1433` for TGS-REQ against a SQL " +
		"Server — the SPN enumeration goldmine for Kerberoasting target " +
		"selection); **Kerberoasting recon** (observe TGS-REQ traffic to " +
		"enumerate which SPNs are actively being requested, pre-targeting " +
		"high-privilege service accounts that yield the best Kerberoast " +
		"crack candidates). Decodes:\n\n" +
		"- **7-entry message type name table** (RFC 4120 §5.10): " +
		"[APPLICATION 10] `0x6A` AS-REQ (initial TGT request) / " +
		"[APPLICATION 11] `0x6B` AS-REP (TGT response — AS-REP-roastable " +
		"material!) / [APPLICATION 12] `0x6C` TGS-REQ (per-service ticket " +
		"request — Kerberoast initiator!) / [APPLICATION 13] `0x6D` TGS-REP " +
		"(per-service ticket response — Kerberoastable material!) / " +
		"[APPLICATION 14] `0x6E` AP-REQ (client authenticates to service) " +
		"/ [APPLICATION 15] `0x6F` AP-REP (mutual auth) / [APPLICATION 30] " +
		"`0x7E` KRB-ERROR (error response).\n" +
		"- **AS-REQ / TGS-REQ body** (KDC-REQ-BODY, §5.4.1): inner SEQUENCE " +
		"context-tagged fields [1] pvno=5 / [2] msg-type / [3] padata / " +
		"[4] req-body { [1] cname PrincipalName / [2] realm GeneralString " +
		"/ [3] sname PrincipalName / [8] etype SEQUENCE OF Int32 }; " +
		"PrincipalName name-string joined with '/' (e.g. `krbtgt/REALM` " +
		"or `MSSQLSvc/host:port`).\n" +
		"- **`pre_auth_required` boolean** — surfaces whether " +
		"PA-ENC-TIMESTAMP (padata type 2) is present in the padata list. " +
		"**When false, the account is AS-REP roastable** (request the AS-" +
		"REP, extract enc-part, hashcat -m 18200 against the user's " +
		"password).\n" +
		"- **11-entry Encryption Type name table** (RFC 3961 + extensions): " +
		"1 des-cbc-crc / 2 des-cbc-md4 / 3 des-cbc-md5 / 16 des3-cbc-sha1 " +
		"/ 17 aes128-cts-hmac-sha1-96 / 18 aes256-cts-hmac-sha1-96 / 19 " +
		"aes128-cts-hmac-sha256-128 / 20 aes256-cts-hmac-sha384-192 / 23 " +
		"rc4-hmac (legacy NT-compat; weak) / 24 rc4-hmac-exp (export-" +
		"grade) / 25 camellia128-cts-cmac / 26 camellia256-cts-cmac.\n" +
		"- **8-entry PA-DATA type name table** (§7.5.2 + extensions): 1 " +
		"PA-TGS-REQ / 2 PA-ENC-TIMESTAMP (preauth!) / 3 PA-PW-SALT / 11 " +
		"PA-ETYPE-INFO / 14 PA-PK-AS-REQ (PKINIT) / 19 PA-ETYPE-INFO2 / " +
		"128 PA-PAC-REQUEST (Windows PAC) / 129 PA-FOR-USER (S4U2self).\n" +
		"- **AS-REP / TGS-REP body** (KDC-REP, §5.4.2): inner SEQUENCE " +
		"[0] pvno / [1] msg-type / [2] padata / [3] crealm / [4] cname / " +
		"[5] ticket (encrypted with krbtgt key — byte length surfaced) / " +
		"[6] enc-part (encrypted with user's password-derived key — byte " +
		"length surfaced, the AS-REP-roastable material!).\n" +
		"- **KRB-ERROR body** (§5.9.1): context-tagged inner SEQUENCE [6] " +
		"error-code / [7] crealm / [9] realm / [10] sname / [11] e-text.\n" +
		"- **13-entry KRB-ERROR error-code name table** (§7.5.9 + " +
		"Microsoft extensions): 6 KDC_ERR_C_PRINCIPAL_UNKNOWN (canonical " +
		"username-doesn't-exist response — great for username enumeration " +
		"sweeps) / 7 KDC_ERR_S_PRINCIPAL_UNKNOWN / 14 KDC_ERR_ETYPE_NOTSUPP " +
		"/ 18 KDC_ERR_CLIENT_REVOKED (account locked) / 24 " +
		"KDC_ERR_PREAUTH_FAILED (wrong password) / 25 " +
		"KDC_ERR_PREAUTH_REQUIRED (canonical \"this user is NOT AS-REP " +
		"roastable\" response — preauth ON) / 32 KRB_AP_ERR_TKT_EXPIRED " +
		"/ 33 KRB_AP_ERR_TKT_NYV / 34 KRB_AP_ERR_REPEAT / 35 " +
		"KRB_AP_ERR_NOT_US / 37 KRB_AP_ERR_SKEW (clock skew > 5 min) / 60 " +
		"KRB_ERR_GENERIC / 68 KDC_ERR_WRONG_REALM (cross-realm referral).\n\n" +
		"Pure offline parser — operators paste Kerberos bytes (the UDP " +
		"datagram payload OR the TCP record after the 4-byte BE length " +
		"prefix strip; default ports UDP/88 + TCP/88) from a `tcpdump -X " +
		"port 88` line or a Wireshark KRB5 dissector view and get the " +
		"documented per-message-type breakdown.\n\n" +
		"Out of scope (deferred): network framing (feed bytes after the " +
		"UDP datagram OR TCP 4-byte BE length-prefix strip); encrypted " +
		"ticket + enc-part decryption (surfaced as byte lengths only; " +
		"hashcat mode 18200 AS-REP / mode 13100 Kerberoast TGS is the " +
		"offline-crack next step); PAC (Privilege Attribute Certificate) " +
		"parsing (Microsoft's authorization-data extension carries the " +
		"user's SID + group SIDs inside the ticket; happens after ticket " +
		"decrypt and is out of scope); PKINIT (RFC 4556 X.509-based " +
		"preauth; PA-PK-AS-REQ surfaced as a padata type but the inner " +
		"CMS/PKCS#7 SignedData is out of scope); GSS-API wrapping (RFC " +
		"4121; when Kerberos rides inside SPNEGO + HTTP Authorization: " +
		"Negotiate / SMB / LDAP / SASL GSSAPI, handle the wrapper strip " +
		"first); cross-realm referral state-machine.\n\n" +
		"Source: docs/catalog/gap-analysis.md (AD-pentest foundational " +
		"decoder — the canonical Kerberos wire dissector for AS-REP " +
		"roasting + Kerberoasting + username enumeration + encryption-" +
		"type downgrade audit; common in DEF CON + Black Hat + HITB AD " +
		"pentests + every internal red-team engagement against a Windows " +
		"environment). Wrap-vs-native: native — RFC 4120 is publicly " +
		"available; Kerberos uses ASN.1 DER with fixed [APPLICATION N] " +
		"outer tags + context-tagged [N] CONSTRUCTED inner fields; the " +
		"decoder includes a small focused DER walker (short/long-form " +
		"length, INTEGER, GeneralString, SEQUENCE / SEQUENCE-OF, context-" +
		"tag discrimination); encrypted parts surfaced as byte counts " +
		"only — no crypto at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Kerberos message bytes as hex (the UDP datagram payload OR the TCP record after the 4-byte BE length-prefix strip; default ports UDP/88 + TCP/88). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   kerberosDecodeHandler,
}

func kerberosDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("kerberos_decode: 'hex' is required")
	}
	res, err := kerberos.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("kerberos_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
