// ldap.go — host-side LDAP v3 message decoder Spec. Wraps the
// internal/ldap walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ldap"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(ldapDecodeSpec)
}

var ldapDecodeSpec = Spec{
	Name: "ldap_decode",
	Description: "Decode an LDAP v3 (Lightweight Directory Access Protocol) " +
		"message per RFC 4511 — the canonical directory-service protocol " +
		"used by **every Active Directory deployment** + most enterprise " +
		"IAM stacks (Microsoft AD LDS, OpenLDAP, 389 Directory Server, " +
		"FreeIPA / IdM, Apple Open Directory, Apache Directory Server, " +
		"Oracle Internet Directory, Novell eDirectory). LDAP runs over " +
		"TCP/389 (cleartext), TCP/636 (LDAPS — implicit TLS), and UDP/389 " +
		"(CLDAP — connectionless LDAP, used by Microsoft NetLogon for " +
		"site/DC discovery). Canonical AD-pentest decoder paired with " +
		"`kerberos_decode` for the complete AD directory-attack dissector. " +
		"The wire format leaks: **cleartext credentials via SimpleBind** " +
		"(BindRequest authentication CHOICE [0] simple OCTET STRING " +
		"carries the password IN CLEARTEXT — observing one such request on " +
		"TCP/389 yields the password directly; AD allows simple-bind over " +
		"cleartext by default); **username + DN enumeration via " +
		"SearchRequest** (baseObject reveals the search root — typically " +
		"the AD domain DC=corp,DC=example,DC=com; SearchResultEntry " +
		"frames leak the matched DN — every user / computer / group " +
		"account); **brute-force feedback via resultCode** (49 " +
		"invalidCredentials = wrong password; 0 success = working " +
		"credential — password-spray tools like kerbrute consume this " +
		"directly); **CLDAP NetLogon enumeration** (anonymous UDP/389 " +
		"rootDSE query leaks DC site + GUID + DnsHostName + flags); " +
		"**SASL mechanism enumeration** (rootDSE supportedSASLMechanisms " +
		"lists GSSAPI / GSS-SPNEGO / DIGEST-MD5 / CRAM-MD5 / EXTERNAL / " +
		"PLAIN). Decodes:\n\n" +
		"- **22-entry operation name table** (RFC 4511 §4.1.1): " +
		"[APPLICATION 0] `0x60` BindRequest / [APPLICATION 1] `0x61` " +
		"BindResponse / [APPLICATION 2] `0x42` UnbindRequest / " +
		"[APPLICATION 3] `0x63` SearchRequest / [APPLICATION 4] `0x64` " +
		"SearchResultEntry / [APPLICATION 5] `0x65` SearchResultDone / " +
		"[APPLICATION 6] `0x66` ModifyRequest / [APPLICATION 7] `0x67` " +
		"ModifyResponse / [APPLICATION 8] `0x68` AddRequest / " +
		"[APPLICATION 9] `0x69` AddResponse / [APPLICATION 10] `0x4A` " +
		"DelRequest / [APPLICATION 11] `0x6B` DelResponse / " +
		"[APPLICATION 12] `0x6C` ModifyDNRequest / [APPLICATION 13] `0x6D` " +
		"ModifyDNResponse / [APPLICATION 14] `0x6E` CompareRequest / " +
		"[APPLICATION 15] `0x6F` CompareResponse / [APPLICATION 16] `0x50` " +
		"AbandonRequest / [APPLICATION 19] `0x73` SearchResultReference / " +
		"[APPLICATION 23] `0x77` ExtendedRequest / [APPLICATION 24] `0x78` " +
		"ExtendedResponse / [APPLICATION 25] `0x79` IntermediateResponse.\n" +
		"- **BindRequest body** (§4.2): version=3 / name (the username / " +
		"UPN / DN — leakable!) / authentication CHOICE [0] simple OCTET " +
		"STRING (cleartext password!) or [3] sasl SaslCredentials. " +
		"Surfaces `bind_name` + `bind_auth_type` (simple / sasl) + " +
		"`simple_bind_present` (cleartext-creds classification!) + " +
		"`bind_password_bytes` (LENGTH ONLY — not the password itself, " +
		"privacy-preserving) + `sasl_mechanism` (when SASL is used; " +
		"GSSAPI = Kerberos integration).\n" +
		"- **BindResponse body** (§4.2.2): SEQUENCE { resultCode " +
		"ENUMERATED / matchedDN / diagnosticMessage }. Surfaces " +
		"`result_code` + `result_code_name`.\n" +
		"- **SearchRequest body** (§4.5.1): SEQUENCE { baseObject / " +
		"scope ENUMERATED { baseObject(0), singleLevel(1), " +
		"wholeSubtree(2), subordinateSubtree(3) } / sizeLimit / " +
		"timeLimit / filter / attributes }. Surfaces " +
		"`search_base_object` + `search_scope` + `search_scope_name` + " +
		"`search_size_limit` + `search_time_limit` + `filter_bytes` " +
		"length.\n" +
		"- **SearchResultEntry body** (§4.5.2): SEQUENCE { objectName / " +
		"attributes }. Surfaces `entry_object_name` (the DN — directory " +
		"enumeration leak!).\n" +
		"- **17-entry resultCode name table** (§4.1.9): 0 success / 1 " +
		"operationsError / 2 protocolError / 4 sizeLimitExceeded / 7 " +
		"authMethodNotSupported / 8 strongerAuthRequired / 10 referral / " +
		"11 adminLimitExceeded / 13 confidentialityRequired / 14 " +
		"saslBindInProgress / 16 noSuchAttribute / 32 noSuchObject / 48 " +
		"inappropriateAuthentication / 49 invalidCredentials (brute-force " +
		"feedback!) / 50 insufficientAccessRights / 51 busy / 53 " +
		"unwillingToPerform.\n" +
		"- **4-entry search scope name table** (§4.5.1): 0 baseObject / " +
		"1 singleLevel / 2 wholeSubtree (canonical full-directory-dump) / " +
		"3 subordinateSubtree.\n\n" +
		"Pure offline parser — operators paste LDAP bytes (the TCP-" +
		"segment payload as hex; default ports TCP/389 cleartext + 636 " +
		"LDAPS, UDP/389 CLDAP) from a `tcpdump -X port 389` line or a " +
		"Wireshark LDAP dissector view and get the documented per-op " +
		"breakdown.\n\n" +
		"Out of scope (deferred): network framing (feed bytes after the " +
		"TCP-segment header strip); LDAPS / StartTLS (TCP/636 wraps LDAP " +
		"in TLS; StartTLS via ExtendedRequest OID 1.3.6.1.4.1.1466.20037 " +
		"upgrades TCP/389 — handle TLS strip first); LDAP filter parser " +
		"(the `filter` field is a Filter CHOICE per §4.5.1 + RFC 4515 — " +
		"its own nested grammar with and/or/not/equalityMatch/substrings/" +
		"greaterOrEqual/lessOrEqual/present/approxMatch/extensibleMatch; " +
		"surfaced as `filter_bytes` length only); SASL mechanism inner-" +
		"decode (GSSAPI carries Kerberos AP-REQ — already handled by " +
		"`kerberos_decode`; SCRAM-SHA-256 / DIGEST-MD5 / CRAM-MD5 " +
		"out of scope); controls parsing ([0] controls Controls OPTIONAL " +
		"at end of LDAPMessage — paging / sort / deleted-objects / VLV " +
		"surfaced as bytes-length only); MS NetLogon / CLDAP rootDSE " +
		"NETLOGON_SAM_LOGON_RESPONSE_EX binary layout; schema parsing.\n\n" +
		"Source: docs/catalog/gap-analysis.md (AD-pentest foundational " +
		"decoder — pairs with kerberos_decode (v0.330) for the complete " +
		"AD directory-attack dissector; canonical decode for AD LDS / " +
		"OpenLDAP / 389 Directory Server / FreeIPA / Apple Open Directory " +
		"/ Apache Directory Server / Oracle Internet Directory / Novell " +
		"eDirectory; common in DEF CON + Black Hat + HITB + OffSec AD " +
		"pentests + every internal red-team Windows engagement). Wrap-vs-" +
		"native: native — RFC 4511 is publicly available; LDAP v3 " +
		"messages are ASN.1 BER-encoded SEQUENCEs with an outer messageID " +
		"INTEGER + context-tagged [APPLICATION N] protocolOp CHOICE; the " +
		"DER walker is the same shape as internal/kerberos; no third-" +
		"party ASN.1 dependency; no crypto at the parse layer; password " +
		"length surfaced (NOT the password itself — privacy-preserving " +
		"while still flagging the simple-bind exposure).",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"LDAP message bytes as hex (the TCP-segment payload; default ports TCP/389 cleartext + 636 LDAPS, UDP/389 CLDAP). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ldapDecodeHandler,
}

func ldapDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("ldap_decode: 'hex' is required")
	}
	res, err := ldap.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("ldap_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
