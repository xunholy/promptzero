// ntlm.go — host-side NTLM message decoder Spec.
// Wraps the internal/ntlm walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ntlm"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(ntlmDecodeSpec)
}

var ntlmDecodeSpec = Spec{
	Name: "ntlm_decode",
	Description: "Decode an NTLM (NT LAN Manager) message per Microsoft Open Protocol " +
		"Specifications MS-NLMP. NTLM is the challenge-response authentication " +
		"protocol used pervasively on Windows networks: SMB/CIFS sessions " +
		"authenticate via NTLM in SESSION_SETUP_ANDX; HTTP IIS / Exchange / " +
		"SharePoint use `Authorization: NTLM <base64>` headers; LDAP / LDAPS " +
		"binds use NTLM as a SASL mechanism when Kerberos is unavailable; legacy " +
		"MS-RPC / DCERPC over named pipes embeds NTLM in bind PDUs. Universally " +
		"observed in Windows-heavy enterprise + AD-joined infrastructure even in " +
		"Kerberos-preferring deployments (NTLM remains a fallback for non-domain " +
		"access, legacy applications, and stale device caches). High pentest + " +
		"DFIR value — Type 2 ServerChallenge + Type 3 NtChallengeResponse feed " +
		"directly into hashcat modes 5500 / 5600 for offline password recovery. " +
		"Decodes:\n\n" +
		"- **12-byte common header**: 8-byte ASCII signature 'NTLMSSP\\x00' " +
		"(validated; mismatches return error) + 4-byte **MessageType** (little-" +
		"endian uint32) with **3-entry name table**: 1 NEGOTIATE_MESSAGE / 2 " +
		"CHALLENGE_MESSAGE / 3 AUTHENTICATE_MESSAGE.\n" +
		"- **NEGOTIATE_MESSAGE (Type 1)** body: NegotiateFlags + Domain fields " +
		"(Len/MaxLen/Offset) + Workstation fields + optional Version + payload " +
		"strings (encoded per OEM/UNICODE flag).\n" +
		"- **CHALLENGE_MESSAGE (Type 2)** body: TargetName fields + NegotiateFlags " +
		"+ **8-byte ServerChallenge** (the random challenge crackable via hashcat " +
		"mode 5500 NTLMv1 / 5600 NTLMv2) + Reserved + TargetInfo fields + " +
		"optional Version + payload (TargetName string + TargetInfo AV pair list).\n" +
		"- **AV Pair walker** (inside CHALLENGE TargetInfo): (AvId uint16 LE + " +
		"AvLen uint16 LE + Value) records ending at AvId 0 (MsvAvEOL). " +
		"**10-entry AvId name table**: 1 MsvAvNbComputerName / 2 MsvAvNbDomainName " +
		"/ 3 MsvAvDnsComputerName / 4 MsvAvDnsDomainName / 5 MsvAvDnsTreeName / 6 " +
		"MsvAvFlags / 7 MsvAvTimestamp / 8 MsvAvSingleHost / 9 MsvAvTargetName / " +
		"10 MsvAvChannelBindings. AV pair values 1-5 surfaced as decoded UTF-16LE " +
		"text.\n" +
		"- **AUTHENTICATE_MESSAGE (Type 3)** body: LmChallengeResponse fields + " +
		"**NtChallengeResponse fields** (the actual hash response, hashcat-" +
		"crackable) + DomainName + UserName + Workstation + " +
		"EncryptedRandomSessionKey + NegotiateFlags + optional Version + optional " +
		"MIC (Message Integrity Check) + payload.\n" +
		"- **NegotiateFlags decode** (MS-NLMP §2.2.2.5) — **~22-entry named-bit " +
		"set**: NEGOTIATE_UNICODE / NEGOTIATE_OEM / REQUEST_TARGET / " +
		"NEGOTIATE_SIGN / NEGOTIATE_SEAL / NEGOTIATE_DATAGRAM / NEGOTIATE_LM_KEY " +
		"/ NEGOTIATE_NTLM / ANONYMOUS_CONNECTION / " +
		"NEGOTIATE_OEM_DOMAIN_SUPPLIED / NEGOTIATE_OEM_WORKSTATION_SUPPLIED / " +
		"NEGOTIATE_ALWAYS_SIGN / TARGET_TYPE_DOMAIN / TARGET_TYPE_SERVER / " +
		"NEGOTIATE_EXTENDED_SESSIONSECURITY / NEGOTIATE_TARGET_INFO / " +
		"NEGOTIATE_IDENTIFY / REQUEST_NON_NT_SESSION_KEY / " +
		"NEGOTIATE_TARGET_INFO_AV_PAIRS / NEGOTIATE_VERSION / NEGOTIATE_128 / " +
		"NEGOTIATE_KEY_EXCH / NEGOTIATE_56.\n" +
		"- **Version structure** (MS-NLMP §2.2.2.10) — when NEGOTIATE_VERSION " +
		"flag set: Major + Minor + Build + Reserved + NTLMRevisionCurrent " +
		"(rendered as canonical 'X.Y build N (NTLM revision R)' string).\n\n" +
		"Pure offline parser — operators paste the raw NTLMSSP bytes already " +
		"extracted from SMB SESSION_SETUP, HTTP 'Authorization: NTLM <base64>' " +
		"(base64-decoded), LDAP bind, or DCE bind PDU.\n\n" +
		"Out of scope (deferred): Transport framing (NTLM is embedded inside SMB " +
		"/ HTTP / LDAP / DCERPC — caller extracts the raw NTLMSSP blob before " +
		"feeding into this Spec; base64 decoding is caller's job for HTTP); " +
		"cryptographic verification of NT/LM responses (surfaced as hex; " +
		"verifying an NTLMv1 / NTLMv2 response requires the user's NT hash and " +
		"the matching Type 2 ServerChallenge — operators use hashcat mode 5500 " +
		"/ 5600 against the surfaced challenge + response); MIC verification " +
		"(requires the session key derived from KXKEY + SIGNKEY material that's " +
		"not in the wire payload); SPNEGO wrapper (when NTLM is the inner " +
		"mechanism in a GSS-API negotiation, strip the outer SPNEGO ASN.1 first; " +
		"this Spec expects an NTLMSSP blob not wrapped in SPNEGO).\n\n" +
		"Source: docs/catalog/gap-analysis.md (foundational Windows " +
		"authentication protocol; universal in SMB / HTTP / LDAP / DCERPC on " +
		"every AD-joined Windows network; high pentest + DFIR value as Type 2 + " +
		"Type 3 messages feed directly into hashcat for offline password " +
		"recovery). Wrap-vs-native: native — MS-NLMP is publicly documented; the " +
		"wire format is straightforward (signature + type + fixed-position " +
		"header + (Len, MaxLen, Offset) field triples + payload strings); no " +
		"crypto at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Raw NTLMSSP bytes (already extracted from SMB SESSION_SETUP / HTTP Authorization: NTLM base64-decoded / LDAP bind / DCE bind PDU). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ntlmDecodeHandler,
}

func ntlmDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("ntlm_decode: 'hex' is required")
	}
	res, err := ntlm.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("ntlm_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
