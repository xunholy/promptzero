// diameter.go — host-side Diameter packet decoder Spec.
// Wraps the internal/diameter walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/diameter"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(diameterDecodeSpec)
}

var diameterDecodeSpec = Spec{
	Name: "diameter_packet_decode",
	Description: "Decode a Diameter packet per RFC 6733 (the current Diameter Base " +
		"Protocol — supersedes RFC 3588). Diameter is the 3GPP AAA protocol that " +
		"succeeded RADIUS (RFC 2865, already covered by `radius_packet_decode`); " +
		"it carries authentication / authorization / accounting / charging " +
		"signalling across every modern cellular network on the S6a (HSS↔MME), " +
		"S13 (HSS↔EIR), Gx (PCEF↔PCRF), Gy (Charging), Rx (P-CSCF↔PCRF), Cx/Dx " +
		"(IMS), Sh (AS↔HSS), and S6t / T6a (IoT M2M) interfaces. Diameter " +
		"typically rides on SCTP (covered by `sctp_packet_decode`) on TCP/SCTP " +
		"port 3868. Decodes:\n\n" +
		"- **20-byte header** (RFC 6733 §3): Version (must be 1) + 24-bit Message " +
		"Length + 8-bit Command Flags (decoded into 4 named bits: R Request / P " +
		"Proxiable / E Error / T Potentially re-transmitted) + 24-bit Command " +
		"Code + 32-bit Application ID + 32-bit Hop-by-Hop ID + 32-bit End-to-End " +
		"ID.\n" +
		"- **~20-entry Command Code name table**: 257 Capabilities-Exchange / 258 " +
		"Re-Auth / 271 Accounting / 272 Credit-Control (Gx/Gy) / 274 Abort-Session " +
		"/ 275 Session-Termination / 280 Device-Watchdog / 282 Disconnect-Peer / " +
		"316 Update-Location (S6a) / 317 Cancel-Location (S6a) / 318 " +
		"Authentication-Information (S6a) / 319 Insert-Subscriber-Data / 320 " +
		"Delete-Subscriber-Data / 321 Purge-UE / 322 Reset / 323 Notify. Suffix " +
		"is '-Request' or '-Answer' based on the R flag.\n" +
		"- **~15-entry Application ID name table**: 0 Diameter Base / 1 NASREQ / " +
		"2 Mobile-IPv4 / 3 Accounting / 4 Credit-Control / 5 EAP / 6 SIP / " +
		"0x01000000 3GPP Cx/Dx / 0x01000001 3GPP Sh / 0x01000014 3GPP Rx / " +
		"0x01000016 3GPP Gx / 0x01000023 3GPP S6a/S6d / 0x01000038 3GPP S13 / " +
		"0x01000044 3GPP S6t / 0x0100004A 3GPP T6a / 0xFFFFFFFF Diameter Relay.\n" +
		"- **AVP walker** — 8-byte minimum AVP header (Code uint32 BE + 1-byte " +
		"Flags + 24-bit Length including header) + optional 4-byte Vendor-ID " +
		"(when V flag set) + value + 4-byte padding. AVP Flags decoded into 3 " +
		"named bits: V (Vendor-Specific) / M (Mandatory) / P (Protected).\n" +
		"- **~35-entry AVP Code name table** covering RFC 6733 base AVPs: " +
		"User-Name / Class / Session-Timeout / Acct-Session-Id / Event-Timestamp " +
		"/ Host-IP-Address / Auth-Application-Id / Acct-Application-Id / Vendor-" +
		"Specific-Application-Id / Session-Id / Origin-Host / Vendor-Id / " +
		"Firmware-Revision / Result-Code / Product-Name / Disconnect-Cause / " +
		"Auth-Request-Type / Auth-Session-State / Origin-State-Id / Failed-AVP " +
		"/ Proxy-Host / Error-Message / Route-Record / Destination-Realm / " +
		"Authorization-Lifetime / Redirect-Host / Destination-Host / Termination-" +
		"Cause / Origin-Realm / Experimental-Result / Experimental-Result-Code " +
		"/ Inband-Security-Id + Accounting AVPs.\n" +
		"- **Type-aware AVP value decoding** based on AVP Code: UTF8String " +
		"(Session-Id, Origin-Host, Origin-Realm, Error-Message, Product-Name, " +
		"Route-Record, etc.) surfaced as decoded UTF-8; Unsigned32 (Result-Code, " +
		"Origin-State-Id, Session-Timeout, Authorization-Lifetime, etc.) surfaced " +
		"as decoded uint32; Address (Host-IP-Address) decoded as IPv4 or IPv6 per " +
		"RFC 6733 §4.3.1 (2-byte AF + 4-or-16-byte address).\n" +
		"- **Result-Code class mapping** — when AVP code is 268 (Result-Code), " +
		"the decoded uint32 is classified as Informational (1xxx) / Success " +
		"(2xxx — with 2001 DIAMETER_SUCCESS distinguished) / Protocol Error " +
		"(3xxx) / Transient Failure (4xxx) / Permanent Failure (5xxx).\n\n" +
		"Pure offline parser — operators paste Diameter bytes (after the SCTP " +
		"DATA-chunk user-data extraction from `sctp_packet_decode`; or directly " +
		"from a `tcpdump -X port 3868` line) and get the documented header + AVP " +
		"breakdown.\n\n" +
		"Out of scope (deferred): SCTP / TCP / TLS framing (use `sctp_packet_decode` " +
		"to unwrap the SCTP envelope first; the resulting DATA chunk's user data " +
		"is the Diameter payload); Grouped AVP recursion (Grouped-type AVPs like " +
		"Vendor-Specific-Application-Id, Proxy-Info, Failed-AVP, Experimental-" +
		"Result have their bodies surfaced as hex; a future iteration would " +
		"recursively walk the inner AVPs); Diameter Routing Agent / Relay " +
		"forwarding logic (higher-level analysis — Route-Record + Destination-" +
		"Realm are surfaced, routing decisions are not); end-to-end security " +
		"(E flag + Protected AVP encryption — flagged in the Flags decode; " +
		"payload remains opaque hex).\n\n" +
		"Source: docs/catalog/gap-analysis.md (foundational 3GPP AAA protocol; " +
		"RADIUS-successor sibling to radius_packet_decode; the long-standing " +
		"telco-pentest decoder catalog gap that opens up HSS / MME / PCRF / PCEF " +
		"visibility on every modern cellular network). Wrap-vs-native: native — " +
		"RFC 6733 is fully public; Diameter has a tight 20-byte header followed " +
		"by a uniform AVP array; no crypto at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Diameter packet bytes (after SCTP DATA-chunk user-data extraction; conventionally TCP/SCTP port 3868). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   diameterDecodeHandler,
}

func diameterDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("diameter_packet_decode: 'hex' is required")
	}
	res, err := diameter.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("diameter_packet_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
