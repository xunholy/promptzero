// someip.go — host-side SOME/IP message decoder Spec.
// Wraps the internal/someip walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/someip"
)

func init() { //nolint:gochecknoinits
	Register(someipDecodeSpec)
}

var someipDecodeSpec = Spec{
	Name: "someip_decode",
	Description: "Decode a SOME/IP (Scalable service-Oriented MiddlewarE over IP) " +
		"message per AUTOSAR R23-11 PRS_SOMEIPProtocol and PRS_SOMEIPServiceDiscovery" +
		"Protocol. SOME/IP is the automotive Ethernet RPC + pub/sub bus sitting " +
		"alongside CAN/CAN-FD in modern vehicles — particularly EVs and AUTOSAR " +
		"Adaptive Platform ECUs — for service-oriented in-vehicle communication " +
		"that the CAN family can't carry (large payloads, multi-recipient pub/sub, " +
		"dynamic service discovery). Operationally, SOME/IP drives camera + radar " +
		"+ lidar feeds from the ADAS sensor cluster to the central perception ECU, " +
		"IVI ↔ instrument cluster service calls, inter-domain controller traffic " +
		"in zonal-architecture vehicles (Tesla, Rivian, VW MEB+, BMW Neue Klasse, " +
		"NIO), and shares Ethernet pairs with DoIP diagnostics. Decodes:\n\n" +
		"- **SOME/IP header** (PRS_SOMEIPProtocol §4.1, 16 bytes, big-endian): " +
		"Service ID (16-bit; 0xFFFF reserved for SOME/IP-SD) + Method ID (16-bit; " +
		"high bit set = event notification, surfaced as `is_event`) + 32-bit " +
		"Length (counts bytes from byte 8 to end of payload) + Client ID + " +
		"Session ID (per-Client monotonic counter pairing Response to Request) + " +
		"Protocol Version (= 0x01) + Interface Version + Message Type + Return " +
		"Code.\n" +
		"- **8-entry messageType name table** (surfaced on the base type with the " +
		"high TP-bit masked off): 0x00 REQUEST / 0x01 REQUEST_NO_RETURN / 0x02 " +
		"NOTIFICATION / 0x40 REQUEST_ACK / 0x41 REQUEST_NO_RETURN_ACK / 0x42 " +
		"NOTIFICATION_ACK / 0x80 RESPONSE / 0x81 ERROR. The 0x20 bit is the " +
		"**Transport-Protocol (TP) flag** indicating a SOME/IP-TP UDP-fragmentation " +
		"segment; surfaced as `tp_segment: true`.\n" +
		"- **12-entry returnCode name table** (PRS_SOMEIPProtocol §4.1.2.11): 0x00 " +
		"E_OK / 0x01 E_NOT_OK / 0x02 E_UNKNOWN_SERVICE / 0x03 E_UNKNOWN_METHOD / " +
		"0x04 E_NOT_READY / 0x05 E_NOT_REACHABLE / 0x06 E_TIMEOUT / 0x07 " +
		"E_WRONG_PROTOCOL_VERSION / 0x08 E_WRONG_INTERFACE_VERSION / 0x09 " +
		"E_MALFORMED_MESSAGE / 0x0A E_WRONG_MESSAGE_TYPE / 0x0B E_E2E_REPEATED. " +
		"Codes 0x20-0x5E are surfaced as 'application-specific'.\n" +
		"- **SOME/IP-SD body decoder** (PRS_SOMEIPServiceDiscoveryProtocol §4.1; " +
		"triggered when Service ID = 0xFFFF + Method ID = 0x8100 over UDP/30490). " +
		"The SD body decodes: 1-byte Flags (Reboot bit 7 + Unicast bit 6) + " +
		"Reserved + Entries Length + **Entries[]** (each 16 bytes: Type + " +
		"Index/Number of 1st/2nd Options + Service ID + Instance ID + Major " +
		"Version + 24-bit TTL + 4 bytes of type-specific data — Minor Version for " +
		"Service entries; Counter + Eventgroup ID for Eventgroup entries) + " +
		"Options Length + **Options[]** (variable length records starting with " +
		"2-byte Length + 1-byte Type + 1-byte Reserved; IPv4/IPv6 endpoint family " +
		"is further decoded into IP address + L4 protocol + port).\n" +
		"- **8-entry SD entry type name table**: 0x00 FIND_SERVICE / 0x01 " +
		"OFFER_SERVICE (and STOP_OFFER_SERVICE when TTL = 0) / 0x06 " +
		"SUBSCRIBE_EVENTGROUP (and STOP_SUBSCRIBE_EVENTGROUP when TTL = 0) / 0x07 " +
		"SUBSCRIBE_EVENTGROUP_ACK. The TTL = 0 stop-semantics is surfaced as the " +
		"derived `is_stop` field.\n" +
		"- **8-entry SD Option type name table**: 0x01 Configuration / 0x02 Load " +
		"Balancing / 0x04 IPv4 Endpoint / 0x06 IPv6 Endpoint / 0x14 IPv4 " +
		"Multicast / 0x16 IPv6 Multicast / 0x24 IPv4 SD Endpoint / 0x26 IPv6 SD " +
		"Endpoint.\n\n" +
		"Pure offline parser — operators paste SOME/IP bytes from a `tcpdump -X " +
		"port 30490 or portrange 30491-30499` line, a Wireshark SOME/IP dissector " +
		"view, or a vehicle Ethernet tap and get the documented header + per-" +
		"type body breakdown.\n\n" +
		"Out of scope (deferred): network framing (UDP/30490 default SD multicast " +
		"+ UDP/30491-30499 per-vendor application channels, or TCP on the same " +
		"port range — feed SOME/IP bytes after the UDP/TCP header strip); payload " +
		"decoding (per-method AUTOSAR SOME/IP serialisation is ARXML-driven and " +
		"service-contract-specific; payload is surfaced as `payload_hex`); TP " +
		"reassembly (when the TP flag is set, the per-segment Offset + " +
		"More-Segments field appears at the start of the payload; the decoder " +
		"surfaces `tp_segment: true` but does not reassemble across input " +
		"packets); SOME/IP-MAC authentication (planned AUTOSAR extension); SD " +
		"state-machine reasoning (Initial-Delay, Repetition-Phase, Cyclic-Offer, " +
		"TTL expiry, Subscription state — higher-level analysis).\n\n" +
		"Source: docs/catalog/gap-analysis.md (automotive Ethernet RPC dissector " +
		"— pairs with the canbus_* + canbus_fd_sniff family for full in-vehicle " +
		"coverage; useful in DEF CON Car Hacking Village CTF + AUTOSAR Adaptive " +
		"Platform pentests). Wrap-vs-native: native — the AUTOSAR PRS specs are " +
		"fully public; SOME/IP has a tight 16-byte header followed by either a " +
		"method-call payload or a Service-Discovery body; no crypto at the parse " +
		"layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"SOME/IP message bytes (after UDP/TCP header strip; UDP/30490 for SD, UDP/30491-30499 or TCP for application channels). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   someipDecodeHandler,
}

func someipDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("someip_decode: 'hex' is required")
	}
	res, err := someip.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("someip_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
