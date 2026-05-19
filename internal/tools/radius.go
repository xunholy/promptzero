// radius.go — host-side RADIUS packet dissector Spec,
// delegating to the internal/radius package for the walker
// proper.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/radius"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(radiusPacketDecodeSpec)
}

var radiusPacketDecodeSpec = Spec{
	Name: "radius_packet_decode",
	Description: "Decode a RADIUS packet — the dominant AAA protocol on enterprise networks " +
		"used by every Wi-Fi 802.1X / WPA2-Enterprise auth, every VPN concentrator, every " +
		"NAS / RADIUS-PAM / FreeRADIUS deployment on UDP/1812 (auth) + UDP/1813 " +
		"(accounting). Per RFC 2865 (auth) + RFC 2866 (accounting) + supporting RFCs. " +
		"High pentest value: enterprise Wi-Fi credential capture analysis, VPN auth-flow " +
		"inspection, RADIUS Vendor-Specific attribute mining. Decodes:\n\n" +
		"- **20-byte header**: Code (16-entry name table — Access-Request / Access-Accept " +
		"/ Access-Reject / Accounting-Request / Accounting-Response / Access-Challenge / " +
		"Status-Server / Disconnect-Request / Disconnect-ACK / Disconnect-NAK / CoA-" +
		"Request / CoA-ACK / CoA-NAK), Identifier, Length (validated against buffer), " +
		"Authenticator (16 bytes).\n" +
		"- **Attribute TLV walker**: type + length + value per RFC 2865 §5.\n" +
		"- **~80-entry attribute name table** covering the IANA RADIUS Types registry: " +
		"User-Name, User-Password, CHAP-Password, NAS-IP-Address, NAS-Port, Service-Type, " +
		"Framed-Protocol, Framed-IP-Address, Framed-IP-Netmask, Framed-Routing, Filter-Id, " +
		"Framed-MTU, Framed-Compression, Login-IP-Host, Login-Service, Login-TCP-Port, " +
		"Reply-Message, Callback-Number, Callback-Id, Framed-Route, State, Class, " +
		"Vendor-Specific, Session-Timeout, Idle-Timeout, Termination-Action, Called-" +
		"Station-Id, Calling-Station-Id, NAS-Identifier, Proxy-State, Acct-Status-Type, " +
		"Acct-Delay-Time, Acct-Input/Output-Octets, Acct-Session-Id, Acct-Authentic, " +
		"Acct-Session-Time, Acct-Input/Output-Packets, Acct-Terminate-Cause, Acct-Multi-" +
		"Session-Id, Acct-Link-Count, Acct-Input/Output-Gigawords, Event-Timestamp, " +
		"CHAP-Challenge, NAS-Port-Type, Port-Limit, Tunnel-Type / Medium-Type / Client/" +
		"Server-Endpoint / Private-Group-ID / Assignment-ID / Preference, EAP-Message, " +
		"Message-Authenticator, Acct-Interim-Interval, NAS-Port-Id, Framed-Pool, " +
		"NAS-IPv6-Address, Framed-Interface-Id, Framed-IPv6-Prefix, Error-Cause.\n" +
		"- **Vendor-Specific (26)** deep decode: vendor-id (4 bytes) with SMI PEN name " +
		"lookup (~20 entries: Cisco, Microsoft, Juniper, Aruba, MikroTik, Fortinet, " +
		"Ruckus, H3C, Nokia/Alcatel-Lucent, Extreme, etc.) + vendor-attribute sub-TLVs.\n" +
		"- **Type-aware value rendering**:\n" +
		"  - String attributes → UTF-8.\n" +
		"  - Integer attributes → uint32 + enum-name lookup for Service-Type (Login / " +
		"Framed / Administrative / NAS-Prompt / Authenticate-Only / Authorize-Only / " +
		"etc.), Framed-Protocol (PPP / SLIP / ARAP / GPRS PDP Context), Acct-Status-Type " +
		"(Start / Stop / Interim-Update / Accounting-On/Off / Tunnel-* / Failed), Acct-" +
		"Terminate-Cause (18 reasons: User-Request / Lost-Carrier / Idle-Timeout / " +
		"Admin-Reset / NAS-Reboot / etc.), NAS-Port-Type (20 entries including Async / " +
		"Ethernet / Wireless-802.11 / xDSL / Cable / Virtual), Tunnel-Type (13 entries: " +
		"PPTP / L2F / L2TP / GRE / IP-in-IP / VLAN / etc.), Tunnel-Medium-Type, Error-" +
		"Cause (RFC 5176 dynamic-authorization codes).\n" +
		"  - IPv4 attributes → dotted-decimal.\n" +
		"  - Time attributes (Event-Timestamp) → uint32 seconds + RFC 3339 UTC string.\n\n" +
		"Pure offline parser — operators paste a hex blob from Wireshark / tshark / " +
		"tcpdump-of-1812-or-1813 / a FreeRADIUS log / an Aruba ClearPass trace / a Cisco " +
		"ACS capture and inspect every documented field without re-sending the request " +
		"to the AAA server. Pairs with ip_packet_decode + tls_handshake_decode + " +
		"eap_decode (EAP-Message attributes) for the complete enterprise-auth decode " +
		"stack.\n\n" +
		"Out of scope (deferred to future iterations): User-Password decryption (requires " +
		"the RADIUS shared secret + Authenticator hash chain); Message-Authenticator " +
		"HMAC-MD5 validation (requires shared secret); EAP-Message reassembly across " +
		"multiple attribute chunks (each attribute decoded individually); Diameter (RFC " +
		"6733) successor protocol; TACACS+ (RFC 8907) alternate AAA protocol.\n\n" +
		"Source: docs/catalog/gap-analysis.md (enterprise AAA decode space — high " +
		"pentest value for Wi-Fi Enterprise / VPN / NAS credential analysis). " +
		"Wrap-vs-native: native — RFC 2865 / 2866 + IANA RADIUS Types registry are " +
		"fully public, wire format is fixed-format header + TLV walker, value rendering " +
		"is enum-table lookup.\n\n" +
		"Accepts ':' / '-' / '_' / whitespace separators and a leading '0x' prefix.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded RADIUS packet: 20-byte header (Code + Identifier + Length + 16-byte Authenticator) + attribute TLV list. Minimum 20 bytes; maximum 4096 per spec. ':' / '-' / '_' / whitespace separators tolerated; '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   radiusPacketDecodeHandler,
}

func radiusPacketDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("radius_packet_decode: 'hex' is required")
	}
	res, err := radius.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("radius_packet_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
