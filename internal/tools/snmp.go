// snmp.go — host-side SNMP v1/v2c/v3 packet dissector Spec,
// delegating to the internal/snmp package for the walker
// proper.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/snmp"
)

func init() { //nolint:gochecknoinits
	Register(snmpPacketDecodeSpec)
}

var snmpPacketDecodeSpec = Spec{
	Name: "snmp_packet_decode",
	Description: "Decode an SNMP packet — the dominant network-management protocol on " +
		"enterprise networks, found on every router / switch / firewall / printer / UPS / " +
		"PDU / managed AP / managed VM-host since the late '80s. Per RFC 1157 (v1) + " +
		"RFC 1905 / 3416 (v2c PDU formats) + RFC 3411-3418 (v3 framework). Supports " +
		"v1, v2c, and v3 envelopes. Decodes:\n\n" +
		"- **Outer ASN.1 BER envelope**: hand-rolled BER walker for SNMP-specific types " +
		"(no encoding/asn1 strictness): SEQUENCE (0x30), INTEGER (0x02), OCTET STRING " +
		"(0x04), NULL (0x05), OBJECT IDENTIFIER (0x06), IpAddress (0x40), Counter32 " +
		"(0x41), Gauge32 / Unsigned32 (0x42), TimeTicks (0x43), Opaque (0x44), Counter64 " +
		"(0x46), and the SNMP-specific noSuchObject (0x80), noSuchInstance (0x81), " +
		"endOfMibView (0x82) value markers + the PDU tags 0xA0..0xA8.\n" +
		"- **Version detection**: v1 (0), v2c (1), v2u historical (2), v3 (3).\n" +
		"- **Community string** for v1/v2c (the long-standing security weakness in " +
		"plaintext SNMP — `public` and `private` defaults are operationally important " +
		"to flag).\n" +
		"- **v3 msgGlobalData header**: msgID, msgMaxSize, msgFlags broken out " +
		"(auth/priv/reportable bits), msgSecurityModel, msgSecurityParameters raw. The " +
		"encrypted scopedPDU body is surfaced as raw hex (decryption requires the " +
		"agent's USM auth/priv keys, out of scope).\n" +
		"- **PDU dispatch** with 9 documented PDU types:\n" +
		"  - **0xA0 GetRequest** / **0xA1 GetNextRequest** / **0xA2 Response** / " +
		"**0xA3 SetRequest** / **0xA5 GetBulkRequest** (v2c+) / **0xA6 InformRequest** / " +
		"**0xA7 SNMPv2-Trap** / **0xA8 Report** — request-id + error-status (or " +
		"non-repeaters for GetBulkRequest) + error-index (or max-repetitions) + " +
		"VarBindList.\n" +
		"  - **0xA4 Trap-PDU** (SNMPv1 only) — different shape: enterprise OID + " +
		"agent-addr (IPv4) + generic-trap (named: coldStart / warmStart / linkDown / " +
		"linkUp / authenticationFailure / egpNeighborLoss / enterpriseSpecific) + " +
		"specific-trap + time-stamp + VarBindList.\n" +
		"- **Error-status naming** (19-entry table from RFC 3416 §3): noError, tooBig, " +
		"noSuchName, badValue, readOnly, genErr, noAccess, wrongType, wrongLength, " +
		"wrongEncoding, wrongValue, noCreation, inconsistentValue, resourceUnavailable, " +
		"commitFailed, undoFailed, authorizationError, notWritable, inconsistentName.\n" +
		"- **VarBindList walker**: each (OID, value) pair with type-specific decode " +
		"(INTEGER + OCTET STRING with printable-ASCII detection + OID + IpAddress + " +
		"Counter32 + Gauge32 + TimeTicks with centisecond-to-pretty-duration rendering " +
		"+ Counter64 + the v2 'no such' markers).\n" +
		"- **Well-known OID name lookup** (~25 entries covering >90% of real-world " +
		"traffic): sysDescr.0, sysObjectID.0, sysUpTime.0, sysContact.0, sysName.0, " +
		"sysLocation.0, sysServices.0, ifNumber.0, ifIndex / ifDescr / ifType / ifSpeed " +
		"/ ifPhysAddress / ifAdminStatus / ifOperStatus / ifInOctets / ifOutOctets, " +
		"snmpTrapOID.0, coldStart / warmStart / linkDown / linkUp / authenticationFailure.\n" +
		"- **OID decoding**: first byte = 40 * arc1 + arc2 (X.690 §8.19), subsequent " +
		"arcs base-128 with continuation bit.\n\n" +
		"Pure offline parser — operators paste a hex blob from Wireshark / tshark / " +
		"tcpdump-of-161/162 / a community-string scan tool / snmpwalk packet capture " +
		"and inspect every documented field without re-querying the agent. Complements " +
		"dns_packet_decode + dhcp_packet_decode for the network-management decode " +
		"stack: DNS for name resolution, DHCP for address assignment, SNMP for runtime " +
		"monitoring + management.\n\n" +
		"Out of scope (deferred to future iterations): SNMPv3 USM authentication " +
		"(HMAC-MD5/SHA-*) and privacy (DES/AES-128/AES-256) — requires agent " +
		"auth/priv keys; the v3 envelope is decoded but the encrypted scopedPDU body " +
		"is raw hex. VACM authorization (runtime decision, not packet decode). Full " +
		"MIB compilation / generic OID-to-name lookup (~1500-line separate effort; " +
		"only the well-known ~25 OIDs are named here). SNMP over TLS/DTLS/SSH (feed " +
		"the inner message after stripping transport). AgentX (separate protocol).\n\n" +
		"Source: docs/catalog/gap-analysis.md (network-management decode space — high " +
		"OT/IT pentest value for default-community-string scanning + v3 USM-flag " +
		"inspection). Wrap-vs-native: native — RFC 1157 + 3416 + 3411-3418 are fully " +
		"public, ASN.1 BER is hand-rolled in ~200 lines, PDU dispatch is a switch.\n\n" +
		"Accepts ':' / '-' / '_' / whitespace separators and a leading '0x' prefix.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded SNMP packet: outer SEQUENCE + INTEGER version + OCTET STRING community (v1/v2c) or msgGlobalData + msgSecurityParameters + msgData (v3) + tagged PDU body. ':' / '-' / '_' / whitespace separators tolerated; '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   snmpPacketDecodeHandler,
}

func snmpPacketDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("snmp_packet_decode: 'hex' is required")
	}
	res, err := snmp.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("snmp_packet_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
