// bacnet.go — host-side BACnet/IP frame dissector Spec,
// delegating to the internal/bacnet package for the walker
// proper.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/bacnet"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(bacnetIPDecodeSpec)
}

var bacnetIPDecodeSpec = Spec{
	Name: "bacnet_ip_decode",
	Description: "Decode a BACnet/IP (BACnet over UDP, ASHRAE 135 Annex J) frame — the " +
		"dominant building-automation protocol used in HVAC controllers, lighting panels, " +
		"energy meters, fire-alarm gateways, elevator dispatch, and BMS (Building " +
		"Management System) front-ends. Per ASHRAE 135 + Annex J. Decodes:\n\n" +
		"- **BVLC envelope** (BACnet Virtual Link Control): Type byte (always 0x81 for " +
		"BACnet/IP), Function byte with 12-entry name table (BVLC-Result, " +
		"Write-Broadcast-Distribution-Table, Forwarded-NPDU, Register-Foreign-Device, " +
		"Distribute-Broadcast-To-Network, Original-Unicast-NPDU, Original-Broadcast-NPDU, " +
		"Secure-BVLL, etc.), and Length field validation against the actual frame size.\n" +
		"- **NPDU envelope** (Network Protocol Data Unit): Version + Control byte with " +
		"bit-field decode (Network Layer Message / Destination Specifier / Source " +
		"Specifier / Reply Expected / Priority — Normal/Urgent/Critical/Life-Safety), " +
		"optional Destination Network (16-bit) + Destination Address (length-prefixed), " +
		"optional Source Network + Source Address, Hop Count (when destination is " +
		"specified), and optional Network Message Type for routing/management traffic " +
		"(20-entry table: Who-Is-Router-To-Network, I-Am-Router-To-Network, " +
		"Initialize-Routing-Table, Establish-Connection, Network-Number-Is, etc.).\n" +
		"- **APDU envelope** (Application Protocol Data Unit): 4-bit PDU Type with " +
		"8-entry table (Confirmed-Request, Unconfirmed-Request, SimpleACK, ComplexACK, " +
		"SegmentACK, Error, Reject, Abort) and per-type flag/field decode:\n" +
		"  - **Confirmed-Request**: SEG / MOR / SA flags, Max Segments Accepted, Max " +
		"APDU Length Accepted, Invoke ID, segment Sequence Number + Window Size when " +
		"segmented, ServiceChoice.\n" +
		"  - **Unconfirmed-Request**: ServiceChoice only.\n" +
		"  - **SimpleACK / ComplexACK**: Invoke ID + ServiceChoice (+ segmentation " +
		"fields for ComplexACK).\n" +
		"  - **SegmentACK**: Server / NegativeACK flags + Invoke ID + Sequence + Window.\n" +
		"  - **Error / Reject / Abort**: Invoke ID + service / reason code.\n" +
		"- **Service choice naming**:\n" +
		"  - **Confirmed services** (~30 entries): readProperty, writeProperty, " +
		"readPropertyMultiple, writePropertyMultiple, subscribeCOV, subscribeCOVProperty, " +
		"acknowledgeAlarm, confirmedCOVNotification, atomicReadFile, atomicWriteFile, " +
		"addListElement, removeListElement, createObject, deleteObject, " +
		"deviceCommunicationControl, reinitializeDevice, vtOpen, vtClose, vtData, " +
		"readRange, lifeSafetyOperation, getEventInformation, " +
		"subscribeCOVPropertyMultiple, confirmedCOVNotificationMultiple, " +
		"confirmedAuditNotification, auditLogQuery, etc.\n" +
		"  - **Unconfirmed services** (~15 entries): i-Am, i-Have, " +
		"unconfirmedCOVNotification, unconfirmedEventNotification, " +
		"unconfirmedPrivateTransfer, unconfirmedTextMessage, timeSynchronization, " +
		"who-Has, who-Is, utcTimeSynchronization, writeGroup, who-Am-I, you-Are, etc.\n" +
		"- **Error / Reject / Abort reason code lookup**: reject reasons (other / " +
		"buffer-overflow / inconsistent-parameters / invalid-parameter-data-type / " +
		"invalid-tag / missing-required-parameter / parameter-out-of-range / " +
		"too-many-arguments / undefined-enumeration / unrecognized-service); abort " +
		"reasons (other / buffer-overflow / invalid-APDU-in-this-state / " +
		"preempted-by-higher-priority-task / segmentation-not-supported / security-error " +
		"/ insufficient-security / window-size-out-of-range / " +
		"application-exceeded-reply-time / out-of-resources / tsm-timeout / " +
		"apdu-too-long).\n\n" +
		"Pure offline parser — operators paste a hex frame from Wireshark / YABE (Yet " +
		"Another BACnet Explorer) / a captured UDP/47808 dump and inspect every layer " +
		"without re-attaching to the BACnet network. Pairs with modbus_decode for full " +
		"OT-protocol coverage of the building-automation / industrial-control space.\n\n" +
		"Out of scope (deferred to future iterations): BACnet-tagged data decoding (the " +
		"APDU body's ASN.1-style context/application tags requiring a recursive walker), " +
		"BACnet MS/TP (RS-485 dialect), BACnet/Ethernet (Type 0x82), BACnet-Secure / " +
		"BACnet/SC encrypted payload, object-instance + property-identifier deeper " +
		"catalog. The ServiceChoice + raw body hex are surfaced so the operator can " +
		"compare against the standard's service-specific layouts.\n\n" +
		"Source: docs/catalog/gap-analysis.md (OT / building-automation decode space — " +
		"BACnet is the most-deployed BMS protocol, companion to modbus_decode for the " +
		"full OT-pentest workflow). Wrap-vs-native: native — ASHRAE 135 is fully public, " +
		"every envelope field is a fixed-format byte stream, dispatch is a switch.\n\n" +
		"Accepts ':' / '-' / '_' / whitespace separators and a leading '0x' prefix.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded BACnet/IP frame: BVLC header (4 bytes, type=0x81) + NPDU (variable: version + control + optional addresses + hop count) + APDU (variable: PDU type + flags + invoke ID + service choice + body). ':' / '-' / '_' / whitespace separators tolerated; '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   bacnetIPDecodeHandler,
}

func bacnetIPDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("bacnet_ip_decode: 'hex' is required")
	}
	res, err := bacnet.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("bacnet_ip_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
