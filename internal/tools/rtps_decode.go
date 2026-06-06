// rtps_decode.go — host-side RTPS / DDS wire-protocol decoder Spec,
// delegating to internal/rtps.
//
// Wrap-vs-native: native — a 20-byte header + a submessage walk
// (id/flags/octetsToNextHeader); byte-field reads, stdlib only. The DDS
// member of the OT/ICS family (modbus/dnp3/.../hicp). Fingerprints the DDS
// vendor + participant + submessage flow from a captured ROS2/industrial
// DDS message. Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/rtps"
)

func init() { //nolint:gochecknoinits
	Register(rtpsDecodeSpec)
}

var rtpsDecodeSpec = Spec{
	Name: "rtps_decode",
	Description: "Decode **RTPS** (Real-Time Publish-Subscribe) — the wire protocol of **OMG DDS**, the pub/sub " +
		"middleware that runs **ROS 2 robotics, autonomous vehicles, naval combat systems and industrial " +
		"control**. The DDS member of the project's OT/ICS decoder family (`modbus`, `dnp3`, `iec104`, " +
		"`s7comm`, `enip`, `profinetdcp`, `opcua`, `ethercat`, `knxnetip`, `hicp`). RTPS is a recon-rich OT " +
		"target: DDS discovery (SPDP / SEDP) and data flow are unauthenticated by default, so a captured RTPS " +
		"message fingerprints the **DDS vendor** (RTI Connext / eProsima FastDDS / Eclipse Cyclone / OpenDDS " +
		"/ …), identifies the **participant** (GUID prefix), and maps the submessage flow (discovery vs data, " +
		"heartbeats, ACKNACKs).\n\n" +
		"Decodes the 20-byte header (magic, protocol version, **vendor id + name**, GUID prefix split into " +
		"host / app / instance) and walks the **submessages** — each kind (DATA / HEARTBEAT / ACKNACK / GAP / " +
		"INFO_TS / INFO_DST / SEC_* / …), endianness, and length (octetsToNextHeader) — lifting out the " +
		"INFO_DST destination GUID prefix.\n\n" +
		"No confidently-wrong output: the header was verified against scapy's RTPS layer (the vendor table is " +
		"scapy's authoritative map) and the submessage walk follows the RTPS-spec octetsToNextHeader boundary " +
		"in each submessage's own endianness; the submessage **bodies** (SPDP/SEDP parameter lists, " +
		"serialized data) are surfaced as raw hex rather than decoded into possibly-wrong vendor/QoS fields. " +
		"No network, no device, transmits nothing, so it is Low risk. ':' / '-' / '_' / whitespace separators " +
		"and a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (DDS / RTPS OT-middleware recon). Wrap-vs-native: native — a " +
		"byte-field read + a submessage walk, stdlib only, no new go.mod dep. Header verified field-for-field " +
		"against scapy's RTPS layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The RTPS message (the DDS UDP payload) as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   rtpsDecodeHandler,
}

func rtpsDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("rtps_decode: 'hex' is required")
	}
	res, err := rtps.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("rtps_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
