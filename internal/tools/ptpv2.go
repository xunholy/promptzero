// ptpv2.go — host-side PTPv2 packet decoder Spec.
// Wraps the internal/ptpv2 walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ptpv2"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(ptpv2DecodeSpec)
}

var ptpv2DecodeSpec = Spec{
	Name: "ptpv2_decode",
	Description: "Decode a PTPv2 (Precision Time Protocol version 2) packet per IEEE " +
		"1588-2008. PTPv2 is the de-facto wire-time synchronisation protocol for " +
		"modern networks that need sub-microsecond clock alignment across hosts — " +
		"well beyond what NTP can deliver. Operationally relevant in 5G/telecom " +
		"fronthaul (eCPRI radio units require ±1.5 µs TAE per O-RAN, met via PTP " +
		"boundary clocks + SyncE), finance (MiFID II RTS 25 mandates ≤100 µs " +
		"traceable to UTC for HFT venues), industrial automation (IEEE 802.1AS gPTP " +
		"is the time base for TSN traffic shaping in robotics + motion control + " +
		"autonomous-vehicle in-cabin networks), power grid telemetry (IEC 61850-9-3 " +
		"power profile mandates PTP for sampled-values + GOOSE timestamping inside " +
		"substations), and broadcast media (SMPTE ST 2110 IP video needs PTP for " +
		"frame-locked playout). Decodes:\n\n" +
		"- **Common header** (IEEE 1588-2008 §13.3, 34 bytes): 4-bit " +
		"transportSpecific + 4-bit messageType + 4-bit Reserved + 4-bit " +
		"versionPTP (= 2) + messageLength + domainNumber + flagField + 64-bit " +
		"correctionField (scaled-nanoseconds — high 48 bits ns, low 16 bits sub-" +
		"ns; transparent clocks accumulate residence time here) + 8-byte " +
		"clockIdentity (typically EUI-64 from MAC) + 2-byte portNumber + " +
		"sequenceId + controlField (deprecated in v2 but transmitted) + 1-byte " +
		"signed logMessageInterval (log₂ of mean inter-message interval in " +
		"seconds — -3 = 125 ms, 0 = 1 s).\n" +
		"- **10-entry messageType name table** (IEEE 1588-2008 §13.3.2.2): 0x0 " +
		"Sync / 0x1 Delay_Req / 0x2 Pdelay_Req / 0x3 Pdelay_Resp / 0x8 Follow_Up " +
		"/ 0x9 Delay_Resp / 0xA Pdelay_Resp_Follow_Up / 0xB Announce / 0xC " +
		"Signaling / 0xD Management. (Event messages 0x0–0x3 travel on UDP/319 " +
		"and are hardware-timestamped on entry/exit; general messages 0x8–0xD " +
		"travel on UDP/320.)\n" +
		"- **Decoded flag set** for the flagField — alternateMaster, twoStep, " +
		"unicast, PTP_profile_specific_1/2, and (Announce-only) leap61 / leap59 " +
		"/ currentUtcOffsetValid / ptpTimescale / timeTraceable / " +
		"frequencyTraceable.\n" +
		"- **Per-messageType body decoders** (IEEE 1588-2008 §13.6-13.13): Sync / " +
		"Delay_Req / Follow_Up / Delay_Resp carry a 10-byte PTP-timestamp " +
		"(6-byte secondsField + 4-byte nanosecondsField); Delay_Resp adds a 10-" +
		"byte requestingPortIdentity copy-back. Pdelay_Req carries originTimestamp " +
		"+ 10-byte reserved. Pdelay_Resp carries requestReceiptTimestamp + " +
		"requestingPortIdentity. Pdelay_Resp_Follow_Up carries " +
		"responseOriginTimestamp + requestingPortIdentity. Signaling / Management " +
		"carry a 10-byte targetPortIdentity then trailing TLVs surfaced as " +
		"`tlv_suffix_hex`.\n" +
		"- **Announce body** (30 bytes, IEEE 1588-2008 §13.5): originTimestamp + " +
		"2-byte currentUtcOffset + reserved + grandmasterPriority1 + " +
		"grandmasterClockQuality (clockClass + clockAccuracy + " +
		"offsetScaledLogVariance) + grandmasterPriority2 + 8-byte " +
		"grandmasterIdentity + stepsRemoved + 1-byte timeSource. Announce is the " +
		"Best Master Clock Algorithm (BMCA) input — every clock compares incoming " +
		"Announce records and elects the best grandmaster.\n" +
		"- **9-entry timeSource name table** (IEEE 1588-2008 §7.6.2.6): 0x10 " +
		"ATOMIC_CLOCK / 0x20 GPS / 0x30 TERRESTRIAL_RADIO / 0x40 PTP / 0x50 NTP " +
		"/ 0x60 HAND_SET / 0x90 OTHER / 0xA0 INTERNAL_OSCILLATOR.\n" +
		"- **clockAccuracy name table** (IEEE 1588-2008 §7.6.2.5): high-runner " +
		"values from 0x20 within 25ns through 0x31 greater than 10s plus 0xFE " +
		"UNKNOWN.\n\n" +
		"Pure offline parser — operators paste PTP bytes from a `tcpdump -X port " +
		"319 or port 320` line, a Wireshark PTP dissector view, or an IEEE 802.3 " +
		"EtherType 0x88F7 frame and get the documented header + per-type body " +
		"breakdown.\n\n" +
		"Out of scope (deferred): network framing (UDP/319 event, UDP/320 general, " +
		"or IEEE 802.3 EtherType 0x88F7 — feed PTP bytes after the transport-" +
		"header strip); TLV suffix walker (PTPv2 messages may carry trailing TLVs " +
		"— organisation-specific extensions, management responses, authentication " +
		"for IEEE 1588-2019; surfaced as `tlv_suffix_hex` for future per-TLV " +
		"decoders); Signaling / Management body decoders (targetPortIdentity is " +
		"decoded; per-action TLV records like REQUEST_UNICAST_TRANSMISSION, GET/" +
		"SET responses are future work); BMCA reasoning (every Announce field " +
		"needed to drive BMCA is surfaced — priority1, clockQuality, " +
		"grandmasterIdentity, stepsRemoved, priority2 — but no record comparison " +
		"or winner-pick); gPTP (IEEE 802.1AS) profile validation (gPTP forbids " +
		"Delay_Req/Delay_Resp — only P2P delay via Pdelay_* is allowed — and pins " +
		"specific flag combinations; raw values surfaced without profile-" +
		"conformance checks); cryptographic authentication (IEEE 1588-2019 v2.1 " +
		"AUTHENTICATION_TLV is out of scope — this Spec targets v2-2008 bare-wire " +
		"deployments); clock state-machine reasoning (slave-side servo loop, " +
		"transparent-clock residence-time accumulation, boundary-clock port-state " +
		"changes — higher-level analysis).\n\n" +
		"Source: docs/catalog/gap-analysis.md (5G / telecom / finance / industrial " +
		"timing dissector — the time-sync companion to NTP decoders). Wrap-vs-" +
		"native: native — IEEE 1588-2008 is fully public; PTPv2 has a tight 34-" +
		"byte common header followed by a per-messageType body and (rarely) a TLV " +
		"suffix; no crypto at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"PTPv2 packet bytes (after UDP/319/320 or EtherType 0x88F7 strip). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ptpv2DecodeHandler,
}

func ptpv2DecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("ptpv2_decode: 'hex' is required")
	}
	res, err := ptpv2.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("ptpv2_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
