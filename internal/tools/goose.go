// goose.go — host-side IEC 61850-8-1 GOOSE message decoder Spec.
// Wraps the internal/goose walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/goose"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(gooseDecodeSpec)
}

var gooseDecodeSpec = Spec{
	Name: "goose_decode",
	Description: "Decode an IEC 61850-8-1 GOOSE (Generic Object Oriented Substation " +
		"Events) message — the time-critical multicast Ethernet protocol that " +
		"carries protective-relay signals between Intelligent Electronic Devices " +
		"(IEDs) inside modern digital substations. GOOSE is the latency-bounded " +
		"sibling of MMS (the IEC 61850 SCADA application layer) and Sampled " +
		"Values. When a protective relay detects a fault and decides to trip a " +
		"breaker, the trip signal travels as a GOOSE message — and the IEC " +
		"61850-5 performance requirements demand it reach the trip coil within " +
		"**4 ms** end-to-end (Type 1A 'Trip' performance class). To make that " +
		"latency budget realistic, GOOSE rides directly over Ethernet (EtherType " +
		"0x88B8) — no IP, no UDP, no TCP — and uses multicast (default group " +
		"01:0C:CD:01:00:00 / range -01:00:01:FF) so a single sender reaches " +
		"every interested IED on the substation LAN simultaneously. Operationally " +
		"carries Trip / Block signals from protection IEDs to circuit-breaker " +
		"controllers, interlocking between IEDs supervising adjacent bays, " +
		"synchronisation status + position indications from bay-control IEDs to " +
		"the station HMI, and test-mode + maintenance signals during " +
		"commissioning. Each message carries an **stNum** (state number; " +
		"increments on every state change) and **sqNum** (sequence number; " +
		"increments on each retransmission while state is stable); receivers " +
		"detect data loss via stNum/sqNum and tag messages stale once the " +
		"**timeAllowedToLive** budget expires. Decodes:\n\n" +
		"- **GOOSE header** (IEC 61850-8-1 §A.3, 8 bytes, big-endian; " +
		"transmitted immediately after the 0x88B8 EtherType): APPID (uint16 BE; " +
		"identifies the GOOSE control block; 0x0000-0x3FFF for GOOSE, " +
		"0x4000-0x7FFF for Sampled Values) + Length (uint16 BE; total bytes " +
		"from APPID through end of APDU INCLUDING this 8-byte header) + " +
		"Reserved1 + Reserved2 (IEC 62351-6 re-purposes these bytes for a " +
		"security tag).\n" +
		"- **IECGoosePdu** (ASN.1 BER-encoded; outer tag 0x61 IMPLICIT " +
		"[APPLICATION 1] CONSTRUCTED — IEC 61850-8-1 §A.2). The decoder walks " +
		"every context-class IMPLICIT field uniformly tagged 0x80 + N:\n" +
		"  - **[0] gocbRef** (tag 0x80, VISIBLE-STRING): " +
		"`<IED-name>/<LD>$GO$<GoCB-name>` reference.\n" +
		"  - **[1] timeAllowedToLive** (tag 0x81, INTEGER, milliseconds): " +
		"receivers must mark stale after this elapses without a fresh message.\n" +
		"  - **[2] datSet** (tag 0x82, VISIBLE-STRING): " +
		"`<IED-name>/<LD>$<DataSet-name>` reference.\n" +
		"  - **[3] goID** (tag 0x83, VISIBLE-STRING): optional human-readable " +
		"label.\n" +
		"  - **[4] t** (tag 0x84, UtcTime, 8 bytes: 4-byte secondsSinceEpoch + " +
		"3-byte fractionOfSecond + 1-byte timeQuality).\n" +
		"  - **[5] stNum** (tag 0x85, INTEGER): state number — increments on " +
		"every state change.\n" +
		"  - **[6] sqNum** (tag 0x86, INTEGER): sequence number — increments " +
		"on each retransmission while state is stable.\n" +
		"  - **[7] test** (tag 0x87, BOOLEAN): test-mode flag.\n" +
		"  - **[8] confRev** (tag 0x88, INTEGER): configuration revision " +
		"counter.\n" +
		"  - **[9] ndsCom** (tag 0x89, BOOLEAN): 'Needs Commissioning' — set " +
		"when the IED isn't fully configured.\n" +
		"  - **[10] numDatSetEntries** (tag 0x8A, INTEGER).\n" +
		"  - **[11] allData** (tag 0xAB, SEQUENCE OF Data, constructed): the " +
		"per-entry Data choice is dataset-specific (Boolean, BitString, " +
		"Integer, UnsignedInteger, FloatingPoint, OctetString, VisibleString, " +
		"BinaryTime, UtcTime, BCD, BooleanArray, MMSString, Structure); " +
		"surfaced as raw `all_data_hex` for downstream per-DataSet walkers.\n" +
		"- **BER length walker** supports both short-form (≤127 bytes) and " +
		"long-form (1-4 octet) length encodings.\n\n" +
		"Pure offline parser — operators paste GOOSE bytes (starting at the " +
		"APPID byte, i.e. after the 14-byte Ethernet header + 0x88B8 EtherType " +
		"strip) from a Wireshark IEC 61850 GOOSE dissector view or a tshark " +
		"capture of substation LAN traffic and get the documented header + " +
		"PDU field breakdown plus the opaque allData bytes for downstream per-" +
		"DataSet decoders.\n\n" +
		"Out of scope (deferred): L2 framing (feed GOOSE bytes after the " +
		"14-byte Ethernet header — destination MAC, source MAC, EtherType " +
		"0x88B8; standard GOOSE destination is multicast group " +
		"01:0C:CD:01:00:00 / range 01:0C:CD:01:00:00 - 01:0C:CD:01:01:FF; " +
		"VLAN tagging via IEEE 802.1Q with PCP=4 priority is common but " +
		"part of the L2 frame and not parsed here); per-entry Data decoder " +
		"(the allData field carries a sequence of Data choices whose per-IED " +
		"dataset schema is loaded from SCL — SubstationConfigurationLanguage " +
		"— files at engineering time; surfaced as `all_data_hex` for " +
		"downstream per-DataSet walkers); IEC 62351-6 security (trailing " +
		"HMAC-SHA256 signature + key-management metadata appear after the " +
		"IECGoosePdu in the Length-bounded region — surfaced as " +
		"`security_trailer_hex`; verification requires the per-IED shared " +
		"key); replay / sequence-number reasoning (the decoder surfaces stNum " +
		"/ sqNum / timeAllowedToLive but does not itself enforce freshness or " +
		"detect replay — per-flow state is a higher-level concern); Sampled " +
		"Values (IEC 61850-9-2 SMV uses a similar Ethernet header with " +
		"EtherType 0x88BA and a different PDU shape; out of scope here).\n\n" +
		"Source: docs/catalog/gap-analysis.md (substation protective-relay " +
		"dissector — completes the IEC 61850 substation trio (PTPv2 for " +
		"timing + IEC 104 for station-bus telecontrol + GOOSE for process-bus " +
		"trip signalling); targets DEF CON ICS Village CTFs + protective-relay " +
		"security research). Wrap-vs-native: native — IEC 61850-8-1 is " +
		"publicly available; the GOOSE wire format is a tight 8-byte fixed " +
		"header followed by an ASN.1 BER-encoded IECGoosePdu with a fully-" +
		"specified schema and uniform context-class implicit tags 0x80-0xAB; " +
		"no crypto at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"GOOSE message bytes starting at the APPID byte (after the 14-byte Ethernet header + 0x88B8 EtherType strip). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   gooseDecodeHandler,
}

func gooseDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("goose_decode: 'hex' is required")
	}
	res, err := goose.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("goose_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
