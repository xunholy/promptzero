// Package netflow decodes NetFlow v5 export packets per Cisco's
// public NetFlow v5 specification (1996; the dominant flow-export
// format on enterprise + ISP networks for two decades, still
// emitted by every Cisco / Juniper / Arista router that runs
// classic NetFlow). NetFlow records summarise unidirectional
// IP flows — every (SrcIP, DstIP, SrcPort, DstPort, Proto)
// tuple seen by a routing-plane sampler is exported to a
// collector for traffic accounting, capacity planning, anomaly
// detection, and SIEM correlation.
//
// Wrap-vs-native judgement
//
//	Native. NetFlow v5 is fully public; the wire format is a
//	tight 24-byte header followed by a uniform array of
//	48-byte flow records. No crypto, no compression, no
//	variable-length fields. Operators paste NetFlow bytes
//	(UDP destination port 2055 / 9555 / 9995) from a
//	`tcpdump -X udp port 2055` line or a Wireshark Follow-
//	UDP-Stream view and get the documented header + per-
//	record breakdown.
//
// What this package covers
//
//   - **24-byte header**:
//
//   - bytes 0-1: **Version** (uint16 BE; must be 5).
//
//   - bytes 2-3: **Count** (uint16 BE; number of flow
//     records in this packet, 1-30; the upper bound is
//     set by MTU — 30 × 48 + 24 = 1464 < 1500).
//
//   - bytes 4-7: **SysUptime** (uint32 BE; milliseconds
//     since the exporting device booted).
//
//   - bytes 8-11: **Unix Secs** (uint32 BE; epoch seconds
//     of the current export).
//
//   - bytes 12-15: **Unix Nsecs** (uint32 BE; nanoseconds
//     since Unix Secs).
//
//   - bytes 16-19: **Flow Sequence** (uint32 BE; per-source
//     monotonic counter of flows exported — gaps signal
//     collector data loss).
//
//   - byte 20: **Engine Type** (uint8; flow engine type
//     — typically 0 RP, 1 LC).
//
//   - byte 21: **Engine ID** (uint8; slot/engine ID for
//     multi-engine routers).
//
//   - bytes 22-23: **Sampling Interval** — top 2 bits =
//     **sampling mode** (0 unsampled, 1 1-in-N
//     deterministic, 2 1-in-N random); bottom 14 bits =
//     interval N.
//
//   - **48-byte flow record** (repeated `Count` times):
//
//   - bytes 0-3: SrcAddr (IPv4).
//
//   - bytes 4-7: DstAddr (IPv4).
//
//   - bytes 8-11: NextHop (IPv4 — next-hop router for
//     outbound forwarding).
//
//   - bytes 12-13: Input (uint16 BE; SNMP ifIndex of
//     incoming interface).
//
//   - bytes 14-15: Output (uint16 BE; SNMP ifIndex of
//     outgoing interface).
//
//   - bytes 16-19: dPkts (uint32 BE; packets in this flow).
//
//   - bytes 20-23: dOctets (uint32 BE; bytes in this flow).
//
//   - bytes 24-27: First (uint32 BE; SysUptime when first
//     packet was seen, in ms).
//
//   - bytes 28-31: Last (uint32 BE; SysUptime when last
//     packet was seen, in ms).
//
//   - bytes 32-33: SrcPort (uint16 BE).
//
//   - bytes 34-35: DstPort (uint16 BE).
//
//   - byte 36: Pad1.
//
//   - byte 37: **TCP Flags** — cumulative OR of all TCP
//     flags seen during the flow (8 named bits per RFC 793
//
//   - RFC 3168: FIN / SYN / RST / PSH / ACK / URG / ECE
//     / CWR).
//
//   - byte 38: **Protocol** — IP protocol number per IANA:
//     0 HOPOPT / 1 ICMP / 2 IGMP / 6 TCP / 17 UDP / 41
//     IPv6 / 47 GRE / 50 ESP / 51 AH / 89 OSPF / 103 PIM
//     / 112 VRRP / 132 SCTP. Uncatalogued values surfaced
//     with the raw number.
//
//   - byte 39: ToS (uint8; IP type-of-service byte).
//
//   - bytes 40-41: SrcAS (uint16 BE; source ASN —
//     populated when the exporter has BGP-table awareness).
//
//   - bytes 42-43: DstAS (uint16 BE; destination ASN).
//
//   - byte 44: SrcMask (uint8; source prefix length).
//
//   - byte 45: DstMask (uint8; destination prefix length).
//
//   - bytes 46-47: Pad2.
//
//   - **Per-record derived fields**: duration in milliseconds
//     (Last - First); protocol name lookup from the 13-entry
//     IANA-protocol table.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - UDP framing — feed NetFlow bytes after the UDP header
//     strip. NetFlow v5 ships on UDP, conventionally to ports
//     2055 / 9555 / 9995.
//
//   - NetFlow v9 (RFC 3954) — template-based; different
//     envelope, different walker; warrants its own Spec.
//
//   - IPFIX (RFC 7011) — IETF standardisation of NetFlow v9;
//     also warrants its own Spec.
//
//   - sFlow — InMon packet-sampling protocol; different model
//     entirely (per-packet sample, not per-flow summary).
//
//   - Flow-record aggregation / windowing — that's collector-
//     side work; this Spec just decodes the wire.
package netflow

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

// Result is the top-level decoded view of a NetFlow v5 packet.
type Result struct {
	Version            int          `json:"version"`
	Count              int          `json:"count"`
	SysUptimeMs        uint32       `json:"sys_uptime_ms"`
	UnixSeconds        uint32       `json:"unix_seconds"`
	UnixNanoseconds    uint32       `json:"unix_nanoseconds"`
	ExportTimestampISO string       `json:"export_timestamp_iso"`
	FlowSequence       uint32       `json:"flow_sequence"`
	EngineType         int          `json:"engine_type"`
	EngineID           int          `json:"engine_id"`
	SamplingMode       int          `json:"sampling_mode"`
	SamplingModeName   string       `json:"sampling_mode_name"`
	SamplingInterval   int          `json:"sampling_interval"`
	Records            []FlowRecord `json:"records"`
	TotalBytes         int          `json:"total_bytes"`
	Notes              []string     `json:"notes,omitempty"`
}

// FlowRecord is one decoded 48-byte flow record.
type FlowRecord struct {
	Index            int        `json:"index"`
	SrcAddress       string     `json:"src_address"`
	DstAddress       string     `json:"dst_address"`
	NextHop          string     `json:"next_hop"`
	InputInterface   int        `json:"input_interface"`
	OutputInterface  int        `json:"output_interface"`
	Packets          uint32     `json:"packets"`
	Bytes            uint32     `json:"bytes"`
	FirstSysUptimeMs uint32     `json:"first_sys_uptime_ms"`
	LastSysUptimeMs  uint32     `json:"last_sys_uptime_ms"`
	DurationMs       uint32     `json:"duration_ms"`
	SrcPort          int        `json:"src_port"`
	DstPort          int        `json:"dst_port"`
	TCPFlags         int        `json:"tcp_flags"`
	TCPFlagsHex      string     `json:"tcp_flags_hex"`
	TCPFlagBreakdown TCPFlagSet `json:"tcp_flag_breakdown,omitempty"`
	Protocol         int        `json:"protocol"`
	ProtocolName     string     `json:"protocol_name"`
	TypeOfService    int        `json:"type_of_service"`
	SrcAS            int        `json:"src_as"`
	DstAS            int        `json:"dst_as"`
	SrcMask          int        `json:"src_mask"`
	DstMask          int        `json:"dst_mask"`
	SrcPrefix        string     `json:"src_prefix"`
	DstPrefix        string     `json:"dst_prefix"`
}

// TCPFlagSet is the decoded 8-bit TCP flags byte from a flow
// record. RFC 793 + RFC 3168.
type TCPFlagSet struct {
	FIN bool `json:"fin"`
	SYN bool `json:"syn"`
	RST bool `json:"rst"`
	PSH bool `json:"psh"`
	ACK bool `json:"ack"`
	URG bool `json:"urg"`
	ECE bool `json:"ece"`
	CWR bool `json:"cwr"`
}

// Decode parses a single NetFlow v5 export packet from hex.
func Decode(hexStr string) (*Result, error) {
	clean := stripSeparators(hexStr)
	if clean == "" {
		return nil, fmt.Errorf("empty input")
	}
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("hex must have even length, got %d", len(clean))
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	if len(b) < 24 {
		return nil, fmt.Errorf("NetFlow v5 packet truncated (%d bytes; need ≥24 for header)",
			len(b))
	}

	version := int(binary.BigEndian.Uint16(b[0:2]))
	if version != 5 {
		return nil, fmt.Errorf("unsupported NetFlow version %d (this Spec covers v5 only)",
			version)
	}

	r := &Result{
		TotalBytes:      len(b),
		Version:         version,
		Count:           int(binary.BigEndian.Uint16(b[2:4])),
		SysUptimeMs:     binary.BigEndian.Uint32(b[4:8]),
		UnixSeconds:     binary.BigEndian.Uint32(b[8:12]),
		UnixNanoseconds: binary.BigEndian.Uint32(b[12:16]),
		FlowSequence:    binary.BigEndian.Uint32(b[16:20]),
		EngineType:      int(b[20]),
		EngineID:        int(b[21]),
	}
	sampling := binary.BigEndian.Uint16(b[22:24])
	r.SamplingMode = int(sampling >> 14)
	r.SamplingModeName = samplingModeName(r.SamplingMode)
	r.SamplingInterval = int(sampling & 0x3FFF)

	if r.UnixSeconds != 0 {
		ts := time.Unix(int64(r.UnixSeconds), int64(r.UnixNanoseconds)).UTC()
		r.ExportTimestampISO = ts.Format(time.RFC3339Nano)
	}

	expected := 24 + r.Count*48
	if expected > len(b) {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"header declares %d records (%d bytes) but only %d remain after header",
			r.Count, r.Count*48, len(b)-24))
	}
	for i := 0; i < r.Count; i++ {
		off := 24 + i*48
		if off+48 > len(b) {
			break
		}
		r.Records = append(r.Records, decodeRecord(b[off:off+48], i))
	}
	return r, nil
}

func decodeRecord(b []byte, idx int) FlowRecord {
	flags := int(b[37])
	rec := FlowRecord{
		Index:            idx,
		SrcAddress:       ipv4String(b[0:4]),
		DstAddress:       ipv4String(b[4:8]),
		NextHop:          ipv4String(b[8:12]),
		InputInterface:   int(binary.BigEndian.Uint16(b[12:14])),
		OutputInterface:  int(binary.BigEndian.Uint16(b[14:16])),
		Packets:          binary.BigEndian.Uint32(b[16:20]),
		Bytes:            binary.BigEndian.Uint32(b[20:24]),
		FirstSysUptimeMs: binary.BigEndian.Uint32(b[24:28]),
		LastSysUptimeMs:  binary.BigEndian.Uint32(b[28:32]),
		SrcPort:          int(binary.BigEndian.Uint16(b[32:34])),
		DstPort:          int(binary.BigEndian.Uint16(b[34:36])),
		TCPFlags:         flags,
		TCPFlagsHex:      fmt.Sprintf("0x%02X", flags),
		TCPFlagBreakdown: decodeTCPFlags(byte(flags)),
		Protocol:         int(b[38]),
		ProtocolName:     protocolName(int(b[38])),
		TypeOfService:    int(b[39]),
		SrcAS:            int(binary.BigEndian.Uint16(b[40:42])),
		DstAS:            int(binary.BigEndian.Uint16(b[42:44])),
		SrcMask:          int(b[44]),
		DstMask:          int(b[45]),
	}
	if rec.LastSysUptimeMs >= rec.FirstSysUptimeMs {
		rec.DurationMs = rec.LastSysUptimeMs - rec.FirstSysUptimeMs
	}
	rec.SrcPrefix = fmt.Sprintf("%s/%d", rec.SrcAddress, rec.SrcMask)
	rec.DstPrefix = fmt.Sprintf("%s/%d", rec.DstAddress, rec.DstMask)
	return rec
}

func decodeTCPFlags(b byte) TCPFlagSet {
	return TCPFlagSet{
		FIN: b&0x01 != 0,
		SYN: b&0x02 != 0,
		RST: b&0x04 != 0,
		PSH: b&0x08 != 0,
		ACK: b&0x10 != 0,
		URG: b&0x20 != 0,
		ECE: b&0x40 != 0,
		CWR: b&0x80 != 0,
	}
}

func samplingModeName(m int) string {
	switch m {
	case 0:
		return "unsampled"
	case 1:
		return "1-in-N deterministic"
	case 2:
		return "1-in-N random"
	}
	return fmt.Sprintf("uncatalogued mode %d", m)
}

func protocolName(p int) string {
	switch p {
	case 0:
		return "HOPOPT"
	case 1:
		return "ICMP"
	case 2:
		return "IGMP"
	case 4:
		return "IPv4"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 41:
		return "IPv6"
	case 47:
		return "GRE"
	case 50:
		return "ESP"
	case 51:
		return "AH"
	case 58:
		return "ICMPv6"
	case 89:
		return "OSPF"
	case 103:
		return "PIM"
	case 112:
		return "VRRP"
	case 132:
		return "SCTP"
	}
	return fmt.Sprintf("uncatalogued IP protocol %d", p)
}

func ipv4String(b []byte) string {
	if len(b) != 4 {
		return strings.ToUpper(hex.EncodeToString(b))
	}
	return net.IPv4(b[0], b[1], b[2], b[3]).String()
}

func stripSeparators(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	var sb strings.Builder
	for _, r := range s {
		switch r {
		case ':', '-', '_', ' ', '\t', '\n', '\r':
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
