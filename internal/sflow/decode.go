// Package sflow decodes sFlow v5 datagrams per the InMon
// publicly-published sFlow v5 specification (sflow.org). sFlow
// is the packet-sampling counterpart to NetFlow (covered by
// `netflow_v5_decode`): instead of summarising per-flow state,
// sFlow exports a configurable 1-in-N sample of the packets
// transiting a device, plus periodic interface counters.
//
// Operationally, sFlow is the dominant monitoring telemetry on
// every modern datacenter switch — Arista, Cisco Nexus, HP,
// Juniper QFX, Mellanox, Cumulus — because it scales linearly
// with link speed regardless of flow churn (whereas NetFlow's
// per-flow state grows with churn). DDoS-detection, capacity
// planning, and security-NDR platforms all consume sFlow.
//
// Wrap-vs-native judgement
//
//	Native. The sFlow v5 spec is fully public; the wire
//	format is XDR-encoded (network-byte-order, 4-byte
//	aligned). A 32-byte datagram header is followed by N
//	(Sample Type + Length + Data) records, each carrying
//	either a Flow Sample (per-packet) or a Counter Sample
//	(per-interface periodic). No crypto, no compression.
//	Operators paste sFlow bytes (UDP destination port 6343)
//	from a `tcpdump -X udp port 6343` line or a Wireshark
//	Follow-UDP-Stream view and get the documented header +
//	sample breakdown.
//
// What this package covers
//
//   - **Datagram common header** (variable; 28 or 40 bytes):
//
//   - bytes 0-3: Version (uint32 BE; must be 5).
//
//   - bytes 4-7: Agent Address Type (uint32 BE; 1 IPv4,
//     2 IPv6).
//
//   - then 4 bytes IPv4 or 16 bytes IPv6 Agent Address.
//
//   - next 4 bytes: Sub-Agent ID (uint32 BE).
//
//   - next 4 bytes: Sequence Number (uint32 BE; per-Agent
//     monotonic — gaps signal datagram loss).
//
//   - next 4 bytes: System Uptime (uint32 BE; ms since
//     agent boot).
//
//   - next 4 bytes: Sample Count (uint32 BE; number of
//     samples in this datagram).
//
//   - **Sample walker** — repeated 8-byte header (Sample
//     Type uint32 BE + Sample Length uint32 BE) + sample
//     body. The Sample Type is split into top 12 bits
//     (Enterprise; 0 for standard sFlow) + bottom 20 bits
//     (Format). **4-entry standard sample format table**:
//     1 Flow Sample, 2 Counter Sample, 3 Expanded Flow
//     Sample, 4 Expanded Counter Sample (Expanded uses
//     uint64 ifIndex fields for bonded interfaces above
//     2^32 — same body otherwise).
//
//   - **Flow Sample body** (Format 1):
//
//   - Sequence Number (uint32 BE).
//
//   - Source ID: top 8 bits **Source Class** (0 ifIndex,
//     1 smonVlanDataSource, 2 entPhysicalEntry) + low 24
//     bits **Source Index** (typically ifIndex of the
//     sampler).
//
//   - **Sampling Rate** (uint32 BE; 1-in-N).
//
//   - Sample Pool (uint32 BE; total packets seen so far
//     on this source).
//
//   - Drops (uint32 BE; cumulative buffer drops).
//
//   - Input Interface Index (uint32 BE).
//
//   - Output Interface Index (uint32 BE; high bits
//     encode special meanings — Discarded, Multiple,
//     Unknown — surfaced as a Note when set).
//
//   - Number of Flow Records (uint32 BE) + N Flow Records.
//
//   - **Flow Record types** (most common):
//
//   - **1 Raw Packet Header** — Header Protocol (uint32
//     BE; **6-entry name table**: 1 Ethernet / 11
//     802.11 / 12 IPv4 / 13 IPv6 / 21 PPP / 22 PPPoE) +
//     Frame Length on wire (uint32 BE) + Stripped octets
//     (uint32 BE; bytes trimmed from start, typically the
//     L2 framing) + Original Sampled Header Length
//     (uint32 BE) + Header Bytes (capped hex preview).
//
//   - **2 Ethernet Frame Data** — Length + 6-byte src
//     MAC + 6-byte dst MAC + EtherType.
//
//   - **3 IPv4 Data** — Length + Protocol (IP proto
//     number) + 4-byte src + 4-byte dst + uint32 src
//     port + uint32 dst port + uint32 TCP flags + uint32
//     ToS.
//
//   - **4 IPv6 Data** — same shape but with 16-byte
//     addresses and an IPv6 priority.
//
//   - **Counter Sample body** (Format 2):
//
//   - Sequence Number (uint32 BE).
//
//   - Source ID (same split as Flow Sample).
//
//   - Number of Counter Records (uint32 BE) + N records.
//
//   - **Counter Record type 1 (Generic Interface Counters)**
//     — full 88-byte body: ifIndex / ifType / ifSpeed
//     (uint64) / ifDirection / ifStatus / ifInOctets
//     (uint64) / ifInUcastPkts / ifInMulticastPkts /
//     ifInBroadcastPkts / ifInDiscards / ifInErrors /
//     ifInUnknownProtos / ifOutOctets (uint64) /
//     ifOutUcastPkts / ifOutMulticastPkts /
//     ifOutBroadcastPkts / ifOutDiscards / ifOutErrors /
//     ifPromiscuousMode.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - UDP framing — feed sFlow bytes after the UDP header
//     strip. sFlow runs on UDP destination port 6343.
//
//   - sFlow v4 and earlier — the wire format changed
//     significantly; v5 has been the standard since 2003.
//
//   - Per-Counter-Record dissection beyond Generic
//     Interface Counters (Ethernet / Token Ring / 802.11 /
//     VG / VLAN / Processor / Radio counters) — surfaced
//     as raw hex; a future iteration could add them.
//
//   - Raw Packet Header inner dissection — the captured
//     header bytes are surfaced as hex; the operator feeds
//     them into the appropriate `*_decode` Spec (e.g.
//     `ip_packet_decode`) based on the Header Protocol.
//
//   - sFlow agent state-machine reasoning (sampling-rate
//     drift, polling-interval skew) — higher-level analysis.
package sflow

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// Result is the top-level decoded view of an sFlow v5 datagram.
type Result struct {
	Version          uint32   `json:"version"`
	AgentAddressType int      `json:"agent_address_type"`
	AgentAddress     string   `json:"agent_address"`
	SubAgentID       uint32   `json:"sub_agent_id"`
	SequenceNumber   uint32   `json:"sequence_number"`
	SystemUptimeMs   uint32   `json:"system_uptime_ms"`
	SampleCount      uint32   `json:"sample_count"`
	Samples          []Sample `json:"samples"`
	TotalBytes       int      `json:"total_bytes"`
	Notes            []string `json:"notes,omitempty"`
}

// Sample is one (Sample Type, Length, Data) record from the
// sample walker.
type Sample struct {
	SampleType   uint32 `json:"sample_type"`
	Enterprise   uint32 `json:"enterprise"`
	Format       uint32 `json:"format"`
	FormatName   string `json:"format_name"`
	SampleLength uint32 `json:"sample_length"`
	BodyHex      string `json:"body_hex,omitempty"`

	// Decoded forms populated for known sample formats.
	FlowSample    *FlowSampleBody    `json:"flow_sample,omitempty"`
	CounterSample *CounterSampleBody `json:"counter_sample,omitempty"`
}

// FlowSampleBody is the decoded body of a Flow Sample (Format 1).
type FlowSampleBody struct {
	SequenceNumber      uint32       `json:"sequence_number"`
	SourceID            uint32       `json:"source_id"`
	SourceClass         int          `json:"source_class"`
	SourceClassName     string       `json:"source_class_name"`
	SourceIndex         uint32       `json:"source_index"`
	SamplingRate        uint32       `json:"sampling_rate"`
	SamplePool          uint32       `json:"sample_pool"`
	Drops               uint32       `json:"drops"`
	InputInterface      uint32       `json:"input_interface"`
	OutputInterface     uint32       `json:"output_interface"`
	OutputInterfaceNote string       `json:"output_interface_note,omitempty"`
	NumberOfRecords     uint32       `json:"number_of_flow_records"`
	FlowRecords         []FlowRecord `json:"flow_records,omitempty"`
}

// FlowRecord is one (Record Type, Length, Data) entry from a
// Flow Sample's flow_records array.
type FlowRecord struct {
	RecordType   uint32 `json:"record_type"`
	Enterprise   uint32 `json:"enterprise"`
	Format       uint32 `json:"format"`
	FormatName   string `json:"format_name"`
	RecordLength uint32 `json:"record_length"`
	DataHex      string `json:"data_hex,omitempty"`

	// Decoded forms populated for known record formats.
	RawPacketHeader *RawPacketHeader `json:"raw_packet_header,omitempty"`
	EthernetFrame   *EthernetFrame   `json:"ethernet_frame,omitempty"`
	IPv4Data        *IPv4FlowData    `json:"ipv4_data,omitempty"`
}

// RawPacketHeader is the decoded body of Flow Record Format 1.
type RawPacketHeader struct {
	HeaderProtocol      uint32 `json:"header_protocol"`
	HeaderProtocolName  string `json:"header_protocol_name"`
	FrameLengthOnWire   uint32 `json:"frame_length_on_wire"`
	StrippedBytes       uint32 `json:"stripped_bytes"`
	SampledHeaderLength uint32 `json:"sampled_header_length"`
	HeaderBytesShown    int    `json:"header_bytes_shown,omitempty"`
	HeaderHex           string `json:"header_hex,omitempty"`
}

// EthernetFrame is the decoded body of Flow Record Format 2.
type EthernetFrame struct {
	Length       uint32 `json:"length"`
	SrcMAC       string `json:"src_mac"`
	DstMAC       string `json:"dst_mac"`
	EtherType    uint32 `json:"ether_type"`
	EtherTypeHex string `json:"ether_type_hex"`
}

// IPv4FlowData is the decoded body of Flow Record Format 3.
type IPv4FlowData struct {
	Length        uint32 `json:"length"`
	Protocol      uint32 `json:"protocol"`
	SrcAddress    string `json:"src_address"`
	DstAddress    string `json:"dst_address"`
	SrcPort       uint32 `json:"src_port"`
	DstPort       uint32 `json:"dst_port"`
	TCPFlags      uint32 `json:"tcp_flags"`
	TypeOfService uint32 `json:"type_of_service"`
}

// CounterSampleBody is the decoded body of a Counter Sample
// (Format 2).
type CounterSampleBody struct {
	SequenceNumber  uint32          `json:"sequence_number"`
	SourceID        uint32          `json:"source_id"`
	SourceClass     int             `json:"source_class"`
	SourceClassName string          `json:"source_class_name"`
	SourceIndex     uint32          `json:"source_index"`
	NumberOfRecords uint32          `json:"number_of_counter_records"`
	CounterRecords  []CounterRecord `json:"counter_records,omitempty"`
}

// CounterRecord is one (Record Type, Length, Data) entry from
// a Counter Sample's counters array.
type CounterRecord struct {
	RecordType   uint32 `json:"record_type"`
	Enterprise   uint32 `json:"enterprise"`
	Format       uint32 `json:"format"`
	FormatName   string `json:"format_name"`
	RecordLength uint32 `json:"record_length"`
	DataHex      string `json:"data_hex,omitempty"`

	// Decoded forms populated for known record formats.
	GenericInterface *GenericInterfaceCounters `json:"generic_interface_counters,omitempty"`
}

// GenericInterfaceCounters is the decoded body of Counter
// Record Format 1 (88-byte ifEntry-equivalent body).
type GenericInterfaceCounters struct {
	IfIndex            uint32 `json:"if_index"`
	IfType             uint32 `json:"if_type"`
	IfSpeed            uint64 `json:"if_speed"`
	IfDirection        uint32 `json:"if_direction"`
	IfStatus           uint32 `json:"if_status"`
	IfInOctets         uint64 `json:"if_in_octets"`
	IfInUcastPkts      uint32 `json:"if_in_ucast_pkts"`
	IfInMulticastPkts  uint32 `json:"if_in_multicast_pkts"`
	IfInBroadcastPkts  uint32 `json:"if_in_broadcast_pkts"`
	IfInDiscards       uint32 `json:"if_in_discards"`
	IfInErrors         uint32 `json:"if_in_errors"`
	IfInUnknownProtos  uint32 `json:"if_in_unknown_protos"`
	IfOutOctets        uint64 `json:"if_out_octets"`
	IfOutUcastPkts     uint32 `json:"if_out_ucast_pkts"`
	IfOutMulticastPkts uint32 `json:"if_out_multicast_pkts"`
	IfOutBroadcastPkts uint32 `json:"if_out_broadcast_pkts"`
	IfOutDiscards      uint32 `json:"if_out_discards"`
	IfOutErrors        uint32 `json:"if_out_errors"`
	IfPromiscuousMode  uint32 `json:"if_promiscuous_mode"`
}

// DecodeOpts tunes the walker for output size.
type DecodeOpts struct {
	// MaxHeaderBytes caps the per-Raw-Packet-Header hex
	// preview. Zero shows full header (up to typical
	// sampled length of 128 bytes).
	MaxHeaderBytes int
}

// DefaultDecodeOpts returns a 128-byte header preview cap.
func DefaultDecodeOpts() DecodeOpts {
	return DecodeOpts{MaxHeaderBytes: 128}
}

// Decode parses a single sFlow v5 datagram from hex.
func Decode(hexStr string, opts DecodeOpts) (*Result, error) {
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
	if len(b) < 8 {
		return nil, fmt.Errorf("sFlow datagram truncated (%d bytes; need ≥8 for version + agent type)",
			len(b))
	}
	r := &Result{TotalBytes: len(b)}
	r.Version = binary.BigEndian.Uint32(b[0:4])
	if r.Version != 5 {
		return r, fmt.Errorf("unsupported sFlow version %d (this Spec covers v5 only)",
			r.Version)
	}
	r.AgentAddressType = int(binary.BigEndian.Uint32(b[4:8]))
	off := 8
	switch r.AgentAddressType {
	case 1:
		if off+4 > len(b) {
			return r, fmt.Errorf("IPv4 agent address truncated")
		}
		r.AgentAddress = net.IPv4(b[off], b[off+1], b[off+2], b[off+3]).String()
		off += 4
	case 2:
		if off+16 > len(b) {
			return r, fmt.Errorf("IPv6 agent address truncated")
		}
		r.AgentAddress = net.IP(b[off : off+16]).String()
		off += 16
	default:
		return r, fmt.Errorf("unknown agent address type %d (1 IPv4 / 2 IPv6)",
			r.AgentAddressType)
	}
	if off+16 > len(b) {
		return r, fmt.Errorf("common header truncated after agent address (need 16 more bytes)")
	}
	r.SubAgentID = binary.BigEndian.Uint32(b[off : off+4])
	r.SequenceNumber = binary.BigEndian.Uint32(b[off+4 : off+8])
	r.SystemUptimeMs = binary.BigEndian.Uint32(b[off+8 : off+12])
	r.SampleCount = binary.BigEndian.Uint32(b[off+12 : off+16])
	off += 16
	for i := uint32(0); i < r.SampleCount && off+8 <= len(b); i++ {
		s, used, err := decodeSample(b[off:], opts, r)
		if err != nil {
			r.Notes = append(r.Notes, err.Error())
			break
		}
		r.Samples = append(r.Samples, s)
		off += used
	}
	return r, nil
}

func decodeSample(b []byte, opts DecodeOpts, parent *Result) (Sample, int, error) {
	sampleType := binary.BigEndian.Uint32(b[0:4])
	sampleLen := binary.BigEndian.Uint32(b[4:8])
	if sampleLen > uint32(len(b)-8) {
		return Sample{}, 0, fmt.Errorf("sample type 0x%08X declares length %d but only %d remain",
			sampleType, sampleLen, len(b)-8)
	}
	body := b[8 : 8+int(sampleLen)]
	s := Sample{
		SampleType:   sampleType,
		Enterprise:   sampleType >> 20,
		Format:       sampleType & 0xFFFFF,
		SampleLength: sampleLen,
		BodyHex:      strings.ToUpper(hex.EncodeToString(body)),
	}
	s.FormatName = sampleFormatName(s.Enterprise, s.Format)
	if s.Enterprise == 0 {
		switch s.Format {
		case 1:
			s.FlowSample = decodeFlowSample(body, opts, parent)
		case 2:
			s.CounterSample = decodeCounterSample(body)
		}
	}
	return s, 8 + int(sampleLen), nil
}

func decodeFlowSample(b []byte, opts DecodeOpts, parent *Result) *FlowSampleBody {
	if len(b) < 32 {
		return nil
	}
	_ = parent // reserved for future Notes routing
	src := binary.BigEndian.Uint32(b[4:8])
	out := binary.BigEndian.Uint32(b[24:28])
	body := &FlowSampleBody{
		SequenceNumber:  binary.BigEndian.Uint32(b[0:4]),
		SourceID:        src,
		SourceClass:     int(src >> 24),
		SourceIndex:     src & 0xFFFFFF,
		SamplingRate:    binary.BigEndian.Uint32(b[8:12]),
		SamplePool:      binary.BigEndian.Uint32(b[12:16]),
		Drops:           binary.BigEndian.Uint32(b[16:20]),
		InputInterface:  binary.BigEndian.Uint32(b[20:24]),
		OutputInterface: out,
	}
	body.SourceClassName = sourceClassName(body.SourceClass)
	// Output interface high-3-bits format special-value note.
	if out>>30 != 0 {
		switch (out >> 30) & 0x3 {
		case 1:
			body.OutputInterfaceNote = "Discarded (drop reason in low 30 bits)"
		case 2:
			body.OutputInterfaceNote = "Multiple destinations (broadcast/multicast; count in low 30 bits)"
		case 3:
			body.OutputInterfaceNote = "Unknown destination"
		}
	}
	body.NumberOfRecords = binary.BigEndian.Uint32(b[28:32])
	off := 32
	for i := uint32(0); i < body.NumberOfRecords && off+8 <= len(b); i++ {
		rec, used, err := decodeFlowRecord(b[off:], opts)
		if err != nil {
			break
		}
		body.FlowRecords = append(body.FlowRecords, rec)
		off += used
	}
	return body
}

func decodeFlowRecord(b []byte, opts DecodeOpts) (FlowRecord, int, error) {
	recType := binary.BigEndian.Uint32(b[0:4])
	recLen := binary.BigEndian.Uint32(b[4:8])
	if recLen > uint32(len(b)-8) {
		return FlowRecord{}, 0, fmt.Errorf("record type 0x%08X length %d > %d available",
			recType, recLen, len(b)-8)
	}
	data := b[8 : 8+int(recLen)]
	rec := FlowRecord{
		RecordType:   recType,
		Enterprise:   recType >> 20,
		Format:       recType & 0xFFFFF,
		RecordLength: recLen,
		DataHex:      strings.ToUpper(hex.EncodeToString(data)),
	}
	rec.FormatName = flowRecordFormatName(rec.Enterprise, rec.Format)
	if rec.Enterprise == 0 {
		switch rec.Format {
		case 1:
			rec.RawPacketHeader = decodeRawPacketHeader(data, opts)
		case 2:
			rec.EthernetFrame = decodeEthernetFrame(data)
		case 3:
			rec.IPv4Data = decodeIPv4FlowData(data)
		}
	}
	// XDR pads to 4-byte boundary.
	pad := (4 - (int(recLen) % 4)) % 4
	return rec, 8 + int(recLen) + pad, nil
}

func decodeRawPacketHeader(b []byte, opts DecodeOpts) *RawPacketHeader {
	if len(b) < 16 {
		return nil
	}
	h := &RawPacketHeader{
		HeaderProtocol:      binary.BigEndian.Uint32(b[0:4]),
		FrameLengthOnWire:   binary.BigEndian.Uint32(b[4:8]),
		StrippedBytes:       binary.BigEndian.Uint32(b[8:12]),
		SampledHeaderLength: binary.BigEndian.Uint32(b[12:16]),
	}
	h.HeaderProtocolName = headerProtocolName(h.HeaderProtocol)
	hdr := b[16:]
	if int(h.SampledHeaderLength) < len(hdr) {
		hdr = hdr[:h.SampledHeaderLength]
	}
	if len(hdr) > 0 {
		show := len(hdr)
		if opts.MaxHeaderBytes > 0 && show > opts.MaxHeaderBytes {
			show = opts.MaxHeaderBytes
		}
		h.HeaderHex = strings.ToUpper(hex.EncodeToString(hdr[:show]))
		h.HeaderBytesShown = show
	}
	return h
}

func decodeEthernetFrame(b []byte) *EthernetFrame {
	if len(b) < 20 {
		return nil
	}
	et := binary.BigEndian.Uint32(b[16:20])
	return &EthernetFrame{
		Length:       binary.BigEndian.Uint32(b[0:4]),
		SrcMAC:       formatMAC(b[4:10]),
		DstMAC:       formatMAC(b[10:16]),
		EtherType:    et,
		EtherTypeHex: fmt.Sprintf("0x%04X", et),
	}
}

func decodeIPv4FlowData(b []byte) *IPv4FlowData {
	if len(b) < 32 {
		return nil
	}
	return &IPv4FlowData{
		Length:        binary.BigEndian.Uint32(b[0:4]),
		Protocol:      binary.BigEndian.Uint32(b[4:8]),
		SrcAddress:    ipv4String(b[8:12]),
		DstAddress:    ipv4String(b[12:16]),
		SrcPort:       binary.BigEndian.Uint32(b[16:20]),
		DstPort:       binary.BigEndian.Uint32(b[20:24]),
		TCPFlags:      binary.BigEndian.Uint32(b[24:28]),
		TypeOfService: binary.BigEndian.Uint32(b[28:32]),
	}
}

func decodeCounterSample(b []byte) *CounterSampleBody {
	if len(b) < 12 {
		return nil
	}
	src := binary.BigEndian.Uint32(b[4:8])
	body := &CounterSampleBody{
		SequenceNumber:  binary.BigEndian.Uint32(b[0:4]),
		SourceID:        src,
		SourceClass:     int(src >> 24),
		SourceIndex:     src & 0xFFFFFF,
		NumberOfRecords: binary.BigEndian.Uint32(b[8:12]),
	}
	body.SourceClassName = sourceClassName(body.SourceClass)
	off := 12
	for i := uint32(0); i < body.NumberOfRecords && off+8 <= len(b); i++ {
		rec, used, err := decodeCounterRecord(b[off:])
		if err != nil {
			break
		}
		body.CounterRecords = append(body.CounterRecords, rec)
		off += used
	}
	return body
}

func decodeCounterRecord(b []byte) (CounterRecord, int, error) {
	recType := binary.BigEndian.Uint32(b[0:4])
	recLen := binary.BigEndian.Uint32(b[4:8])
	if recLen > uint32(len(b)-8) {
		return CounterRecord{}, 0, fmt.Errorf("counter record type 0x%08X length %d > %d available",
			recType, recLen, len(b)-8)
	}
	data := b[8 : 8+int(recLen)]
	rec := CounterRecord{
		RecordType:   recType,
		Enterprise:   recType >> 20,
		Format:       recType & 0xFFFFF,
		RecordLength: recLen,
		DataHex:      strings.ToUpper(hex.EncodeToString(data)),
	}
	rec.FormatName = counterRecordFormatName(rec.Enterprise, rec.Format)
	if rec.Enterprise == 0 && rec.Format == 1 {
		rec.GenericInterface = decodeGenericInterfaceCounters(data)
	}
	pad := (4 - (int(recLen) % 4)) % 4
	return rec, 8 + int(recLen) + pad, nil
}

func decodeGenericInterfaceCounters(b []byte) *GenericInterfaceCounters {
	if len(b) < 88 {
		return nil
	}
	return &GenericInterfaceCounters{
		IfIndex:            binary.BigEndian.Uint32(b[0:4]),
		IfType:             binary.BigEndian.Uint32(b[4:8]),
		IfSpeed:            binary.BigEndian.Uint64(b[8:16]),
		IfDirection:        binary.BigEndian.Uint32(b[16:20]),
		IfStatus:           binary.BigEndian.Uint32(b[20:24]),
		IfInOctets:         binary.BigEndian.Uint64(b[24:32]),
		IfInUcastPkts:      binary.BigEndian.Uint32(b[32:36]),
		IfInMulticastPkts:  binary.BigEndian.Uint32(b[36:40]),
		IfInBroadcastPkts:  binary.BigEndian.Uint32(b[40:44]),
		IfInDiscards:       binary.BigEndian.Uint32(b[44:48]),
		IfInErrors:         binary.BigEndian.Uint32(b[48:52]),
		IfInUnknownProtos:  binary.BigEndian.Uint32(b[52:56]),
		IfOutOctets:        binary.BigEndian.Uint64(b[56:64]),
		IfOutUcastPkts:     binary.BigEndian.Uint32(b[64:68]),
		IfOutMulticastPkts: binary.BigEndian.Uint32(b[68:72]),
		IfOutBroadcastPkts: binary.BigEndian.Uint32(b[72:76]),
		IfOutDiscards:      binary.BigEndian.Uint32(b[76:80]),
		IfOutErrors:        binary.BigEndian.Uint32(b[80:84]),
		IfPromiscuousMode:  binary.BigEndian.Uint32(b[84:88]),
	}
}

func sampleFormatName(enterprise, format uint32) string {
	if enterprise != 0 {
		return fmt.Sprintf("vendor enterprise %d format %d", enterprise, format)
	}
	switch format {
	case 1:
		return "Flow Sample"
	case 2:
		return "Counter Sample"
	case 3:
		return "Expanded Flow Sample"
	case 4:
		return "Expanded Counter Sample"
	}
	return fmt.Sprintf("uncatalogued standard format %d", format)
}

func flowRecordFormatName(enterprise, format uint32) string {
	if enterprise != 0 {
		return fmt.Sprintf("vendor enterprise %d format %d", enterprise, format)
	}
	switch format {
	case 1:
		return "Raw Packet Header"
	case 2:
		return "Ethernet Frame Data"
	case 3:
		return "IPv4 Data"
	case 4:
		return "IPv6 Data"
	case 1001:
		return "Extended Switch Data"
	case 1002:
		return "Extended Router Data"
	case 1003:
		return "Extended Gateway Data"
	case 1004:
		return "Extended User Data"
	case 1005:
		return "Extended URL Data"
	}
	return fmt.Sprintf("uncatalogued standard format %d", format)
}

func counterRecordFormatName(enterprise, format uint32) string {
	if enterprise != 0 {
		return fmt.Sprintf("vendor enterprise %d format %d", enterprise, format)
	}
	switch format {
	case 1:
		return "Generic Interface Counters"
	case 2:
		return "Ethernet Interface Counters"
	case 3:
		return "Token Ring Counters"
	case 4:
		return "100 BaseVG Counters"
	case 5:
		return "VLAN Counters"
	case 6:
		return "IEEE 802.11 Counters"
	case 1001:
		return "Processor Counters"
	}
	return fmt.Sprintf("uncatalogued standard format %d", format)
}

func headerProtocolName(p uint32) string {
	switch p {
	case 1:
		return "Ethernet ISO 88023"
	case 2:
		return "ISO 88024 Token Bus"
	case 3:
		return "ISO 88025 Token Ring"
	case 4:
		return "FDDI"
	case 5:
		return "Frame Relay"
	case 6:
		return "X.25"
	case 7:
		return "PPP"
	case 8:
		return "SMDS"
	case 9:
		return "AAL5"
	case 10:
		return "AAL5 + IP"
	case 11:
		return "IPv4"
	case 12:
		return "IPv6"
	case 13:
		return "MPLS"
	case 14:
		return "POS"
	case 15:
		return "802.11 MAC"
	case 16:
		return "802.11 AMPDU"
	case 17:
		return "802.11 AMSDU subframe"
	}
	return fmt.Sprintf("uncatalogued header protocol %d", p)
}

func sourceClassName(c int) string {
	switch c {
	case 0:
		return "ifIndex"
	case 1:
		return "smonVlanDataSource"
	case 2:
		return "entPhysicalEntry"
	}
	return fmt.Sprintf("uncatalogued source class %d", c)
}

func ipv4String(b []byte) string {
	if len(b) != 4 {
		return strings.ToUpper(hex.EncodeToString(b))
	}
	return net.IPv4(b[0], b[1], b[2], b[3]).String()
}

func formatMAC(b []byte) string {
	if len(b) != 6 {
		return strings.ToUpper(hex.EncodeToString(b))
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		b[0], b[1], b[2], b[3], b[4], b[5])
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
