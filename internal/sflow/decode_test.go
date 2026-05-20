package sflow

import (
	"strings"
	"testing"
)

func TestDecode_MinimalDatagramNoSamples(t *testing.T) {
	// v5 header: AgentIPv4=192.168.1.1, SubAgent=1,
	// Seq=123, Uptime=1000000, SampleCount=0.
	in := "00000005 00000001 C0A80101" +
		"00000001 0000007B 000F4240 00000000"
	r, err := Decode(in, DefaultDecodeOpts())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 5 {
		t.Errorf("version: %d", r.Version)
	}
	if r.AgentAddress != "192.168.1.1" {
		t.Errorf("agent: %q", r.AgentAddress)
	}
	if r.SubAgentID != 1 || r.SequenceNumber != 123 ||
		r.SystemUptimeMs != 1000000 {
		t.Errorf("header counters: %+v", r)
	}
	if r.SampleCount != 0 || len(r.Samples) != 0 {
		t.Errorf("samples: count=%d len=%d", r.SampleCount, len(r.Samples))
	}
}

func TestDecode_FlowSample_NoRecords(t *testing.T) {
	// Header + 1 Flow Sample with no flow_records.
	// FlowSampleBody: Seq=1, SourceID=0x00000064 (ifIndex 100),
	// SamplingRate=1024, SamplePool=10000, Drops=0,
	// In=1, Out=2, NumberOfRecords=0.
	// Body length = 32 bytes.
	in := "00000005 00000001 C0A80101" +
		"00000001 0000007B 000F4240 00000001" +
		// Sample type 1 (Flow Sample) + length 32.
		"00000001 00000020" +
		// Body:
		"00000001" + // Seq
		"00000064" + // SourceID (class=0, idx=100)
		"00000400" + // SamplingRate 1024
		"00002710" + // SamplePool 10000
		"00000000" + // Drops
		"00000001" + // In iface
		"00000002" + // Out iface
		"00000000" // NumberOfRecords
	r, err := Decode(in, DefaultDecodeOpts())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.Samples) != 1 {
		t.Fatalf("samples: %d", len(r.Samples))
	}
	s := r.Samples[0]
	if s.FormatName != "Flow Sample" {
		t.Errorf("format: %q", s.FormatName)
	}
	if s.FlowSample == nil {
		t.Fatal("flow sample body nil")
	}
	fs := s.FlowSample
	if fs.SamplingRate != 1024 {
		t.Errorf("sampling rate: %d", fs.SamplingRate)
	}
	if fs.SourceIndex != 100 {
		t.Errorf("source index: %d", fs.SourceIndex)
	}
	if fs.InputInterface != 1 || fs.OutputInterface != 2 {
		t.Errorf("interfaces: %+v", fs)
	}
}

func TestDecode_FlowSample_WithRawPacketHeader(t *testing.T) {
	// Header + Flow Sample with 1 Raw Packet Header record
	// containing 4 bytes of "sampled" header.
	// FlowSampleBody = 32 fixed bytes + 1 record.
	// Raw Packet Header body = 16 fixed bytes + 4 hdr bytes
	// = 20 bytes. Padded to 4-byte boundary = 20 already.
	// Record = 8 header + 20 body = 28 bytes.
	// Sample length = 32 + 28 = 60 bytes.
	in := "00000005 00000001 C0A80101" +
		"00000001 0000007B 000F4240 00000001" +
		// Sample type 1 + length 60.
		"00000001 0000003C" +
		// FlowSample body fixed (32 bytes):
		"00000001 00000064 00000400 00002710 00000000" +
		"00000001 00000002 00000001" + // NumberOfRecords=1
		// Flow Record header: type 1 + length 20.
		"00000001 00000014" +
		// Raw Packet Header body:
		"00000001" + // HeaderProtocol=1 (Ethernet)
		"0000005E" + // FrameLength=94
		"00000004" + // StrippedBytes=4
		"00000010" + // SampledHeaderLength=16 (but we only have 4 bytes — that's OK for test)
		"DEADBEEF" // Header bytes
	r, err := Decode(in, DefaultDecodeOpts())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Samples[0].FlowSample == nil {
		t.Fatal("flow sample body nil")
	}
	recs := r.Samples[0].FlowSample.FlowRecords
	if len(recs) != 1 {
		t.Fatalf("records: %d", len(recs))
	}
	if recs[0].FormatName != "Raw Packet Header" {
		t.Errorf("record format: %q", recs[0].FormatName)
	}
	h := recs[0].RawPacketHeader
	if h == nil {
		t.Fatal("raw packet header body nil")
	}
	if h.HeaderProtocolName != "Ethernet ISO 88023" {
		t.Errorf("header protocol: %q", h.HeaderProtocolName)
	}
	if h.FrameLengthOnWire != 94 {
		t.Errorf("frame length: %d", h.FrameLengthOnWire)
	}
}

func TestDecode_FlowSample_WithEthernetFrame(t *testing.T) {
	// FlowSample with one Ethernet Frame Data record
	// (Format 2). Body = 20 bytes (length + 6 src + 6 dst
	// + 4 ethertype with padding in low bits).
	// Record = 8 header + 20 body = 28.
	// Sample = 32 + 28 = 60.
	in := "00000005 00000001 C0A80101" +
		"00000001 0000007B 000F4240 00000001" +
		"00000001 0000003C" +
		"00000001 00000064 00000400 00002710 00000000" +
		"00000001 00000002 00000001" +
		// Format 2 + length 20.
		"00000002 00000014" +
		"00000040" + // Length=64
		"001122334455" + // src MAC
		"AABBCCDDEEFF" + // dst MAC
		"00000800" // EtherType IPv4 (0x0800)
	r, err := Decode(in, DefaultDecodeOpts())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	rec := r.Samples[0].FlowSample.FlowRecords[0]
	if rec.FormatName != "Ethernet Frame Data" {
		t.Errorf("format: %q", rec.FormatName)
	}
	e := rec.EthernetFrame
	if e == nil {
		t.Fatal("ethernet frame body nil")
	}
	if e.SrcMAC != "00:11:22:33:44:55" || e.DstMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("MACs: src=%q dst=%q", e.SrcMAC, e.DstMAC)
	}
	if e.EtherType != 0x800 {
		t.Errorf("ether type: 0x%X", e.EtherType)
	}
}

func TestDecode_CounterSample_GenericInterface(t *testing.T) {
	// Counter sample with one Generic Interface Counters
	// record (88-byte body).
	// CounterSample body = 12 fixed + 1 record.
	// Counter record = 8 header + 88 body = 96 bytes.
	// Sample length = 12 + 96 = 108 = 0x6C.
	body := "00000001 00000064 00000001" // Seq, Source, Count
	gif := "00000064" +                  // ifIndex=100
		"00000006" + // ifType=6 (ethernetCsmacd)
		"00000000 3B9ACA00" + // ifSpeed=1000000000 (1Gbps)
		"00000001" + // ifDirection=1 (full duplex)
		"00000003" + // ifStatus=3 (up + admin up)
		"00000000 0000C350" + // InOctets=50000
		"00000064" + // InUcast=100
		"0000000A" + "00000005" + // InMulticast=10, InBroadcast=5
		"00000000" + "00000000" + "00000000" + // Discards, Errors, UnknownProtos
		"00000000 0000C350" + // OutOctets=50000
		"00000064" + // OutUcast=100
		"00000000" + "00000000" + // OutMulticast, OutBroadcast
		"00000000" + "00000000" + // OutDiscards, OutErrors
		"00000000" // PromiscuousMode
	rec := "00000001 00000058" + gif
	sample := body + rec
	in := "00000005 00000001 C0A80101" +
		"00000001 0000007B 000F4240 00000001" +
		"00000002 0000006C" + sample
	r, err := Decode(in, DefaultDecodeOpts())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	s := r.Samples[0]
	if s.FormatName != "Counter Sample" {
		t.Errorf("sample format: %q", s.FormatName)
	}
	cs := s.CounterSample
	if cs == nil {
		t.Fatal("counter sample body nil")
	}
	if len(cs.CounterRecords) != 1 {
		t.Fatalf("counter records: %d", len(cs.CounterRecords))
	}
	g := cs.CounterRecords[0].GenericInterface
	if g == nil {
		t.Fatal("generic interface counters nil")
	}
	if g.IfIndex != 100 || g.IfType != 6 {
		t.Errorf("if: %+v", g)
	}
	if g.IfSpeed != 1000000000 {
		t.Errorf("if speed: %d", g.IfSpeed)
	}
	if g.IfInOctets != 50000 || g.IfOutOctets != 50000 {
		t.Errorf("octets: in=%d out=%d", g.IfInOctets, g.IfOutOctets)
	}
}

func TestDecode_IPv6AgentAddress(t *testing.T) {
	// Header with IPv6 agent address fe80::1.
	in := "00000005 00000002" +
		"FE800000 00000000 00000000 00000001" +
		"00000001 0000007B 000F4240 00000000"
	r, err := Decode(in, DefaultDecodeOpts())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.AgentAddress != "fe80::1" {
		t.Errorf("agent: %q", r.AgentAddress)
	}
}

func TestDecode_SampleFormatTable(t *testing.T) {
	cases := map[uint32]string{
		1: "Flow Sample",
		2: "Counter Sample",
		3: "Expanded Flow Sample",
		4: "Expanded Counter Sample",
	}
	for k, v := range cases {
		if got := sampleFormatName(0, k); got != v {
			t.Errorf("sampleFormatName(0, %d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_FlowRecordFormatTable(t *testing.T) {
	cases := map[uint32]string{
		1: "Raw Packet Header",
		2: "Ethernet Frame Data",
		3: "IPv4 Data",
		4: "IPv6 Data",
	}
	for k, v := range cases {
		if got := flowRecordFormatName(0, k); got != v {
			t.Errorf("flowRecordFormatName(0, %d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_CounterRecordFormatTable(t *testing.T) {
	cases := map[uint32]string{
		1: "Generic Interface Counters",
		2: "Ethernet Interface Counters",
		5: "VLAN Counters",
	}
	for k, v := range cases {
		if got := counterRecordFormatName(0, k); got != v {
			t.Errorf("counterRecordFormatName(0, %d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_HeaderProtocolTable(t *testing.T) {
	cases := map[uint32]string{
		1:  "Ethernet ISO 88023",
		11: "IPv4",
		12: "IPv6",
		13: "MPLS",
		15: "802.11 MAC",
	}
	for k, v := range cases {
		if got := headerProtocolName(k); got != v {
			t.Errorf("headerProtocolName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_VendorEnterpriseFormat(t *testing.T) {
	// Sample type with enterprise=42, format=7 →
	// (42 << 20) | 7 = 0x02A00007.
	if got := sampleFormatName(42, 7); !strings.Contains(got, "vendor enterprise 42") {
		t.Errorf("vendor format: %q", got)
	}
}

func TestDecode_UnsupportedVersion(t *testing.T) {
	in := "00000004 00000001 C0A80101"
	_, err := Decode(in, DefaultDecodeOpts())
	if err == nil {
		t.Fatal("expected error for v4")
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":   "",
		"odd hex": "00 00",
		"short":   "00000005",
		"bad hex": "ZZ000005 00000001 C0A80101 00000001 0000007B 000F4240 00000000",
	}
	for name, in := range cases {
		_, err := Decode(in, DefaultDecodeOpts())
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
