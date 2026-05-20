package netflow

import (
	"strings"
	"testing"
)

func TestDecode_HeaderOnly_CountZero(t *testing.T) {
	// Version 5, Count 0, SysUptime 1 ms, Unix Secs 100,
	// Flow Sequence 100, Engine Type 0, Engine ID 1,
	// Sampling 0000 (unsampled).
	in := "00050000 00000001 00000064 00000000 00000064 0001 0000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 5 {
		t.Errorf("version: %d", r.Version)
	}
	if r.Count != 0 {
		t.Errorf("count: %d", r.Count)
	}
	if r.FlowSequence != 100 {
		t.Errorf("flow seq: %d", r.FlowSequence)
	}
	if r.EngineID != 1 {
		t.Errorf("engine ID: %d", r.EngineID)
	}
	if r.SamplingModeName != "unsampled" {
		t.Errorf("sampling mode: %q", r.SamplingModeName)
	}
	if r.ExportTimestampISO == "" {
		t.Errorf("expected export timestamp")
	}
}

func TestDecode_OneTCPFlow_ACKOnly(t *testing.T) {
	// Header: V5 Count=1 SysUptime=1000ms FlowSeq=101.
	// Record: 192.168.1.1:443 → 10.0.0.1:54321, TCP, ACK only,
	// 100 packets / 10000 bytes, First=100ms Last=1000ms.
	in := "00050001 000003E8 60000000 00000000 00000065 0001 0000" +
		"C0A80101 0A000001 C0A80101 0001 0002" +
		"00000064 00002710 00000064 000003E8" +
		"01BB D431 00 10 06 00 0000 0000 18 18 0000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Count != 1 {
		t.Errorf("count: %d", r.Count)
	}
	if len(r.Records) != 1 {
		t.Fatalf("records: %d", len(r.Records))
	}
	rec := r.Records[0]
	if rec.SrcAddress != "192.168.1.1" || rec.DstAddress != "10.0.0.1" {
		t.Errorf("addrs: %s → %s", rec.SrcAddress, rec.DstAddress)
	}
	if rec.SrcPort != 443 || rec.DstPort != 54321 {
		t.Errorf("ports: %d → %d", rec.SrcPort, rec.DstPort)
	}
	if rec.ProtocolName != "TCP" {
		t.Errorf("protocol: %q", rec.ProtocolName)
	}
	if !rec.TCPFlagBreakdown.ACK || rec.TCPFlagBreakdown.SYN ||
		rec.TCPFlagBreakdown.FIN {
		t.Errorf("flags: %+v", rec.TCPFlagBreakdown)
	}
	if rec.Packets != 100 || rec.Bytes != 10000 {
		t.Errorf("counters: pkts=%d bytes=%d", rec.Packets, rec.Bytes)
	}
	if rec.DurationMs != 900 {
		t.Errorf("duration: %d (expected 900)", rec.DurationMs)
	}
	if rec.SrcPrefix != "192.168.1.1/24" {
		t.Errorf("src prefix: %q", rec.SrcPrefix)
	}
}

func TestDecode_AllTCPFlagsSet(t *testing.T) {
	in := "00050001 00000000 00000000 00000000 00000001 0001 0000" +
		"C0A80101 0A000001 00000000 0000 0000" +
		"00000001 00000040 00000000 00000000" +
		"0000 0000 00 FF 06 00 0000 0000 00 00 0000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	f := r.Records[0].TCPFlagBreakdown
	if !f.FIN || !f.SYN || !f.RST || !f.PSH || !f.ACK || !f.URG ||
		!f.ECE || !f.CWR {
		t.Errorf("expected all TCP flags: %+v", f)
	}
}

func TestDecode_UDPFlow(t *testing.T) {
	// Protocol 17 (UDP), Port 53 → 32768.
	in := "00050001 00000000 00000000 00000000 00000001 0001 0000" +
		"08080808 C0A80101 00000000 0000 0000" +
		"00000001 00000040 00000000 00000000" +
		"0035 8000 00 00 11 00 0000 0000 00 00 0000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Records[0].ProtocolName != "UDP" {
		t.Errorf("protocol: %q", r.Records[0].ProtocolName)
	}
	if r.Records[0].SrcPort != 53 || r.Records[0].DstPort != 32768 {
		t.Errorf("ports: %+v", r.Records[0])
	}
}

func TestDecode_ProtocolNameTable(t *testing.T) {
	cases := map[int]string{
		0:   "HOPOPT",
		1:   "ICMP",
		2:   "IGMP",
		6:   "TCP",
		17:  "UDP",
		47:  "GRE",
		50:  "ESP",
		51:  "AH",
		58:  "ICMPv6",
		89:  "OSPF",
		103: "PIM",
		112: "VRRP",
		132: "SCTP",
	}
	for k, v := range cases {
		if got := protocolName(k); got != v {
			t.Errorf("protocolName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_UncataloguedProtocol(t *testing.T) {
	if got := protocolName(99); !strings.Contains(got, "uncatalogued") {
		t.Errorf("uncatalogued protocol: %q", got)
	}
}

func TestDecode_SamplingModeRandom(t *testing.T) {
	// Sampling Interval bytes 22-23: top 2 bits = mode (2 = random),
	// bottom 14 bits = N (1000 = 0x3E8).
	// 0b10 << 14 | 1000 = 0x8000 + 0x3E8 = 0x83E8.
	in := "00050000 00000001 00000064 00000000 00000064 0001 83E8"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.SamplingMode != 2 {
		t.Errorf("sampling mode: %d", r.SamplingMode)
	}
	if r.SamplingModeName != "1-in-N random" {
		t.Errorf("sampling mode name: %q", r.SamplingModeName)
	}
	if r.SamplingInterval != 1000 {
		t.Errorf("sampling interval: %d", r.SamplingInterval)
	}
}

func TestDecode_SamplingModeTable(t *testing.T) {
	cases := map[int]string{
		0: "unsampled",
		1: "1-in-N deterministic",
		2: "1-in-N random",
	}
	for k, v := range cases {
		if got := samplingModeName(k); got != v {
			t.Errorf("samplingModeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_TruncatedHeader(t *testing.T) {
	_, err := Decode("0005 0000")
	if err == nil {
		t.Fatal("expected error for short header")
	}
}

func TestDecode_UnsupportedVersion(t *testing.T) {
	// Version 9 (NetFlow v9 — not handled by this Spec).
	in := "00090000 00000001 00000064 00000000 00000064 0001 0000"
	_, err := Decode(in)
	if err == nil {
		t.Fatal("expected error for unsupported version")
	}
}

func TestDecode_CountMismatchesPacket_Note(t *testing.T) {
	// Header declares Count=5 but only 1 record's worth of
	// bytes follow.
	in := "00050005 00000000 00000000 00000000 00000001 0001 0000" +
		"C0A80101 0A000001 00000000 0000 0000" +
		"00000001 00000040 00000000 00000000" +
		"0000 0000 00 10 06 00 0000 0000 18 18 0000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.Notes) == 0 {
		t.Fatalf("expected truncation note")
	}
	if !strings.Contains(r.Notes[0], "5 records") {
		t.Errorf("expected mismatch note: %v", r.Notes)
	}
}

func TestDecode_MultipleRecords(t *testing.T) {
	// 2 flows.
	hdr := "00050002 00000000 00000000 00000000 00000001 0001 0000"
	rec1 := "C0A80101 0A000001 00000000 0000 0000" +
		"00000001 00000040 00000000 00000000" +
		"0050 8000 00 00 06 00 0000 0000 18 18 0000"
	rec2 := "C0A80102 0A000002 00000000 0000 0000" +
		"00000002 00000080 00000000 00000000" +
		"0035 8001 00 00 11 00 0000 0000 18 18 0000"
	in := hdr + rec1 + rec2
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.Records) != 2 {
		t.Fatalf("records: %d", len(r.Records))
	}
	if r.Records[0].SrcAddress != "192.168.1.1" ||
		r.Records[1].SrcAddress != "192.168.1.2" {
		t.Errorf("srcs: %s / %s",
			r.Records[0].SrcAddress, r.Records[1].SrcAddress)
	}
	if r.Records[0].ProtocolName != "TCP" ||
		r.Records[1].ProtocolName != "UDP" {
		t.Errorf("protocols: %s / %s",
			r.Records[0].ProtocolName, r.Records[1].ProtocolName)
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":   "",
		"odd hex": "0005 000",
		"bad hex": "ZZ05 0000 00000001 00000064 00000000 00000064 0001 0000",
	}
	for name, in := range cases {
		_, err := Decode(in)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
