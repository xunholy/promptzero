package sctp

import (
	"testing"
)

func TestDecode_Heartbeat(t *testing.T) {
	// Common header + HEARTBEAT with empty Info param.
	in := "04D2 162E DEADBEEF 12345678 04 00 0008 0001 0004"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.SourcePort != 1234 || r.DestinationPort != 5678 {
		t.Errorf("ports: %d → %d", r.SourcePort, r.DestinationPort)
	}
	if r.VerificationTag != 0xDEADBEEF {
		t.Errorf("vtag: 0x%08X", r.VerificationTag)
	}
	if len(r.Chunks) != 1 {
		t.Fatalf("chunks: %d", len(r.Chunks))
	}
	c := r.Chunks[0]
	if c.TypeName != "HEARTBEAT" {
		t.Errorf("chunk type: %q", c.TypeName)
	}
	if c.HeartbeatInfo == nil ||
		c.HeartbeatInfo.InfoParameterType != 1 {
		t.Errorf("heartbeat info: %+v", c.HeartbeatInfo)
	}
}

func TestDecode_INITMinimal(t *testing.T) {
	// INIT with InitiateTag=0xCAFEBABE, a_rwnd=64K,
	// 1 outbound + 1 inbound stream, Initial TSN=100,
	// no parameters.
	in := "04D2 162E 00000000 12345678" +
		"01 00 0014 CAFEBABE 00010000 0001 0001 00000064"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	c := r.Chunks[0]
	if c.TypeName != "INIT" {
		t.Errorf("chunk type: %q", c.TypeName)
	}
	ic := c.InitChunk
	if ic == nil {
		t.Fatal("INIT body nil")
	}
	if ic.InitiateTag != 0xCAFEBABE {
		t.Errorf("initiate tag: 0x%08X", ic.InitiateTag)
	}
	if ic.AdvReceiverWindowCredit != 0x00010000 {
		t.Errorf("a_rwnd: %d", ic.AdvReceiverWindowCredit)
	}
	if ic.OutboundStreams != 1 || ic.InboundStreams != 1 {
		t.Errorf("streams: out=%d in=%d",
			ic.OutboundStreams, ic.InboundStreams)
	}
	if ic.InitialTSN != 100 {
		t.Errorf("initial TSN: %d", ic.InitialTSN)
	}
}

func TestDecode_INITWithIPv4Parameter(t *testing.T) {
	// INIT + IPv4 Address parameter for 192.168.1.1.
	in := "04D2 162E 00000000 12345678" +
		"01 00 001C CAFEBABE 00010000 0001 0001 00000064" +
		"0005 0008 C0A80101"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	ic := r.Chunks[0].InitChunk
	if ic == nil || len(ic.Parameters) != 1 {
		t.Fatalf("parameters: %+v", ic)
	}
	p := ic.Parameters[0]
	if p.TypeName != "IPv4 Address" {
		t.Errorf("param type: %q", p.TypeName)
	}
	if p.IPv4Address != "192.168.1.1" {
		t.Errorf("ipv4: %q", p.IPv4Address)
	}
}

func TestDecode_DATAWithDiameterPPID(t *testing.T) {
	// DATA chunk with PPID 46 (Diameter), flags B+E.
	in := "04D2 162E DEADBEEF 12345678" +
		"00 03 0014 00000001 0000 0000 0000002E 01020304"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	d := r.Chunks[0].DataChunk
	if d == nil {
		t.Fatal("DATA body nil")
	}
	if d.PPID != 46 {
		t.Errorf("PPID: %d", d.PPID)
	}
	if d.PPIDName != "Diameter (cleartext)" {
		t.Errorf("PPID name: %q", d.PPIDName)
	}
	if !d.FlagBeginning || !d.FlagEnding {
		t.Errorf("flags B+E should be set: %+v", d)
	}
	if d.FlagUnordered || d.FlagSACKImm {
		t.Errorf("flags U/I should be clear: %+v", d)
	}
	if d.UserDataHex != "01020304" {
		t.Errorf("user data: %q", d.UserDataHex)
	}
}

func TestDecode_SACK(t *testing.T) {
	// SACK with Cumulative TSN Ack=100, a_rwnd=64K, no
	// gap blocks or duplicate TSNs.
	in := "04D2 162E DEADBEEF 12345678" +
		"03 00 0010 00000064 00010000 0000 0000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	s := r.Chunks[0].SACKChunk
	if s == nil {
		t.Fatal("SACK body nil")
	}
	if s.CumulativeTSNAck != 100 {
		t.Errorf("cum tsn ack: %d", s.CumulativeTSNAck)
	}
	if s.NumGapAckBlocks != 0 || s.NumDuplicateTSNs != 0 {
		t.Errorf("gap/dup counts: %+v", s)
	}
}

func TestDecode_SACKWithGapAndDup(t *testing.T) {
	// SACK with 1 gap block + 1 duplicate TSN.
	in := "04D2 162E DEADBEEF 12345678" +
		"03 00 0018 00000064 00010000 0001 0001" +
		"0002 0005" + // gap: start=2, end=5
		"00000063" // dup TSN=99
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	s := r.Chunks[0].SACKChunk
	if s.NumGapAckBlocks != 1 || s.NumDuplicateTSNs != 1 {
		t.Errorf("counts: %+v", s)
	}
	if len(s.GapAckBlocks) != 1 ||
		s.GapAckBlocks[0].Start != 2 || s.GapAckBlocks[0].End != 5 {
		t.Errorf("gap blocks: %+v", s.GapAckBlocks)
	}
	if len(s.DuplicateTSNs) != 1 || s.DuplicateTSNs[0] != 99 {
		t.Errorf("dup TSNs: %+v", s.DuplicateTSNs)
	}
}

func TestDecode_MultipleChunks(t *testing.T) {
	// HEARTBEAT followed by SACK.
	in := "04D2 162E DEADBEEF 12345678" +
		"04 00 0008 0001 0004" +
		"03 00 0010 00000064 00010000 0000 0000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.Chunks) != 2 {
		t.Fatalf("chunks: %d", len(r.Chunks))
	}
	if r.Chunks[0].TypeName != "HEARTBEAT" ||
		r.Chunks[1].TypeName != "SACK" {
		t.Errorf("chunk types: %q / %q",
			r.Chunks[0].TypeName, r.Chunks[1].TypeName)
	}
}

func TestDecode_ABORTWithErrorCause(t *testing.T) {
	// ABORT (type 6) with Cause 13 (Protocol Violation),
	// no body.
	in := "04D2 162E DEADBEEF 12345678" +
		"06 00 0008 000D 0004"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Chunks[0].TypeName != "ABORT" {
		t.Errorf("chunk type: %q", r.Chunks[0].TypeName)
	}
	if len(r.Chunks[0].ErrorCauses) != 1 {
		t.Fatalf("error causes: %+v", r.Chunks[0].ErrorCauses)
	}
	if r.Chunks[0].ErrorCauses[0].CodeName != "Protocol Violation" {
		t.Errorf("cause name: %q",
			r.Chunks[0].ErrorCauses[0].CodeName)
	}
}

func TestDecode_PaddingAlignment(t *testing.T) {
	// DATA chunk with 5-byte user data → length=17,
	// padded to 20. Following chunk must parse cleanly.
	in := "04D2 162E DEADBEEF 12345678" +
		"00 03 0015 00000001 0000 0000 0000002E 0102030405 000000" +
		"04 00 0008 0001 0004"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.Chunks) != 2 {
		t.Fatalf("chunks (padding may have eaten next chunk): %d",
			len(r.Chunks))
	}
	if r.Chunks[1].TypeName != "HEARTBEAT" {
		t.Errorf("second chunk: %q", r.Chunks[1].TypeName)
	}
}

func TestDecode_ChunkTypeTable(t *testing.T) {
	cases := map[int]string{
		0:   "DATA",
		1:   "INIT",
		2:   "INIT_ACK",
		3:   "SACK",
		4:   "HEARTBEAT",
		5:   "HEARTBEAT_ACK",
		6:   "ABORT",
		7:   "SHUTDOWN",
		8:   "SHUTDOWN_ACK",
		9:   "ERROR",
		10:  "COOKIE_ECHO",
		11:  "COOKIE_ACK",
		12:  "ECNE",
		13:  "CWR",
		14:  "SHUTDOWN_COMPLETE",
		15:  "AUTH",
		128: "ASCONF_ACK",
		129: "RE-CONFIG",
		130: "PAD",
		132: "ASCONF",
		192: "FORWARD-TSN",
	}
	for k, v := range cases {
		if got := chunkTypeName(k); got != v {
			t.Errorf("chunkTypeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_PPIDNameTable(t *testing.T) {
	cases := map[uint32]string{
		3:  "M3UA (MTP3-User Adaptation)",
		4:  "SUA (SCCP-User Adaptation)",
		18: "S1AP (LTE eNodeB to MME)",
		27: "X2AP (LTE eNodeB-to-eNodeB)",
		46: "Diameter (cleartext)",
		47: "Diameter (over DTLS)",
		60: "NGAP (5G NG Application Protocol)",
	}
	for k, v := range cases {
		if got := ppidName(k); got != v {
			t.Errorf("ppidName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_ParameterTypeTable(t *testing.T) {
	cases := map[int]string{
		1:  "Heartbeat Info",
		5:  "IPv4 Address",
		6:  "IPv6 Address",
		7:  "State Cookie",
		11: "Hostname",
		12: "Supported Address Types",
	}
	for k, v := range cases {
		if got := parameterTypeName(k); got != v {
			t.Errorf("parameterTypeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_ErrorCauseTable(t *testing.T) {
	cases := map[int]string{
		1:  "Invalid Stream Identifier",
		3:  "Stale Cookie Error",
		6:  "Unrecognized Chunk Type",
		12: "User Initiated Abort",
		13: "Protocol Violation",
	}
	for k, v := range cases {
		if got := errorCauseName(k); got != v {
			t.Errorf("errorCauseName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":   "",
		"odd hex": "04D2 162E DEAD",
		"short":   "04D2 162E DEADBEEF",
		"bad hex": "ZZD2 162E DEADBEEF 12345678",
	}
	for name, in := range cases {
		_, err := Decode(in)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
