package pcp

import (
	"strings"
	"testing"
)

func TestDecode_AnnounceResponse(t *testing.T) {
	// ANNOUNCE response from server (R=1, Opcode=0).
	// Result=SUCCESS, Lifetime=0, Epoch=12345.
	in := "02 80 00 00 00000000 00003039 000000000000000000000000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 2 {
		t.Errorf("version: %d", r.Version)
	}
	if !r.IsResponse {
		t.Errorf("expected response")
	}
	if r.OpcodeName != "ANNOUNCE" {
		t.Errorf("opcode: %q", r.OpcodeName)
	}
	if r.ResponseHeader == nil {
		t.Fatal("response header nil")
	}
	if r.ResponseHeader.ResultCodeName != "SUCCESS" {
		t.Errorf("result: %q", r.ResponseHeader.ResultCodeName)
	}
	if r.ResponseHeader.EpochTime != 12345 {
		t.Errorf("epoch: %d", r.ResponseHeader.EpochTime)
	}
}

func TestDecode_MapRequest(t *testing.T) {
	// MAP request (R=0, Opcode=1).
	// Lifetime=3600s, Client IP=IPv4-mapped 192.168.1.100.
	// MAP body: Nonce=DEADBEEF..., Protocol=6 TCP, Internal=80,
	// Suggested External=8080, External IP=0.0.0.0 (any).
	in := "02 01 0000 00000E10" +
		"00000000000000000000FFFFC0A80164" + // IPv4-mapped 192.168.1.100
		"DEADBEEFCAFEBABE12345678" + // Mapping Nonce (12 bytes)
		"06 000000" + // Protocol=TCP + Reserved
		"0050 1F90" + // Internal=80, Suggested External=8080
		"00000000000000000000FFFF00000000" // External IP IPv4-mapped 0.0.0.0
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.IsResponse {
		t.Errorf("expected request")
	}
	if r.OpcodeName != "MAP" {
		t.Errorf("opcode: %q", r.OpcodeName)
	}
	if r.RequestHeader.RequestedLifetimeSec != 3600 {
		t.Errorf("lifetime: %d", r.RequestHeader.RequestedLifetimeSec)
	}
	if r.RequestHeader.ClientIPAddress != "192.168.1.100" {
		t.Errorf("client IP: %q", r.RequestHeader.ClientIPAddress)
	}
	mb := r.MapBody
	if mb == nil {
		t.Fatal("MAP body nil")
	}
	if mb.Protocol != 6 || mb.ProtocolName != "TCP" {
		t.Errorf("protocol: %d %q", mb.Protocol, mb.ProtocolName)
	}
	if mb.InternalPort != 80 || mb.SuggestedExternalPort != 8080 {
		t.Errorf("ports: int=%d ext=%d", mb.InternalPort, mb.SuggestedExternalPort)
	}
	if mb.SuggestedExternalAddress != "0.0.0.0" {
		t.Errorf("ext addr: %q", mb.SuggestedExternalAddress)
	}
}

func TestDecode_MapResponse_Success(t *testing.T) {
	// MAP response (R=1, Opcode=1), Result=SUCCESS,
	// Lifetime=3600, External IP=203.0.113.5, port=12345.
	in := "02 81 00 00 00000E10 00003039 000000000000000000000000" +
		"DEADBEEFCAFEBABE12345678" +
		"06 000000" +
		"0050 3039" +
		"00000000000000000000FFFFCB007105"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.IsResponse {
		t.Errorf("expected response")
	}
	if r.MapBody == nil {
		t.Fatal("MAP body nil")
	}
	if r.MapBody.SuggestedExternalAddress != "203.0.113.5" {
		t.Errorf("ext addr: %q", r.MapBody.SuggestedExternalAddress)
	}
	if r.MapBody.SuggestedExternalPort != 12345 {
		t.Errorf("ext port: %d", r.MapBody.SuggestedExternalPort)
	}
}

func TestDecode_PeerRequest(t *testing.T) {
	// PEER request (R=0, Opcode=2).
	in := "02 02 0000 00000E10" +
		"00000000000000000000FFFFC0A80164" + // Client 192.168.1.100
		"DEADBEEFCAFEBABE12345678" + // Nonce
		"06 000000" + // TCP
		"0050 1F90" + // Internal 80, Suggested External 8080
		"00000000000000000000FFFF00000000" + // External IP any
		"01BB 0000" + // Remote Peer Port 443
		"00000000000000000000FFFF08080808" // Remote Peer 8.8.8.8
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.OpcodeName != "PEER" {
		t.Errorf("opcode: %q", r.OpcodeName)
	}
	pb := r.PeerBody
	if pb == nil {
		t.Fatal("PEER body nil")
	}
	if pb.RemotePeerPort != 443 {
		t.Errorf("remote port: %d", pb.RemotePeerPort)
	}
	if pb.RemotePeerAddress != "8.8.8.8" {
		t.Errorf("remote addr: %q", pb.RemotePeerAddress)
	}
}

func TestDecode_ErrorResultCode(t *testing.T) {
	// MAP response with Result=USER_EX_QUOTA (10).
	in := "02 81 00 0A 00000000 00003039 000000000000000000000000" +
		"DEADBEEFCAFEBABE12345678" +
		"06 000000" +
		"0050 0050" +
		"00000000000000000000FFFF00000000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.ResponseHeader.ResultCodeName != "USER_EX_QUOTA" {
		t.Errorf("result: %q", r.ResponseHeader.ResultCodeName)
	}
}

func TestDecode_MapWithIPv6ClientAndOptions(t *testing.T) {
	// MAP request from IPv6 client fe80::1 with one
	// PREFER_FAILURE option (no payload — 4-byte header
	// alone, length=0).
	in := "02 01 0000 00000E10" +
		"FE800000 00000000 00000000 00000001" + // Client fe80::1
		"DEADBEEFCAFEBABE12345678" +
		"06 000000" +
		"0050 1F90" +
		"00000000000000000000FFFFCB007105" +
		"02 00 0000" // Option PREFER_FAILURE, mandatory=0, length=0
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.RequestHeader.ClientIPAddress != "fe80::1" {
		t.Errorf("client IP: %q", r.RequestHeader.ClientIPAddress)
	}
	if len(r.Options) != 1 {
		t.Fatalf("options: %d", len(r.Options))
	}
	if r.Options[0].CodeName != "PREFER_FAILURE" {
		t.Errorf("option: %q", r.Options[0].CodeName)
	}
}

func TestDecode_OpcodeTable(t *testing.T) {
	cases := map[int]string{
		0: "ANNOUNCE",
		1: "MAP",
		2: "PEER",
	}
	for k, v := range cases {
		if got := opcodeName(k); got != v {
			t.Errorf("opcodeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_ResultCodeTable(t *testing.T) {
	cases := map[int]string{
		0:  "SUCCESS",
		1:  "UNSUPP_VERSION",
		2:  "NOT_AUTHORIZED",
		3:  "MALFORMED_REQUEST",
		4:  "UNSUPP_OPCODE",
		5:  "UNSUPP_OPTION",
		6:  "MALFORMED_OPTION",
		7:  "NETWORK_FAILURE",
		8:  "NO_RESOURCES",
		9:  "UNSUPP_PROTOCOL",
		10: "USER_EX_QUOTA",
		11: "CANNOT_PROVIDE_EXTERNAL",
		12: "ADDRESS_MISMATCH",
		13: "EXCESSIVE_REMOTE_PEERS",
	}
	for k, v := range cases {
		if got := resultCodeName(k); got != v {
			t.Errorf("resultCodeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_OptionCodeTable(t *testing.T) {
	cases := map[int]string{
		1: "THIRD_PARTY",
		2: "PREFER_FAILURE",
		3: "FILTER",
		4: "NAT64_PREFIX",
		5: "PORT_SET",
	}
	for k, v := range cases {
		if got := optionCodeName(k); got != v {
			t.Errorf("optionCodeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_ProtocolNameTable(t *testing.T) {
	cases := map[int]string{
		0:   "ALL protocols",
		1:   "ICMP",
		6:   "TCP",
		17:  "UDP",
		50:  "ESP",
		51:  "AH",
		58:  "ICMPv6",
		132: "SCTP",
	}
	for k, v := range cases {
		if got := protocolName(k); got != v {
			t.Errorf("protocolName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_VersionNot2_Note(t *testing.T) {
	// Version 1 (NAT-PMP-era).
	in := "01 01 0000 00000E10" +
		"00000000000000000000FFFFC0A80164" +
		strings.Repeat("00", 36)
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "PCP / RFC 6887 version 2") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected version note: %v", r.Notes)
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":   "",
		"odd hex": "02 01 000",
		"short":   "02 01 0000",
		"bad hex": "ZZ 01 0000 00000E10" + strings.Repeat("00", 32),
	}
	for name, in := range cases {
		_, err := Decode(in)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
