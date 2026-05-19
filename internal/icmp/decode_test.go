package icmp

import (
	"strings"
	"testing"
)

func TestDecode_V4EchoRequest(t *testing.T) {
	// Type 8 Echo Request, code 0, checksum 0xABCD,
	// id 0x1234, seq 0x0001, data "hi" (0x68 0x69).
	in := "08 00 ABCD 1234 0001 6869"
	r, err := Decode(in, "")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != "v4" {
		t.Errorf("version: %q", r.Version)
	}
	if r.Type != 8 || r.TypeName != "Echo Request" {
		t.Errorf("type: %d %q", r.Type, r.TypeName)
	}
	if r.ChecksumHex != "ABCD" {
		t.Errorf("checksum: %q", r.ChecksumHex)
	}
	if r.Echo == nil {
		t.Fatal("Echo body nil")
	}
	if r.Echo.Identifier != 0x1234 || r.Echo.Sequence != 1 {
		t.Errorf("id/seq: %x / %d", r.Echo.Identifier, r.Echo.Sequence)
	}
	if r.Echo.DataHex != "6869" {
		t.Errorf("data: %q", r.Echo.DataHex)
	}
}

func TestDecode_V4DestinationUnreachable_PortUnreachable(t *testing.T) {
	// Type 3 Code 3 (Port Unreachable). Unused 4 bytes + embedded
	// IP+8-bytes-payload (just a placeholder 16 bytes here).
	in := "03 03 0000 00000000 " + strings.Repeat("AA", 16)
	r, err := Decode(in, "")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.TypeName != "Destination Unreachable" {
		t.Errorf("type: %q", r.TypeName)
	}
	if r.CodeName != "Port Unreachable" {
		t.Errorf("code: %q", r.CodeName)
	}
	if r.DestUnreachable == nil {
		t.Fatal("DestUnreachable body nil")
	}
	if r.DestUnreachable.UnusedHex != "00000000" {
		t.Errorf("unused: %q", r.DestUnreachable.UnusedHex)
	}
}

func TestDecode_V4TimeExceeded_TTL(t *testing.T) {
	// Type 11 Code 0 (TTL Expired in Transit).
	in := "0B 00 0000 00000000 " + strings.Repeat("BB", 8)
	r, err := Decode(in, "")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.TypeName != "Time Exceeded" {
		t.Errorf("type: %q", r.TypeName)
	}
	if r.CodeName != "TTL Expired in Transit" {
		t.Errorf("code: %q", r.CodeName)
	}
	if r.TimeExceeded == nil {
		t.Fatal("TimeExceeded body nil")
	}
}

func TestDecode_V4Redirect(t *testing.T) {
	// Type 5 Code 1 (Redirect for Host). Gateway 192.168.1.1.
	in := "05 01 0000 C0A80101 " + strings.Repeat("00", 12)
	r, err := Decode(in, "")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Redirect == nil {
		t.Fatal("Redirect nil")
	}
	if r.Redirect.GatewayIP != "192.168.1.1" {
		t.Errorf("gateway: %q", r.Redirect.GatewayIP)
	}
	if r.CodeName != "Redirect for Host" {
		t.Errorf("code: %q", r.CodeName)
	}
}

func TestDecode_V6EchoRequest(t *testing.T) {
	// Type 128 ICMPv6 Echo Request, id 0xCAFE, seq 0x0042,
	// data "test".
	in := "80 00 1234 CAFE 0042 74657374"
	r, err := Decode(in, "")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != "v6" {
		t.Errorf("version: %q", r.Version)
	}
	if r.TypeName != "Echo Request" {
		t.Errorf("type: %q", r.TypeName)
	}
	if r.Echo == nil {
		t.Fatal("Echo nil")
	}
	if r.Echo.Identifier != 0xCAFE {
		t.Errorf("id: %x", r.Echo.Identifier)
	}
	if r.Echo.Sequence != 0x42 {
		t.Errorf("seq: %x", r.Echo.Sequence)
	}
}

func TestDecode_V6PacketTooBig(t *testing.T) {
	// Type 2 ICMPv6 Packet Too Big, MTU 1500.
	// Type 2 is ambiguous (v4 Source Quench vs v6 Packet Too
	// Big); pass the v6 hint explicitly.
	in := "02 00 0000 000005DC " + strings.Repeat("00", 40)
	r, err := Decode(in, "v6")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.TypeName != "Packet Too Big" {
		t.Errorf("type: %q", r.TypeName)
	}
	if r.PacketTooBig == nil {
		t.Fatal("PacketTooBig nil")
	}
	if r.PacketTooBig.MTU != 1500 {
		t.Errorf("MTU: %d", r.PacketTooBig.MTU)
	}
}

func TestDecode_V6NeighborSolicitation_WithSourceLLAddr(t *testing.T) {
	// Type 135 NS:
	// 87 00 chk 00000000 (reserved) + 16 byte target (fe80::1)
	// + 1 NDP option type 1 (Source Link-Layer Address) length 1 (8 bytes)
	// + 6 byte MAC (aa bb cc dd ee ff)
	target := "FE80000000000000000000000000 0001"
	opt := "01 01 AABBCCDDEEFF" // type=1, len_w8=1 → 8 bytes total, 6 byte body
	in := "87 00 0000 00000000 " + target + opt
	r, err := Decode(in, "")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.TypeName != "Neighbor Solicitation (NDP)" {
		t.Errorf("type: %q", r.TypeName)
	}
	if r.NeighborSolicit == nil {
		t.Fatal("NeighborSolicit nil")
	}
	if r.NeighborSolicit.TargetAddress != "fe80::1" {
		t.Errorf("target: %q", r.NeighborSolicit.TargetAddress)
	}
	if len(r.NeighborSolicit.Options) != 1 {
		t.Fatalf("expected 1 option, got %d", len(r.NeighborSolicit.Options))
	}
	o := r.NeighborSolicit.Options[0]
	if o.TypeName != "Source Link-Layer Address" {
		t.Errorf("option type name: %q", o.TypeName)
	}
	if o.BodyHex != "AABBCCDDEEFF" {
		t.Errorf("option body: %q", o.BodyHex)
	}
}

func TestDecode_V6NeighborAdvertisement_Flags(t *testing.T) {
	// Type 136 NA with R+S+O flags (0xE0) and target fe80::2.
	target := "FE80000000000000000000000000 0002"
	in := "88 00 0000 E0000000 " + target
	r, err := Decode(in, "")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.NeighborAdvertise == nil {
		t.Fatal("NeighborAdvertise nil")
	}
	got := r.NeighborAdvertise.Flags
	for _, want := range []string{"R", "S", "O"} {
		if !strings.Contains(got, want) {
			t.Errorf("flags missing %q: %q", want, got)
		}
	}
}

func TestDecode_V6RouterAdvertisement(t *testing.T) {
	// Type 134 RA:
	// CurHopLimit=64, Flags=0xC0 (M+O), RouterLifetime=0x0708 (1800s),
	// ReachableTime=0x00007530 (30000ms), RetransTimer=0x000003E8 (1000ms).
	in := "86 00 0000 40 C0 0708 00007530 000003E8"
	r, err := Decode(in, "")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.RouterAdvertise == nil {
		t.Fatal("RouterAdvertise nil")
	}
	ra := r.RouterAdvertise
	if ra.CurHopLimit != 64 {
		t.Errorf("cur_hop_limit: %d", ra.CurHopLimit)
	}
	if ra.RouterLifetime != 1800 {
		t.Errorf("router_lifetime: %d", ra.RouterLifetime)
	}
	if ra.ReachableTime != 30000 {
		t.Errorf("reachable_time: %d", ra.ReachableTime)
	}
	if !strings.Contains(ra.Flags, "M") || !strings.Contains(ra.Flags, "O") {
		t.Errorf("flags: %q", ra.Flags)
	}
}

func TestDecode_VersionHintHonoured(t *testing.T) {
	// Type 1 with v6 hint becomes ICMPv6 Destination Unreachable;
	// without the hint defaults to v4.
	in := "01 00 0000 00000000"
	r6, err := Decode(in, "v6")
	if err != nil {
		t.Fatalf("Decode v6: %v", err)
	}
	if r6.TypeName != "Destination Unreachable" || r6.Version != "v6" {
		t.Errorf("v6 hint: %s %s", r6.Version, r6.TypeName)
	}

	r4, err := Decode(in, "v4")
	if err != nil {
		t.Fatalf("Decode v4: %v", err)
	}
	if r4.Version != "v4" {
		t.Errorf("v4 hint: %s", r4.Version)
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":     "",
		"odd hex":   "08000",
		"bad hex":   "ZZ00",
		"too short": "0800",
	}
	for name, in := range cases {
		_, err := Decode(in, "")
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
