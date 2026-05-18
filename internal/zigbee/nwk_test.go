package zigbee

import (
	"strings"
	"testing"
)

// TestDecode_DataFrameMinimal pins the minimum Data frame:
//
//	FC = 0x0008 (Frame Type=Data=0, Protocol Version=2)
//	  → bits 0..1 = 00, bits 2..5 = 0010 → byte 0 = 0x08
//	  → wire LE 08 00
//	DstAddr 0x0000 (coordinator) → wire 00 00
//	SrcAddr 0x1234 → wire 34 12
//	Radius = 30, SeqNum = 1
//	Payload (no extra headers): AA BB CC
func TestDecode_DataFrameMinimal(t *testing.T) {
	got, err := Decode("08 00 00 00 34 12 1E 01 AA BB CC")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.FrameControl.FrameTypeName != "Data" {
		t.Errorf("FrameTypeName = %q; want 'Data'", got.FrameControl.FrameTypeName)
	}
	if got.FrameControl.ProtocolVersion != 2 {
		t.Errorf("ProtocolVersion = %d; want 2", got.FrameControl.ProtocolVersion)
	}
	if got.DestinationAddress != "0000" {
		t.Errorf("DestinationAddress = %q; want '0000'", got.DestinationAddress)
	}
	if got.SourceAddress != "1234" {
		t.Errorf("SourceAddress = %q; want '1234'", got.SourceAddress)
	}
	if got.Radius != 30 {
		t.Errorf("Radius = %d; want 30", got.Radius)
	}
	if got.SequenceNumber != 1 {
		t.Errorf("SequenceNumber = %d; want 1", got.SequenceNumber)
	}
	if got.PayloadHex != "AABBCC" {
		t.Errorf("PayloadHex = %q; want 'AABBCC'", got.PayloadHex)
	}
}

// TestDecode_BroadcastClass pins the well-known broadcast
// destination address classification.
//
// FC = 0x0008 (Data, ProtoVer 2), Dst = 0xFFFD (all non-sleepy)
func TestDecode_BroadcastClass(t *testing.T) {
	got, err := Decode("08 00 FD FF 34 12 1E 01")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.DestinationAddress != "FFFD" {
		t.Errorf("DestinationAddress = %q", got.DestinationAddress)
	}
	if got.BroadcastClass != "All non-sleepy nodes" {
		t.Errorf("BroadcastClass = %q", got.BroadcastClass)
	}
}

// TestDecode_DestinationIEEE — the 0x0800 flag pulls in 8 bytes
// of destination IEEE address after the standard header.
func TestDecode_DestinationIEEE(t *testing.T) {
	// FC bits: Data (00), ProtoVer 2 (0010 → bits 2..5), Dst IEEE
	// flag = 1 (bit 11 = 0x0800). Combined: 0x0808. Wire LE: 08 08.
	hex := "08 08 00 00 34 12 1E 01 " +
		"08 07 06 05 04 03 02 01 " + // Dst IEEE wire LE (→ BE "0102030405060708")
		"AA BB" // Payload
	got, err := Decode(hex)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.FrameControl.DestinationIEEE {
		t.Error("DestinationIEEE flag should be true")
	}
	if got.DestinationIEEEHex != "0102030405060708" {
		t.Errorf("DestinationIEEEHex = %q; want '0102030405060708' (LE→BE)",
			got.DestinationIEEEHex)
	}
	if got.PayloadHex != "AABB" {
		t.Errorf("PayloadHex = %q", got.PayloadHex)
	}
}

// TestDecode_MulticastControl exercises the multicast flag +
// control byte decode.
//
// FC bits: Data (00), ProtoVer 2 (0010), Multicast = 1 (bit 8 =
// 0x0100). Combined: 0x0108. Wire LE: 08 01.
// Multicast control byte 0x39 = bits 0-1 (mode=1 Member),
//
//	bits 2-4 (Non-Member Radius=6), bits 5-7 (Max Non-Member=1)
//
// 0x39 = 0011_1001 → mode=01=Member, NMR=01 0=2? wait let me
// reconsider: 0x39 = 0011 1001. mode = bits 0-1 = 01 = 1 (Member),
// NonMemberRadius bits 2-4 = (0x39 >> 2) & 0x07 = 0xE & 0x07 = 6,
// MaxNonMemberRadius bits 5-7 = (0x39 >> 5) & 0x07 = 1.
func TestDecode_MulticastControl(t *testing.T) {
	got, err := Decode("08 01 00 00 34 12 1E 01 39 AA")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.FrameControl.Multicast {
		t.Error("Multicast flag should be true")
	}
	if got.MulticastControl == nil {
		t.Fatal("MulticastControl missing")
	}
	mc := got.MulticastControl
	if mc.Mode != 1 {
		t.Errorf("Mode = %d; want 1 (Member)", mc.Mode)
	}
	if mc.ModeName != "Member" {
		t.Errorf("ModeName = %q", mc.ModeName)
	}
	if mc.NonMemberRadius != 6 {
		t.Errorf("NonMemberRadius = %d; want 6", mc.NonMemberRadius)
	}
	if mc.MaxNonMemberRadius != 1 {
		t.Errorf("MaxNonMemberRadius = %d; want 1", mc.MaxNonMemberRadius)
	}
}

// TestDecode_SecurityHeader exercises the security flag —
// surfaces the aux security header as hex without dissecting.
func TestDecode_SecurityHeader(t *testing.T) {
	// FC: Data + ProtoVer 2 + Security (bit 9 = 0x0200). Combined: 0x0208.
	// Wire LE: 08 02.
	// Standard header (8 bytes), then aux security header.
	// SecCtrl byte 0x28 = bits 0-2 sec level=0, bits 3-4 keyID=01 (network key),
	// bit 5 extended nonce = 1 (so +8 bytes source IEEE), so header length =
	// 1 (SecCtrl) + 4 (Frame Counter) + 8 (Source IEEE) + 1 (Key Seq Num) = 14
	hex := "08 02 00 00 34 12 1E 01 " +
		"28 01 02 03 04 " + // SecCtrl + Frame Counter
		"08 07 06 05 04 03 02 01 " + // Source IEEE (wire LE)
		"00 " + // Key Sequence Number
		"AA BB CC" // Payload
	got, err := Decode(hex)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.FrameControl.Security {
		t.Error("Security flag should be true")
	}
	if got.AuxSecurityHeaderHex == "" {
		t.Error("AuxSecurityHeaderHex should be populated")
	}
	if got.PayloadHex != "AABBCC" {
		t.Errorf("PayloadHex = %q; want 'AABBCC'", got.PayloadHex)
	}
}

// TestDecode_NWKCommand pins the NWK Command frame type.
//
// FC bits: NWK Command = 01, ProtoVer 2 (0010). Combined byte 0: 0x09.
// Wire LE: 09 00.
func TestDecode_NWKCommand(t *testing.T) {
	got, err := Decode("09 00 00 00 34 12 1E 01 01 02")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.FrameControl.FrameTypeName != "NWK Command" {
		t.Errorf("FrameTypeName = %q; want 'NWK Command'", got.FrameControl.FrameTypeName)
	}
}

// TestDecode_DiscoverRouteEnable exercises the discover-route
// nibble decoding. DiscoverRoute=Enable=1 (bits 6-7). FC byte 0
// = ProtoVer 2 (00 1000) + DiscoverRoute 1 << 6 = 0x48. Wire LE: 48 00.
func TestDecode_DiscoverRouteEnable(t *testing.T) {
	got, err := Decode("48 00 00 00 34 12 1E 01")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.FrameControl.DiscoverRouteName != "Enable" {
		t.Errorf("DiscoverRouteName = %q; want 'Enable'", got.FrameControl.DiscoverRouteName)
	}
}

// TestDecode_SourceRouteSubframe exercises the source-route
// flag + relay-count walking. Source Route flag = bit 10 = 0x0400.
// FC = 0x0408 → wire LE 08 04.
// Source route subframe: relay_count=2, relay_index=0,
//
//	relay1=0x1111 LE 11 11, relay2=0x2222 LE 22 22.
//
// Total SR length = 2 + 2*2 = 6 bytes.
func TestDecode_SourceRouteSubframe(t *testing.T) {
	hex := "08 04 00 00 34 12 1E 01 " +
		"02 00 11 11 22 22 " + // SR: relay_count=2, relay_index=0, two relays
		"AA BB" // Payload
	got, err := Decode(hex)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.FrameControl.SourceRoute {
		t.Error("SourceRoute flag should be true")
	}
	if got.SourceRouteHex != "020011112222" {
		t.Errorf("SourceRouteHex = %q; want '020011112222'", got.SourceRouteHex)
	}
	if got.PayloadHex != "AABB" {
		t.Errorf("PayloadHex = %q", got.PayloadHex)
	}
}

// TestDecode_TruncatedFrame — frame shorter than 8-byte minimum.
func TestDecode_TruncatedFrame(t *testing.T) {
	_, err := Decode("08 00 00 00")
	if err == nil {
		t.Fatal("want error for truncated NWK frame")
	}
}

// TestDecode_TruncatedDestIEEE — flag set but only partial IEEE
// bytes present.
func TestDecode_TruncatedDestIEEE(t *testing.T) {
	// FC with dest IEEE flag, no IEEE bytes following the header.
	_, err := Decode("08 08 00 00 34 12 1E 01")
	if err == nil {
		t.Fatal("want error for missing dest IEEE bytes")
	}
}

// TestDecode_BadInput — empty / invalid hex.
func TestDecode_BadInput(t *testing.T) {
	if _, err := Decode(""); err == nil {
		t.Error("empty input: want error")
	}
	if _, err := Decode("ZZ"); err == nil {
		t.Error("invalid hex: want error")
	}
}

// TestDecode_ToleratesSeparators — ':' / '-' / '_' / whitespace.
func TestDecode_ToleratesSeparators(t *testing.T) {
	base := "08 00 00 00 34 12 1E 01 AA BB CC"
	for _, sep := range []string{":", "-", "_", " "} {
		in := strings.ReplaceAll(base, " ", sep)
		got, err := Decode(in)
		if err != nil {
			t.Errorf("sep=%q: %v", sep, err)
			continue
		}
		if got.SourceAddress != "1234" {
			t.Errorf("sep=%q: SourceAddress = %q", sep, got.SourceAddress)
		}
	}
}

// TestNWKFrameTypeNames pins the frame-type-name table.
func TestNWKFrameTypeNames(t *testing.T) {
	cases := map[NWKFrameType]string{
		NWKFrameTypeData:     "Data",
		NWKFrameTypeCommand:  "NWK Command",
		NWKFrameTypeInterPAN: "Inter-PAN",
		NWKFrameTypeReserved: "Reserved",
	}
	for ft, want := range cases {
		if got := ft.String(); got != want {
			t.Errorf("NWKFrameType(%d).String() = %q; want %q", ft, got, want)
		}
	}
}

// TestSecurityHeaderLen spot-checks the per-KeyID + extended-nonce
// length calculations.
func TestSecurityHeaderLen(t *testing.T) {
	// SecCtrl 0x00 = no extended nonce, KeyID=0 (data key) → 1+4 = 5
	if got := securityHeaderLen(0x00); got != 5 {
		t.Errorf("KeyID=0, no ext nonce: %d; want 5", got)
	}
	// SecCtrl 0x08 = KeyID=1 (network key), no ext nonce → 1+4+1 = 6
	if got := securityHeaderLen(0x08); got != 6 {
		t.Errorf("KeyID=1, no ext nonce: %d; want 6", got)
	}
	// SecCtrl 0x20 = extended nonce, KeyID=0 → 1+4+8 = 13
	if got := securityHeaderLen(0x20); got != 13 {
		t.Errorf("KeyID=0, ext nonce: %d; want 13", got)
	}
	// SecCtrl 0x28 = extended nonce + KeyID=1 → 1+4+8+1 = 14
	if got := securityHeaderLen(0x28); got != 14 {
		t.Errorf("KeyID=1, ext nonce: %d; want 14", got)
	}
}

// TestBroadcastClassNames pins the well-known NWK broadcast
// addresses.
func TestBroadcastClassNames(t *testing.T) {
	cases := map[uint16]string{
		0xFFFF: "All nodes",
		0xFFFD: "All non-sleepy nodes",
		0xFFFC: "All routers + coordinator",
		0xFFFB: "Low-power routers",
		0x0001: "",
	}
	for addr, want := range cases {
		if got := broadcastClassName(addr); got != want {
			t.Errorf("broadcastClassName(0x%04X) = %q; want %q", addr, got, want)
		}
	}
}
