package ndp

import (
	"strings"
	"testing"
)

// TestDecodeRouterAdvertisementWithPrefixAndRDNSS pins a
// canonical RA carrying a SLAAC prefix + RDNSS option —
// the mitm6 / fake_router6 attack surface.
func TestDecodeRouterAdvertisementWithPrefixAndRDNSS(t *testing.T) {
	// ICMPv6 header: Type 134 RA + Code 0 + Checksum 0x1234.
	// RA fixed fields (12 bytes):
	//   CurHopLimit = 64
	//   Flags = 0xC0 (M + O)
	//   RouterLifetime = 1800 (0x0708)
	//   ReachableTime = 0
	//   RetransTimer = 0
	// Options:
	//   Source LLA (Type 1, length 1 → 8 bytes total):
	//     01 01 + 6-byte MAC 00 11 22 33 44 55
	//   Prefix Information (Type 3, length 4 → 32 bytes):
	//     03 04 + body 30 bytes
	//     prefixLen=64, flags=0xC0 (L+A), valid=0xFFFFFFFF,
	//     pref=0xFFFFFFFF, reserved=0, prefix=2001:db8::
	//   RDNSS (Type 25, length 3 → 24 bytes): 19 03 + body 22 bytes
	//     reserved=0x0000, lifetime=3600, 1 DNS IPv6 = 2001:db8::1
	in := "86 00 1234 " +
		"40 C0 0708 00000000 00000000 " + // RA fixed
		"01 01 001122334455 " + // Source LLA
		"03 04 40 C0 FFFFFFFF FFFFFFFF 00000000 20010DB8000000000000000000000000 " +
		"19 03 0000 00000E10 20010DB8000000000000000000000001"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.TypeName != "Router_Advertisement" {
		t.Errorf("type: got %q want Router_Advertisement", r.TypeName)
	}
	if r.CurHopLimit != 64 {
		t.Errorf("curHopLimit: got %d want 64", r.CurHopLimit)
	}
	if !r.RAManaged || !r.RAOther {
		t.Errorf("RA flags: M=%v O=%v want true/true", r.RAManaged, r.RAOther)
	}
	if r.RouterLifetimeS != 1800 {
		t.Errorf("routerLifetime: got %d want 1800", r.RouterLifetimeS)
	}
	if len(r.Options) != 3 {
		t.Fatalf("options: got %d want 3", len(r.Options))
	}
	if r.Options[0].TypeName != "Source_Link_Layer_Address" ||
		r.Options[0].LinkLayerAddress != "00:11:22:33:44:55" {
		t.Errorf("SLLA: got %+v", r.Options[0])
	}
	if r.Options[1].TypeName != "Prefix_Information" {
		t.Errorf("opt[1] type: got %q", r.Options[1].TypeName)
	}
	if r.Options[1].PrefixLength != 64 {
		t.Errorf("prefixLen: got %d want 64", r.Options[1].PrefixLength)
	}
	if !r.Options[1].PrefixOnLink || !r.Options[1].PrefixAutoconfig {
		t.Errorf("prefix L/A flags: L=%v A=%v", r.Options[1].PrefixOnLink,
			r.Options[1].PrefixAutoconfig)
	}
	if !strings.HasPrefix(r.Options[1].Prefix, "2001:db8") {
		t.Errorf("prefix: got %q", r.Options[1].Prefix)
	}
	if r.Options[2].TypeName != "RDNSS" {
		t.Errorf("opt[2] type: got %q", r.Options[2].TypeName)
	}
	if r.Options[2].LifetimeS != 3600 {
		t.Errorf("rdnss lifetime: got %d want 3600", r.Options[2].LifetimeS)
	}
	if len(r.Options[2].DNSServers) != 1 ||
		!strings.HasSuffix(r.Options[2].DNSServers[0], ":1") {
		t.Errorf("rdnss servers: got %v", r.Options[2].DNSServers)
	}
}

// TestDecodeNeighborSolicitation pins an NS — the IPv6
// equivalent of ARP.
func TestDecodeNeighborSolicitation(t *testing.T) {
	// Type 135 NS, target = 2001:db8::ab; Source LLA option.
	in := "87 00 ABCD 00000000 " +
		"20010DB80000000000000000000000AB " + // 16 bytes target
		"01 01 AABBCCDDEEFF"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.TypeName != "Neighbor_Solicitation" {
		t.Errorf("type: got %q", r.TypeName)
	}
	if !strings.HasSuffix(r.TargetAddress, ":ab") {
		t.Errorf("targetAddress: got %q", r.TargetAddress)
	}
	if len(r.Options) != 1 ||
		r.Options[0].LinkLayerAddress != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("SLLA: got %+v", r.Options)
	}
}

// TestDecodeNeighborAdvertisement pins an NA with R/S/O flags.
func TestDecodeNeighborAdvertisement(t *testing.T) {
	// Type 136 NA, Flags = 0xE0 (R + S + O).
	in := "88 00 1234 " +
		"E0 000000 " +
		"20010DB80000000000000000000000AB " +
		"02 01 112233445566"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.TypeName != "Neighbor_Advertisement" {
		t.Errorf("type: got %q", r.TypeName)
	}
	if !r.NARouter || !r.NASolicited || !r.NAOverride {
		t.Errorf("NA flags: R=%v S=%v O=%v want all true",
			r.NARouter, r.NASolicited, r.NAOverride)
	}
	if r.Options[0].TypeName != "Target_Link_Layer_Address" {
		t.Errorf("TLLA opt: got %q", r.Options[0].TypeName)
	}
}

// TestDecodeRouterSolicitation pins an RS — the cold-boot "any
// routers?" query.
func TestDecodeRouterSolicitation(t *testing.T) {
	// Type 133 RS, then Source LLA option.
	in := "85 00 5678 00000000 01 01 001122334455"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.TypeName != "Router_Solicitation" {
		t.Errorf("type: got %q want Router_Solicitation", r.TypeName)
	}
	if len(r.Options) != 1 ||
		r.Options[0].LinkLayerAddress != "00:11:22:33:44:55" {
		t.Errorf("SLLA: got %+v", r.Options)
	}
}

// TestDecodeRedirect pins a Redirect message.
func TestDecodeRedirect(t *testing.T) {
	// Type 137, target = 2001:db8::aa, destination =
	// 2001:db8::bb.
	in := "89 00 1111 00000000 " +
		"20010DB80000000000000000000000AA " +
		"20010DB80000000000000000000000BB"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.TypeName != "Redirect" {
		t.Errorf("type: got %q", r.TypeName)
	}
	if !strings.HasSuffix(r.TargetAddress, ":aa") {
		t.Errorf("targetAddress: got %q", r.TargetAddress)
	}
	if !strings.HasSuffix(r.DestinationAddress, ":bb") {
		t.Errorf("destAddress: got %q", r.DestinationAddress)
	}
}

// TestDecodeMTUOption pins the MTU option decode.
func TestDecodeMTUOption(t *testing.T) {
	// RS with MTU option (Type 5, length 1, MTU 1500 = 0x05DC).
	in := "85 00 0000 00000000 05 01 0000 000005DC"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(r.Options) != 1 || r.Options[0].MTU != 1500 {
		t.Errorf("MTU: got %+v want 1500", r.Options)
	}
}

// TestDecodeDNSSL pins the DNS Search List option.
func TestDecodeDNSSL(t *testing.T) {
	// DNSSL: Type 31, length 3 → 24 bytes total.
	// reserved + lifetime + search domain "corp.lan" (encoded
	// as length-prefixed labels: 04 "corp" 03 "lan" 00).
	// Domain encoding = 1+4+1+3+1 = 10 bytes. Total option =
	// 2 (hdr) + 2 (reserved) + 4 (lifetime) + 10 (domain) = 18.
	// Pad to 24 = round up to next 8-byte boundary (24-18 = 6
	// trailing zeros).
	in := "85 00 0000 00000000 " +
		"1F 03 0000 00000E10 " + // hdr + reserved + lifetime 3600
		"04 63 6F 72 70 03 6C 61 6E 00 " + // "corp" "lan"
		"00 00 00 00 00 00" // padding
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(r.Options) != 1 || r.Options[0].TypeName != "DNSSL" {
		t.Fatalf("DNSSL option missing: %+v", r.Options)
	}
	if len(r.Options[0].SearchDomains) == 0 ||
		r.Options[0].SearchDomains[0] != "corp.lan" {
		t.Errorf("search domains: got %v want [corp.lan]",
			r.Options[0].SearchDomains)
	}
}

// TestTypeNameTable covers each catalogued NDP type.
func TestTypeNameTable(t *testing.T) {
	cases := map[int]string{
		133: "Router_Solicitation",
		134: "Router_Advertisement",
		135: "Neighbor_Solicitation",
		136: "Neighbor_Advertisement",
		137: "Redirect",
	}
	for k, v := range cases {
		if got := typeName(k); got != v {
			t.Errorf("typeName(%d) = %q want %q", k, got, v)
		}
	}
	if !strings.HasPrefix(typeName(128), "non-NDP") {
		t.Errorf("typeName(128) should mark non-NDP")
	}
}

// TestOptionTypeNameTable covers each catalogued option type.
func TestOptionTypeNameTable(t *testing.T) {
	cases := map[int]string{
		1:  "Source_Link_Layer_Address",
		2:  "Target_Link_Layer_Address",
		3:  "Prefix_Information",
		4:  "Redirected_Header",
		5:  "MTU",
		13: "Nonce",
		24: "Route_Information",
		25: "RDNSS",
		31: "DNSSL",
	}
	for k, v := range cases {
		if got := optionTypeName(k); got != v {
			t.Errorf("optionTypeName(%d) = %q want %q", k, got, v)
		}
	}
}

// TestRAPreferenceNameTable covers the 4 documented values.
func TestRAPreferenceNameTable(t *testing.T) {
	cases := map[int]string{
		0: "Medium", 1: "High", 2: "Reserved", 3: "Low",
	}
	for k, v := range cases {
		if got := raPreferenceName(k); got != v {
			t.Errorf("raPreferenceName(%d) = %q want %q", k, got, v)
		}
	}
}

func TestDecodeRejectsEmpty(t *testing.T) {
	if _, err := Decode(""); err == nil {
		t.Fatal("want error for empty input")
	}
}

func TestDecodeRejectsOddNibbles(t *testing.T) {
	if _, err := Decode("ABC"); err == nil {
		t.Fatal("want error for odd-length input")
	}
}

func TestDecodeRejectsShortHeader(t *testing.T) {
	if _, err := Decode("85 00"); err == nil {
		t.Fatal("want error for short header")
	}
}

func TestDecodeRejectsBadHex(t *testing.T) {
	if _, err := Decode("ZZZZ"); err == nil {
		t.Fatal("want error for non-hex chars")
	}
}
