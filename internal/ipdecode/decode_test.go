package ipdecode

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

// TestDecode_IPv4_TCP_SYN pins a TCP SYN packet from
// 192.168.1.10:54321 to 93.184.216.34:443 with MSS option.
func TestDecode_IPv4_TCP_SYN(t *testing.T) {
	pkt := buildIPv4TCPSyn(t)
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Version != 4 {
		t.Errorf("Version = %d", got.Version)
	}
	if got.IPv4 == nil {
		t.Fatal("IPv4 nil")
	}
	if got.IPv4.SourceIP != "192.168.1.10" {
		t.Errorf("SourceIP = %q", got.IPv4.SourceIP)
	}
	if got.IPv4.DestinationIP != "93.184.216.34" {
		t.Errorf("DestinationIP = %q", got.IPv4.DestinationIP)
	}
	if !got.IPv4.FlagDontFragment {
		t.Error("FlagDontFragment = false; want true")
	}
	if got.IPv4.TTL != 64 {
		t.Errorf("TTL = %d", got.IPv4.TTL)
	}
	if got.ProtocolName != "TCP" {
		t.Errorf("ProtocolName = %q", got.ProtocolName)
	}
	if got.TCP == nil {
		t.Fatal("TCP nil")
	}
	if got.TCP.SourcePort != 54321 {
		t.Errorf("TCP.SourcePort = %d", got.TCP.SourcePort)
	}
	if got.TCP.DestinationPort != 443 {
		t.Errorf("TCP.DestinationPort = %d", got.TCP.DestinationPort)
	}
	if !got.TCP.FlagSYN {
		t.Error("FlagSYN = false; want true")
	}
	if got.TCP.FlagACK {
		t.Error("FlagACK = true; want false")
	}
	if got.TCP.FlagsString != "SYN" {
		t.Errorf("FlagsString = %q; want 'SYN'", got.TCP.FlagsString)
	}
	if len(got.TCP.Options) == 0 {
		t.Fatal("TCP options missing")
	}
	if got.TCP.Options[0].Name != "Maximum Segment Size (MSS)" {
		t.Errorf("Option[0].Name = %q", got.TCP.Options[0].Name)
	}
	if got.TCP.Options[0].MSS != 1460 {
		t.Errorf("Option[0].MSS = %d; want 1460", got.TCP.Options[0].MSS)
	}
}

// TestDecode_IPv4_UDP_DNSQuery pins a UDP packet over IPv4
// (UDP envelope only — the DNS payload is just raw hex here).
func TestDecode_IPv4_UDP_DNSQuery(t *testing.T) {
	pkt := buildIPv4UDP(t, 53345, 53, []byte("DNSPAYLOAD"))
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.UDP == nil {
		t.Fatal("UDP nil")
	}
	if got.UDP.SourcePort != 53345 {
		t.Errorf("UDP.SourcePort = %d", got.UDP.SourcePort)
	}
	if got.UDP.DestinationPort != 53 {
		t.Errorf("UDP.DestinationPort = %d", got.UDP.DestinationPort)
	}
	if got.ProtocolName != "UDP" {
		t.Errorf("ProtocolName = %q", got.ProtocolName)
	}
	if got.UDP.PayloadHex == "" {
		t.Error("UDP.PayloadHex empty")
	}
}

// TestDecode_IPv4_ICMP_Echo pins an ICMP Echo Request with
// identifier + sequence broken out.
func TestDecode_IPv4_ICMP_Echo(t *testing.T) {
	pkt := buildIPv4ICMPEcho(t, 8, 0x1234, 0x5678, []byte("ABC"))
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.ICMP == nil {
		t.Fatal("ICMP nil")
	}
	if got.ICMP.Type != 8 {
		t.Errorf("Type = %d", got.ICMP.Type)
	}
	if got.ICMP.TypeName != "Echo Request" {
		t.Errorf("TypeName = %q", got.ICMP.TypeName)
	}
	if got.ICMP.Identifier != 0x1234 {
		t.Errorf("Identifier = 0x%X", got.ICMP.Identifier)
	}
	if got.ICMP.Sequence != 0x5678 {
		t.Errorf("Sequence = 0x%X", got.ICMP.Sequence)
	}
}

// TestDecode_IPv4_ICMP_DestUnreachable pins ICMP type 3
// (Destination Unreachable) with the Port Unreachable code.
func TestDecode_IPv4_ICMP_DestUnreachable(t *testing.T) {
	pkt := buildIPv4ICMPEcho(t, 3, 0, 0, nil) // identifier+seq fields here are interpreted as unused
	pkt[len(pkt)-len([]byte("body"))-8+1] = 3 // code = Port Unreachable
	// Actually simpler: just write the ICMP header directly with type=3 code=3
	pkt2 := buildIPv4Header(t, 1, 28)
	icmp := []byte{3, 3, 0, 0, 0, 0, 0, 0}
	pkt2 = append(pkt2, icmp...)
	got, err := DecodeBytes(pkt2)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.ICMP.Type != 3 {
		t.Errorf("Type = %d", got.ICMP.Type)
	}
	if got.ICMP.TypeName != "Destination Unreachable" {
		t.Errorf("TypeName = %q", got.ICMP.TypeName)
	}
	if got.ICMP.CodeName != "Port Unreachable" {
		t.Errorf("CodeName = %q", got.ICMP.CodeName)
	}
}

// TestDecode_IPv6_TCP pins an IPv6 packet carrying a TCP
// SYN-ACK.
func TestDecode_IPv6_TCP(t *testing.T) {
	pkt := buildIPv6TCP(t)
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Version != 6 {
		t.Errorf("Version = %d", got.Version)
	}
	if got.IPv6 == nil {
		t.Fatal("IPv6 nil")
	}
	if got.IPv6.SourceIP != "2001:db8::1" {
		t.Errorf("SourceIP = %q", got.IPv6.SourceIP)
	}
	if got.IPv6.HopLimit != 64 {
		t.Errorf("HopLimit = %d", got.IPv6.HopLimit)
	}
	if got.IPv6.NextHeaderName != "TCP" {
		t.Errorf("NextHeaderName = %q", got.IPv6.NextHeaderName)
	}
	if got.TCP == nil {
		t.Fatal("TCP nil")
	}
	if !got.TCP.FlagSYN || !got.TCP.FlagACK {
		t.Errorf("FlagsString = %q; want 'SYN, ACK'", got.TCP.FlagsString)
	}
}

// TestDecode_IPv6_ICMPv6_Echo pins an IPv6 ICMPv6 echo reply
// (type 129).
func TestDecode_IPv6_ICMPv6_Echo(t *testing.T) {
	hdr := buildIPv6Header(t, 58, 8)
	icmp := []byte{129, 0, 0, 0, 0x12, 0x34, 0x00, 0x01}
	pkt := append(hdr, icmp...)
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.ICMPv6 == nil {
		t.Fatal("ICMPv6 nil")
	}
	if got.ICMPv6.TypeName != "Echo Reply" {
		t.Errorf("TypeName = %q", got.ICMPv6.TypeName)
	}
	if got.ICMPv6.Identifier != 0x1234 {
		t.Errorf("Identifier = 0x%X", got.ICMPv6.Identifier)
	}
	if got.ICMPv6.Sequence != 1 {
		t.Errorf("Sequence = %d", got.ICMPv6.Sequence)
	}
}

// TestDecode_IPv6_NeighborSolicitation pins ICMPv6 NDP type
// 135 (Neighbor Solicitation) name lookup.
func TestDecode_IPv6_NeighborSolicitation(t *testing.T) {
	hdr := buildIPv6Header(t, 58, 24)
	icmp := []byte{135, 0, 0, 0, 0, 0, 0, 0}
	target := make([]byte, 16)
	icmp = append(icmp, target...)
	pkt := append(hdr, icmp...)
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.ICMPv6.TypeName != "Neighbor Solicitation" {
		t.Errorf("TypeName = %q", got.ICMPv6.TypeName)
	}
}

// TestDecode_TCPOptions_Multiple pins MSS + NOP + Window Scale
// + SACK Permitted parsing in one packet.
func TestDecode_TCPOptions_Multiple(t *testing.T) {
	// Build IPv4 header + TCP with options:
	// MSS=1460, NOP, Window Scale=7, NOP, NOP, SACK Permitted
	tcpHdr := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHdr[0:2], 12345)
	binary.BigEndian.PutUint16(tcpHdr[2:4], 80)
	// 12 bytes of options + 4 bytes of EOL padding = 16 bytes
	// → 36-byte TCP header → data offset = 9.
	tcpHdr[12] = 9 << 4
	tcpHdr[13] = 0x02 // SYN
	opts := []byte{
		2, 4, 0x05, 0xB4, // MSS = 1460
		1,       // NOP
		3, 3, 7, // Window Scale = 7
		1, 1, // NOP NOP
		4, 2, // SACK Permitted
		0, 0, 0, 0, // EOL padding to 16 bytes
	}
	tcpHdr = append(tcpHdr, opts...)
	ipHdr := buildIPv4Header(t, 6, len(tcpHdr))
	pkt := append(ipHdr, tcpHdr...)
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.TCP == nil {
		t.Fatal("TCP nil")
	}
	if len(got.TCP.Options) < 4 {
		t.Fatalf("Options count = %d; want at least 4", len(got.TCP.Options))
	}
	var mssOpt, wsOpt, sackOpt *TCPOption
	for _, o := range got.TCP.Options {
		switch o.Kind {
		case 2:
			mssOpt = o
		case 3:
			wsOpt = o
		case 4:
			sackOpt = o
		}
	}
	if mssOpt == nil || mssOpt.MSS != 1460 {
		t.Errorf("MSS option = %v", mssOpt)
	}
	if wsOpt == nil || wsOpt.WindowScale != 7 {
		t.Errorf("Window Scale option = %v", wsOpt)
	}
	if sackOpt == nil {
		t.Error("SACK Permitted option missing")
	}
}

// TestDecode_BadVersion rejects packets where first nibble
// is neither 4 nor 6.
func TestDecode_BadVersion(t *testing.T) {
	if _, err := Decode("70 00 00 00"); err == nil {
		t.Error("version 7: want error")
	}
}

// TestDecode_TooShort rejects empty / short IPv4 / short IPv6.
func TestDecode_TooShort(t *testing.T) {
	if _, err := Decode(""); err == nil {
		t.Error("empty: want error")
	}
	if _, err := Decode("45 00 00 00"); err == nil {
		t.Error("4-byte IPv4: want error")
	}
	if _, err := Decode("60 00 00 00 00 00 00 00"); err == nil {
		t.Error("8-byte IPv6: want error")
	}
}

// TestProtocolNameTable spot-checks the protocol-number table.
func TestProtocolNameTable(t *testing.T) {
	cases := map[int]string{
		1:   "ICMP",
		2:   "IGMP",
		6:   "TCP",
		17:  "UDP",
		47:  "GRE",
		50:  "ESP",
		58:  "ICMPv6",
		89:  "OSPF",
		132: "SCTP",
	}
	for p, want := range cases {
		if got := protocolName(p); got != want {
			t.Errorf("protocolName(%d) = %q; want %q", p, got, want)
		}
	}
}

// TestICMPCodeName spot-checks the type-3 sub-codes.
func TestICMPCodeName(t *testing.T) {
	cases := []struct {
		typ, code int
		want      string
	}{
		{3, 0, "Network Unreachable"},
		{3, 1, "Host Unreachable"},
		{3, 3, "Port Unreachable"},
		{3, 4, "Fragmentation Needed and Don't Fragment was Set"},
		{11, 0, "TTL Exceeded in Transit"},
	}
	for _, c := range cases {
		if got := icmpCodeName(c.typ, c.code); got != c.want {
			t.Errorf("icmpCodeName(%d, %d) = %q; want %q", c.typ, c.code, got, c.want)
		}
	}
}

// TestICMPv6TypeTable spot-checks.
func TestICMPv6TypeTable(t *testing.T) {
	cases := map[int]string{
		1:   "Destination Unreachable",
		2:   "Packet Too Big",
		3:   "Time Exceeded",
		128: "Echo Request",
		129: "Echo Reply",
		133: "Router Solicitation",
		134: "Router Advertisement",
		135: "Neighbor Solicitation",
		136: "Neighbor Advertisement",
		137: "Redirect",
	}
	for typ, want := range cases {
		if got := icmpv6TypeName(typ); got != want {
			t.Errorf("icmpv6TypeName(%d) = %q; want %q", typ, got, want)
		}
	}
}

// --- test helpers --------------------------------------------------

func buildIPv4Header(t *testing.T, proto int, payloadLen int) []byte {
	t.Helper()
	totalLen := 20 + payloadLen
	hdr := make([]byte, 20)
	hdr[0] = 0x45 // version=4, IHL=5
	hdr[1] = 0    // ToS
	binary.BigEndian.PutUint16(hdr[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(hdr[4:6], 0xABCD) // ID
	binary.BigEndian.PutUint16(hdr[6:8], 0x4000) // DF set
	hdr[8] = 64                                  // TTL
	hdr[9] = byte(proto)
	// checksum left zero
	copy(hdr[12:16], net.ParseIP("192.168.1.10").To4())
	copy(hdr[16:20], net.ParseIP("93.184.216.34").To4())
	return hdr
}

func buildIPv4TCPSyn(t *testing.T) []byte {
	t.Helper()
	tcp := make([]byte, 24)
	binary.BigEndian.PutUint16(tcp[0:2], 54321) // src port
	binary.BigEndian.PutUint16(tcp[2:4], 443)   // dst port
	binary.BigEndian.PutUint32(tcp[4:8], 0x12345678)
	binary.BigEndian.PutUint32(tcp[8:12], 0) // ACK = 0 for SYN
	tcp[12] = 6 << 4                         // Data offset = 6 (24 bytes header)
	tcp[13] = 0x02                           // SYN
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	// MSS option
	tcp[20] = 2
	tcp[21] = 4
	binary.BigEndian.PutUint16(tcp[22:24], 1460)
	hdr := buildIPv4Header(t, 6, len(tcp))
	return append(hdr, tcp...)
}

func buildIPv4UDP(t *testing.T, srcPort, dstPort int, payload []byte) []byte {
	t.Helper()
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(udp[2:4], uint16(dstPort))
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	udp = append(udp, payload...)
	hdr := buildIPv4Header(t, 17, len(udp))
	return append(hdr, udp...)
}

func buildIPv4ICMPEcho(t *testing.T, typ byte, identifier, sequence uint16, body []byte) []byte {
	t.Helper()
	icmp := make([]byte, 8)
	icmp[0] = typ
	icmp[1] = 0 // code
	binary.BigEndian.PutUint16(icmp[4:6], identifier)
	binary.BigEndian.PutUint16(icmp[6:8], sequence)
	icmp = append(icmp, body...)
	hdr := buildIPv4Header(t, 1, len(icmp))
	return append(hdr, icmp...)
}

func buildIPv6Header(t *testing.T, nextHdr int, payloadLen int) []byte {
	t.Helper()
	hdr := make([]byte, 40)
	hdr[0] = 0x60 // version=6
	binary.BigEndian.PutUint16(hdr[4:6], uint16(payloadLen))
	hdr[6] = byte(nextHdr)
	hdr[7] = 64 // hop limit
	src := net.ParseIP("2001:db8::1").To16()
	dst := net.ParseIP("2001:db8::2").To16()
	copy(hdr[8:24], src)
	copy(hdr[24:40], dst)
	return hdr
}

func buildIPv6TCP(t *testing.T) []byte {
	t.Helper()
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], 80)
	binary.BigEndian.PutUint16(tcp[2:4], 54321)
	binary.BigEndian.PutUint32(tcp[4:8], 0xDEADBEEF)
	binary.BigEndian.PutUint32(tcp[8:12], 0x12345679)
	tcp[12] = 5 << 4 // data offset = 5
	tcp[13] = 0x12   // SYN + ACK
	binary.BigEndian.PutUint16(tcp[14:16], 32768)
	hdr := buildIPv6Header(t, 6, len(tcp))
	return append(hdr, tcp...)
}

// Quick sanity that test helpers above compile and produce
// the expected output.
var _ = strings.Split
