package eigrp

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// eigrpPacket builds a minimal EIGRP packet with the given header fields and
// TLV payload. The checksum field is left as zero (not computed).
func eigrpPacket(version, opcode uint8, flags uint32, seq, ack uint32, vrID, as uint16, tlvs []byte) []byte {
	hdr := make([]byte, eigrpHeaderSize)
	hdr[0] = version
	hdr[1] = opcode
	// checksum [2:4] = 0x0000
	binary.BigEndian.PutUint32(hdr[4:8], flags)
	binary.BigEndian.PutUint32(hdr[8:12], seq)
	binary.BigEndian.PutUint32(hdr[12:16], ack)
	binary.BigEndian.PutUint16(hdr[16:18], vrID)
	binary.BigEndian.PutUint16(hdr[18:20], as)
	return append(hdr, tlvs...)
}

// parametersTLV builds a Parameters TLV (type 0x0001).
// value = K1 K2 K3 K4 K5 (1 byte each) + hold_time (2 BE) = 7 bytes value.
// Total TLV = 4 (header) + 7 = 11 bytes.
func parametersTLV(k1, k2, k3, k4, k5 uint8, holdTime uint16) []byte {
	tlv := make([]byte, 11)
	binary.BigEndian.PutUint16(tlv[0:2], 0x0001) // type
	binary.BigEndian.PutUint16(tlv[2:4], 11)     // length
	tlv[4] = k1
	tlv[5] = k2
	tlv[6] = k3
	tlv[7] = k4
	tlv[8] = k5
	binary.BigEndian.PutUint16(tlv[9:11], holdTime)
	return tlv
}

// softwareVersionTLV builds a Software Version TLV (type 0x0004).
// value = IOS_major IOS_minor EIGRP_major EIGRP_minor (1 byte each) = 4 bytes.
// Total TLV = 4 (header) + 4 = 8 bytes.
func softwareVersionTLV(iosMaj, iosMin, eigrpMaj, eigrpMin uint8) []byte {
	tlv := make([]byte, 8)
	binary.BigEndian.PutUint16(tlv[0:2], 0x0004) // type
	binary.BigEndian.PutUint16(tlv[2:4], 8)      // length
	tlv[4] = iosMaj
	tlv[5] = iosMin
	tlv[6] = eigrpMaj
	tlv[7] = eigrpMin
	return tlv
}

// authTLV builds an Authentication TLV (type 0x0002).
// Minimal: type (2 BE) + length (2 BE) + auth_type (2 BE) = 6 bytes.
func authTLV(authType uint16) []byte {
	tlv := make([]byte, 6)
	binary.BigEndian.PutUint16(tlv[0:2], 0x0002) // type
	binary.BigEndian.PutUint16(tlv[2:4], 6)      // length
	binary.BigEndian.PutUint16(tlv[4:6], authType)
	return tlv
}

// internalRouteTLV builds an Internal Route TLV (type 0x0102) for IPv4.
// Layout (value, after the 4-byte TLV header):
//
//	next_hop(4) + delay(4) + bandwidth(4) + reserved(3) + reliability(1) +
//	load(1) + mtu(3) + hop_count(1) + reliability2(1) = 22 bytes
//	+ prefix_length(1) + destination(ceil(prefix/8) bytes)
func internalRouteTLV(nextHop [4]byte, delay, bandwidth uint32, prefixLen uint8, dst [4]byte) []byte {
	addrBytes := (int(prefixLen) + 7) / 8
	valueLen := 22 + 1 + addrBytes // 22 fixed + prefix_length + destination
	totalLen := 4 + valueLen
	tlv := make([]byte, totalLen)
	binary.BigEndian.PutUint16(tlv[0:2], 0x0102)           // type
	binary.BigEndian.PutUint16(tlv[2:4], uint16(totalLen)) // length
	// next_hop at value[0:4]
	copy(tlv[4:8], nextHop[:])
	// delay at value[4:8]
	binary.BigEndian.PutUint32(tlv[8:12], delay)
	// bandwidth at value[8:12]
	binary.BigEndian.PutUint32(tlv[12:16], bandwidth)
	// reserved(3) + reliability(1) + load(1) + mtu(3) + hop_count(1) + reliability2(1)
	// offsets [16:26] in tlv = value[12:22] — zero-initialized, fine for test
	// prefix_length at value[22] = tlv[26]
	tlv[4+22] = prefixLen
	// destination at value[23..] = tlv[27..]
	copy(tlv[4+23:], dst[:addrBytes])
	return tlv
}

// TestDecode_Hello_WithParameters tests a Hello packet containing a Parameters
// TLV (K-values + hold time) and a Software Version TLV — the canonical
// EIGRP Hello shape from IOS.
func TestDecode_Hello_WithParameters(t *testing.T) {
	var tlvs []byte
	tlvs = append(tlvs, parametersTLV(1, 0, 1, 0, 0, 15)...) // classic K1=1 K3=1 hold=15s
	tlvs = append(tlvs, softwareVersionTLV(15, 4, 1, 2)...)  // IOS 15.4, EIGRP 1.2

	pkt := eigrpPacket(2, 5, 0, 0, 0, 0x0000, 100, tlvs)
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatal(err)
	}
	if r.OpcodeName != "Hello" {
		t.Errorf("opcode_name=%q, want Hello", r.OpcodeName)
	}
	if !r.IsHello {
		t.Error("expected IsHello=true")
	}
	if r.AutonomousSystem != 100 {
		t.Errorf("as=%d, want 100", r.AutonomousSystem)
	}
	if !r.HasParameters {
		t.Error("expected HasParameters=true")
	}
	if r.K1 != 1 {
		t.Errorf("K1=%d, want 1", r.K1)
	}
	if r.K2 != 0 {
		t.Errorf("K2=%d, want 0", r.K2)
	}
	if r.K3 != 1 {
		t.Errorf("K3=%d, want 1", r.K3)
	}
	if r.HoldTime != 15 {
		t.Errorf("hold_time=%d, want 15", r.HoldTime)
	}
	if !r.HasSoftwareVersion {
		t.Error("expected HasSoftwareVersion=true")
	}
	if r.IOSMajor != 15 {
		t.Errorf("ios_major=%d, want 15", r.IOSMajor)
	}
	if r.IOSMinor != 4 {
		t.Errorf("ios_minor=%d, want 4", r.IOSMinor)
	}
	if r.EIGRPMajor != 1 {
		t.Errorf("eigrp_major=%d, want 1", r.EIGRPMajor)
	}
	if r.TLVCount != 2 {
		t.Errorf("tlv_count=%d, want 2", r.TLVCount)
	}
}

// TestDecode_Update_WithInternalRoute tests an Update packet containing a
// single Internal Route TLV (IPv4). Verifies route count and prefix decode.
func TestDecode_Update_WithInternalRoute(t *testing.T) {
	nextHop := [4]byte{10, 0, 0, 1}
	dst := [4]byte{192, 168, 1, 0}
	routeTLV := internalRouteTLV(nextHop, 2816000, 1000000, 24, dst)

	// Init flag set (first Update in adjacency).
	pkt := eigrpPacket(2, 1, 0x00000001, 1, 0, 0x0000, 65001, routeTLV)
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatal(err)
	}
	if r.OpcodeName != "Update" {
		t.Errorf("opcode_name=%q, want Update", r.OpcodeName)
	}
	if !r.IsUpdate {
		t.Error("expected IsUpdate=true")
	}
	if !r.FlagInit {
		t.Error("expected FlagInit=true")
	}
	if r.AutonomousSystem != 65001 {
		t.Errorf("as=%d, want 65001", r.AutonomousSystem)
	}
	if r.RouteCount != 1 {
		t.Errorf("route_count=%d, want 1", r.RouteCount)
	}
	if r.FirstRoutePrefix != "192.168.1.0/24" {
		t.Errorf("first_route_prefix=%q, want 192.168.1.0/24", r.FirstRoutePrefix)
	}
}

// TestDecode_Auth_MD5 tests a Hello packet carrying an MD5 Authentication TLV.
func TestDecode_Auth_MD5(t *testing.T) {
	var tlvs []byte
	tlvs = append(tlvs, authTLV(2)...)                       // MD5
	tlvs = append(tlvs, parametersTLV(1, 0, 1, 0, 0, 30)...) // K1=1 K3=1 hold=30

	pkt := eigrpPacket(2, 5, 0, 0, 0, 0x0000, 200, tlvs)
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatal(err)
	}
	if !r.HasAuth {
		t.Error("expected HasAuth=true")
	}
	if r.AuthType != 2 {
		t.Errorf("auth_type=%d, want 2 (MD5)", r.AuthType)
	}
	if r.AuthTypeName != "MD5" {
		t.Errorf("auth_type_name=%q, want MD5", r.AuthTypeName)
	}
	if !r.HasParameters {
		t.Error("expected HasParameters=true after Auth TLV")
	}
}

// TestDecode_RejectsEmpty checks that an empty hex string returns an error.
func TestDecode_RejectsEmpty(t *testing.T) {
	_, err := Decode("")
	if err == nil {
		t.Fatal("want error for empty input")
	}
}

// TestDecode_RejectsTruncated checks that a buffer shorter than the 20-byte
// header returns an error.
func TestDecode_RejectsTruncated(t *testing.T) {
	_, err := Decode("02050000") // 4 bytes, far below 20
	if err == nil {
		t.Fatal("want error for truncated input")
	}
}

// TestDecode_FlagsDecoded verifies that all four EIGRP flag bits are decoded.
func TestDecode_FlagsDecoded(t *testing.T) {
	// flags = 0x0000000F → Init | CR | Restart | EndOfTable all set
	pkt := eigrpPacket(2, 5, 0x0000000F, 0, 0, 0x0000, 1, nil)
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatal(err)
	}
	if !r.FlagInit {
		t.Error("expected FlagInit=true")
	}
	if !r.FlagConditionalReceive {
		t.Error("expected FlagConditionalReceive=true")
	}
	if !r.FlagRestart {
		t.Error("expected FlagRestart=true")
	}
	if !r.FlagEndOfTable {
		t.Error("expected FlagEndOfTable=true")
	}
}

// TestDecode_SeparatorTolerance verifies that colon-separated hex is accepted.
func TestDecode_SeparatorTolerance(t *testing.T) {
	pkt := eigrpPacket(2, 5, 0, 0, 0, 0x0000, 1, nil)
	raw := hex.EncodeToString(pkt)
	// Insert colons between every byte pair.
	var separated strings.Builder
	for i := 0; i < len(raw); i += 2 {
		if i > 0 {
			separated.WriteByte(':')
		}
		separated.WriteString(raw[i : i+2])
	}
	r, err := Decode(separated.String())
	if err != nil {
		t.Fatalf("colon-separated input rejected: %v", err)
	}
	if r.OpcodeName != "Hello" {
		t.Errorf("opcode=%q, want Hello", r.OpcodeName)
	}
}
