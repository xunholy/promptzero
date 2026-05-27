package isis

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// isisCommonHeader builds the 8-byte IS-IS common header.
// pduTypeFull is the full byte value for byte 4 (pdu_type in lower 5 bits).
func isisCommonHeader(pduType uint8) []byte {
	hdr := make([]byte, isisCommonHeaderSize)
	hdr[0] = 0x83 // IRPD
	hdr[1] = 0    // length_indicator — filled in by callers
	hdr[2] = 1    // version
	hdr[3] = 0    // id_length (0 = 6, default)
	hdr[4] = pduType & 0x1F
	hdr[5] = 1 // version2
	hdr[6] = 0 // reserved
	hdr[7] = 0 // max_area_addresses (0 = 3, default)
	return hdr
}

// buildL2LANHello builds a minimal L2 LAN Hello (IIH) with TLVs.
// PDU type 16. Includes area address TLV (1), hostname TLV (137), and
// IP interface address TLV (132).
func buildL2LANHello(sourceID [6]byte, holdingTime uint16, ipAddr [4]byte, areaAddr []byte, hostname string) []byte {
	// Build TLVs first.
	var tlvs []byte

	// TLV 1: Area Addresses
	// Value: addr_len(1) + addr(addr_len)
	areaValue := append([]byte{byte(len(areaAddr))}, areaAddr...)
	tlvs = append(tlvs, buildTLV(1, areaValue)...)

	// TLV 132: IP Interface Address
	tlvs = append(tlvs, buildTLV(132, ipAddr[:])...)

	// TLV 137: Dynamic Hostname
	tlvs = append(tlvs, buildTLV(137, []byte(hostname))...)

	// Build the fixed per-PDU fields (after common header, before TLVs).
	// LAN IIH: circuit_type(1) + source_id(6) + holding_time(2) +
	// pdu_length(2) + priority(1) + lan_id(7)
	sysIDLen := 6
	lanIDLen := sysIDLen + 1
	fixedLen := 1 + sysIDLen + 2 + 2 + 1 + lanIDLen
	fixed := make([]byte, fixedLen)
	fixed[0] = 0x02 // circuit_type = L2
	copy(fixed[1:7], sourceID[:])
	binary.BigEndian.PutUint16(fixed[7:9], holdingTime)
	totalPDULen := isisCommonHeaderSize + fixedLen + len(tlvs)
	binary.BigEndian.PutUint16(fixed[9:11], uint16(totalPDULen))
	fixed[11] = 64 // priority
	// lan_id: source_id + pseudonode 0 (simulated DIS = self)
	copy(fixed[12:18], sourceID[:])
	fixed[18] = 0x00 // pseudonode ID

	// Build the complete PDU.
	hdr := isisCommonHeader(16)
	hdrLen := isisCommonHeaderSize + fixedLen
	hdr[1] = byte(hdrLen) // length_indicator

	var pdu []byte
	pdu = append(pdu, hdr...)
	pdu = append(pdu, fixed...)
	pdu = append(pdu, tlvs...)
	return pdu
}

// buildLSPWithAuth builds an L2 LSP with a cleartext authentication TLV.
func buildLSPWithAuth(lspID [8]byte, seqNum uint32, password string) []byte {
	// TLV 10: Authentication, auth_type=1 (cleartext)
	authValue := append([]byte{0x01}, []byte(password)...)
	var tlvs []byte
	tlvs = append(tlvs, buildTLV(10, authValue)...)

	// LSP fixed fields: pdu_length(2) + remaining_lifetime(2) + lsp_id(8) +
	// sequence_number(4) + checksum(2) + p_att_oload_istype(1)
	fixedLen := 2 + 2 + 8 + 4 + 2 + 1
	fixed := make([]byte, fixedLen)
	totalPDULen := isisCommonHeaderSize + fixedLen + len(tlvs)
	binary.BigEndian.PutUint16(fixed[0:2], uint16(totalPDULen))
	binary.BigEndian.PutUint16(fixed[2:4], 1200) // remaining_lifetime
	copy(fixed[4:12], lspID[:])
	binary.BigEndian.PutUint32(fixed[12:16], seqNum)
	binary.BigEndian.PutUint16(fixed[16:18], 0x1234) // checksum
	fixed[18] = 0x02                                 // is_type = L2, no overload

	hdr := isisCommonHeader(20) // L2 LSP
	hdrLen := isisCommonHeaderSize + fixedLen
	hdr[1] = byte(hdrLen)

	var pdu []byte
	pdu = append(pdu, hdr...)
	pdu = append(pdu, fixed...)
	pdu = append(pdu, tlvs...)
	return pdu
}

// buildTLV constructs a single IS-IS TLV (type(1) + length(1) + value).
func buildTLV(tlvType uint8, value []byte) []byte {
	tlv := make([]byte, 2+len(value))
	tlv[0] = tlvType
	tlv[1] = byte(len(value))
	copy(tlv[2:], value)
	return tlv
}

// TestDecode_L2LANHello_WithTLVs tests a complete L2 LAN Hello packet
// carrying area address, hostname, and IP interface address TLVs.
func TestDecode_L2LANHello_WithTLVs(t *testing.T) {
	sourceID := [6]byte{0x01, 0x68, 0x01, 0x00, 0x10, 0x01}
	ipAddr := [4]byte{10, 0, 0, 1}
	areaAddr := []byte{0x49, 0x00, 0x01}
	hostname := "core-router-nyc-01"

	pkt := buildL2LANHello(sourceID, 30, ipAddr, areaAddr, hostname)
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatal(err)
	}

	if r.PDUTypeName != "L2_LAN_Hello" {
		t.Errorf("pdu_type_name=%q, want L2_LAN_Hello", r.PDUTypeName)
	}
	if !r.IsHello {
		t.Error("expected IsHello=true")
	}
	if r.IsLSP {
		t.Error("expected IsLSP=false")
	}
	if r.Level != 2 {
		t.Errorf("level=%d, want 2", r.Level)
	}
	if r.SourceID != "0168.0100.1001" {
		t.Errorf("source_id=%q, want 0168.0100.1001", r.SourceID)
	}
	if r.HoldingTime != 30 {
		t.Errorf("holding_time=%d, want 30", r.HoldingTime)
	}
	if r.IRPD != 0x83 {
		t.Errorf("irpd=0x%02x, want 0x83", r.IRPD)
	}
	// TLV checks
	if r.TLVCount != 3 {
		t.Errorf("tlv_count=%d, want 3", r.TLVCount)
	}
	if len(r.AreaAddresses) != 1 || r.AreaAddresses[0] != "490001" {
		t.Errorf("area_addresses=%v, want [490001]", r.AreaAddresses)
	}
	if r.Hostname != hostname {
		t.Errorf("hostname=%q, want %q", r.Hostname, hostname)
	}
	if len(r.IPAddresses) != 1 || r.IPAddresses[0] != "10.0.0.1" {
		t.Errorf("ip_addresses=%v, want [10.0.0.1]", r.IPAddresses)
	}
	if r.HasAuth {
		t.Error("expected HasAuth=false (no auth TLV)")
	}
	if r.IsCleartextAuth {
		t.Error("expected IsCleartextAuth=false")
	}
}

// TestDecode_LSP_WithCleartextAuth tests an L2 LSP with a cleartext
// Authentication TLV (auth_type=1). This is the critical security-sensitive case
// that exposes the plaintext IS-IS authentication key.
func TestDecode_LSP_WithCleartextAuth(t *testing.T) {
	lspID := [8]byte{0x01, 0x68, 0x01, 0x00, 0x10, 0x01, 0x00, 0x00}
	pkt := buildLSPWithAuth(lspID, 1, "secretpassword")
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatal(err)
	}

	if r.PDUTypeName != "L2_LSP" {
		t.Errorf("pdu_type_name=%q, want L2_LSP", r.PDUTypeName)
	}
	if !r.IsLSP {
		t.Error("expected IsLSP=true")
	}
	if r.IsHello {
		t.Error("expected IsHello=false")
	}
	if r.Level != 2 {
		t.Errorf("level=%d, want 2", r.Level)
	}
	if r.SequenceNumber != 1 {
		t.Errorf("sequence_number=%d, want 1", r.SequenceNumber)
	}
	if r.RemainingLifetime != 1200 {
		t.Errorf("remaining_lifetime=%d, want 1200", r.RemainingLifetime)
	}
	if r.Checksum != "0x1234" {
		t.Errorf("checksum=%q, want 0x1234", r.Checksum)
	}
	if r.ISType != 2 {
		t.Errorf("is_type=%d, want 2", r.ISType)
	}
	if r.OverloadBit {
		t.Error("expected overload_bit=false")
	}
	if !r.HasAuth {
		t.Error("expected HasAuth=true")
	}
	if r.AuthType != 1 {
		t.Errorf("auth_type=%d, want 1 (Cleartext)", r.AuthType)
	}
	if r.AuthTypeName != "Cleartext" {
		t.Errorf("auth_type_name=%q, want Cleartext", r.AuthTypeName)
	}
	if !r.IsCleartextAuth {
		t.Error("expected IsCleartextAuth=true")
	}
	if r.TLVCount != 1 {
		t.Errorf("tlv_count=%d, want 1", r.TLVCount)
	}
}

// TestDecode_RejectsEmpty checks that an empty hex string returns an error.
func TestDecode_RejectsEmpty(t *testing.T) {
	_, err := Decode("")
	if err == nil {
		t.Fatal("want error for empty input")
	}
}

// TestDecode_RejectsTruncated checks that a buffer shorter than the 8-byte
// common header returns an error.
func TestDecode_RejectsTruncated(t *testing.T) {
	_, err := Decode("8301010001") // 5 bytes, below 8
	if err == nil {
		t.Fatal("want error for truncated input")
	}
}

// TestDecode_PDUTypeNames verifies all 9 known PDU type names decode correctly.
func TestDecode_PDUTypeNames(t *testing.T) {
	cases := []struct {
		pduType uint8
		want    string
	}{
		{15, "L1_LAN_Hello"},
		{16, "L2_LAN_Hello"},
		{17, "P2P_Hello"},
		{18, "L1_LSP"},
		{20, "L2_LSP"},
		{24, "L1_CSNP"},
		{25, "L2_CSNP"},
		{26, "L1_PSNP"},
		{27, "L2_PSNP"},
	}
	for _, tc := range cases {
		hdr := isisCommonHeader(tc.pduType)
		r, err := Decode(hex.EncodeToString(hdr))
		if err != nil {
			t.Errorf("pdu_type %d: %v", tc.pduType, err)
			continue
		}
		if r.PDUTypeName != tc.want {
			t.Errorf("pdu_type %d: got %q, want %q", tc.pduType, r.PDUTypeName, tc.want)
		}
	}
}

// TestDecode_SystemIDFormatting verifies that a 6-byte system ID is formatted
// as "XXXX.XXXX.XXXX" dotted hex.
func TestDecode_SystemIDFormatting(t *testing.T) {
	sourceID := [6]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	ipAddr := [4]byte{192, 168, 1, 1}
	areaAddr := []byte{0x49, 0x00, 0x01}
	pkt := buildL2LANHello(sourceID, 10, ipAddr, areaAddr, "test")
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatal(err)
	}
	if r.SourceID != "aabb.ccdd.eeff" {
		t.Errorf("source_id=%q, want aabb.ccdd.eeff", r.SourceID)
	}
}

// TestDecode_SeparatorTolerance verifies that colon-separated hex is accepted.
func TestDecode_SeparatorTolerance(t *testing.T) {
	hdr := isisCommonHeader(16)
	raw := hex.EncodeToString(hdr)
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
	if r.PDUTypeName != "L2_LAN_Hello" {
		t.Errorf("pdu_type_name=%q, want L2_LAN_Hello", r.PDUTypeName)
	}
}

// TestDecode_MultipleIPAddresses verifies that multiple IP addresses from TLV 132
// are all surfaced.
func TestDecode_MultipleIPAddresses(t *testing.T) {
	// Build a minimal L2 LAN Hello with two IP interface addresses in one TLV.
	sourceID := [6]byte{0x01, 0x00, 0x01, 0x00, 0x01, 0x00}

	// Manually build a packet with a TLV 132 containing two IPv4 addresses.
	var tlvs []byte
	areaValue := []byte{0x03, 0x49, 0x00, 0x01}
	tlvs = append(tlvs, buildTLV(1, areaValue)...)
	// Two IPs in one TLV 132 value.
	twoIPs := []byte{10, 0, 0, 1, 192, 168, 1, 1}
	tlvs = append(tlvs, buildTLV(132, twoIPs)...)

	sysIDLen := 6
	lanIDLen := sysIDLen + 1
	fixedLen := 1 + sysIDLen + 2 + 2 + 1 + lanIDLen
	fixed := make([]byte, fixedLen)
	fixed[0] = 0x02 // circuit_type = L2
	copy(fixed[1:7], sourceID[:])
	binary.BigEndian.PutUint16(fixed[7:9], 30)
	totalPDULen := isisCommonHeaderSize + fixedLen + len(tlvs)
	binary.BigEndian.PutUint16(fixed[9:11], uint16(totalPDULen))
	fixed[11] = 64
	copy(fixed[12:18], sourceID[:])
	fixed[18] = 0x00

	hdr := isisCommonHeader(16)
	hdrLen := isisCommonHeaderSize + fixedLen
	hdr[1] = byte(hdrLen)

	var pdu []byte
	pdu = append(pdu, hdr...)
	pdu = append(pdu, fixed...)
	pdu = append(pdu, tlvs...)

	r, err := Decode(hex.EncodeToString(pdu))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.IPAddresses) != 2 {
		t.Fatalf("ip_addresses count=%d, want 2; got %v", len(r.IPAddresses), r.IPAddresses)
	}
	if r.IPAddresses[0] != "10.0.0.1" {
		t.Errorf("ip_addresses[0]=%q, want 10.0.0.1", r.IPAddresses[0])
	}
	if r.IPAddresses[1] != "192.168.1.1" {
		t.Errorf("ip_addresses[1]=%q, want 192.168.1.1", r.IPAddresses[1])
	}
}
