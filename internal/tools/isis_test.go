package tools

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// isisL2LanHello builds a minimal IS-IS L2 LAN Hello PDU with a hostname TLV
// and an IP interface address TLV for handler-level tests.
// PDU type = 16 (L2 LAN Hello).
func isisL2LanHello(sourceID [6]byte, holdingTime uint16, hostname string, ipAddr [4]byte) []byte {
	const commonHdrSize = 8
	sysIDLen := 6

	// Build TLVs.
	// TLV 137: Dynamic Hostname
	hostnameTLV := make([]byte, 2+len(hostname))
	hostnameTLV[0] = 137
	hostnameTLV[1] = byte(len(hostname))
	copy(hostnameTLV[2:], []byte(hostname))

	// TLV 132: IP Interface Address (4 bytes)
	ipTLV := make([]byte, 6)
	ipTLV[0] = 132
	ipTLV[1] = 4
	copy(ipTLV[2:], ipAddr[:])

	var tlvs []byte
	tlvs = append(tlvs, hostnameTLV...)
	tlvs = append(tlvs, ipTLV...)

	// Fixed LAN IIH fields.
	lanIDLen := sysIDLen + 1
	fixedLen := 1 + sysIDLen + 2 + 2 + 1 + lanIDLen
	fixed := make([]byte, fixedLen)
	fixed[0] = 0x02 // circuit_type = L2
	copy(fixed[1:7], sourceID[:])
	binary.BigEndian.PutUint16(fixed[7:9], holdingTime)
	totalPDULen := commonHdrSize + fixedLen + len(tlvs)
	binary.BigEndian.PutUint16(fixed[9:11], uint16(totalPDULen))
	fixed[11] = 64 // priority
	copy(fixed[12:18], sourceID[:])
	fixed[18] = 0x00 // pseudonode ID

	// Common header.
	hdr := make([]byte, commonHdrSize)
	hdr[0] = 0x83                           // IRPD
	hdr[1] = byte(commonHdrSize + fixedLen) // length_indicator
	hdr[2] = 1                              // version
	hdr[3] = 0                              // id_length (0=6)
	hdr[4] = 16                             // pdu_type = L2 LAN Hello
	hdr[5] = 1                              // version2
	hdr[6] = 0                              // reserved
	hdr[7] = 0                              // max_area_addresses

	var pdu []byte
	pdu = append(pdu, hdr...)
	pdu = append(pdu, fixed...)
	pdu = append(pdu, tlvs...)
	return pdu
}

// TestISISDecodeHandler_L2Hello pins the canonical L2 LAN Hello shape through
// the handler — PDU type name, is_hello, level, source_id, hostname, ip.
func TestISISDecodeHandler_L2Hello(t *testing.T) {
	sourceID := [6]byte{0x01, 0x68, 0x01, 0x00, 0x10, 0x01}
	ipAddr := [4]byte{10, 0, 0, 1}
	pkt := isisL2LanHello(sourceID, 30, "spine-01", ipAddr)

	out, err := isisDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(pkt)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"pdu_type_name": "L2_LAN_Hello"`,
		`"is_hello": true`,
		`"level": 2`,
		`"source_id": "0168.0100.1001"`,
		`"holding_time": 30`,
		`"hostname": "spine-01"`,
		`"10.0.0.1"`,
		`"has_auth": false`,
		`"is_cleartext_auth": false`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestISISDecodeHandler_RejectsEmpty confirms the handler returns an error
// when the hex parameter is empty.
func TestISISDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := isisDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}

// TestISISDecodeHandler_RejectsTruncated confirms that a buffer shorter than
// the 8-byte IS-IS common header is rejected.
func TestISISDecodeHandler_RejectsTruncated(t *testing.T) {
	_, err := isisDecodeHandler(context.Background(), nil,
		map[string]any{"hex": "8301010001"}) // 5 bytes
	if err == nil {
		t.Fatal("want error for truncated input")
	}
}
