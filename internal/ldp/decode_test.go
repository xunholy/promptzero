package ldp

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// ldpPDUHeader builds a 10-byte LDP PDU header.
// version=1, pduLength covers the PDU body (messages), lsrID and labelSpace.
func ldpPDUHeader(pduLength uint16, lsrID [4]byte, labelSpace uint16) []byte {
	hdr := make([]byte, ldpPDUHeaderSize)
	binary.BigEndian.PutUint16(hdr[0:2], 1) // version = 1
	binary.BigEndian.PutUint16(hdr[2:4], pduLength)
	copy(hdr[4:8], lsrID[:])
	binary.BigEndian.PutUint16(hdr[8:10], labelSpace)
	return hdr
}

// ldpMsgHeader builds an 8-byte LDP message header.
// msgType is the 15-bit type (unknown_bit will be 0).
// msgLength covers: message_id(4) + TLVs.
func ldpMsgHeader(msgType uint16, msgLength uint16, msgID uint32) []byte {
	hdr := make([]byte, ldpMsgHeaderSize)
	binary.BigEndian.PutUint16(hdr[0:2], msgType&0x7FFF)
	binary.BigEndian.PutUint16(hdr[2:4], msgLength)
	binary.BigEndian.PutUint32(hdr[4:8], msgID)
	return hdr
}

// commonHelloParamsTLV builds a Common Hello Parameters TLV (type 0x0500).
// value = hold_time (2 BE) + flags (2 BE); total value = 4 bytes.
// Total TLV = 4 (header) + 4 = 8 bytes.
func commonHelloParamsTLV(holdTime uint16, targeted, requestTargeted bool) []byte {
	tlv := make([]byte, 8)
	binary.BigEndian.PutUint16(tlv[0:2], 0x0500)
	binary.BigEndian.PutUint16(tlv[2:4], 4) // length = 4 (value only)
	binary.BigEndian.PutUint16(tlv[4:6], holdTime)
	var flags uint16
	if targeted {
		flags |= 0x8000
	}
	if requestTargeted {
		flags |= 0x4000
	}
	binary.BigEndian.PutUint16(tlv[6:8], flags)
	return tlv
}

// ipv4TransportAddressTLV builds an IPv4 Transport Address TLV (type 0x0501).
// value = 4-byte IPv4 address; total TLV = 4 + 4 = 8 bytes.
func ipv4TransportAddressTLV(addr [4]byte) []byte {
	tlv := make([]byte, 8)
	binary.BigEndian.PutUint16(tlv[0:2], 0x0501)
	binary.BigEndian.PutUint16(tlv[2:4], 4) // length = 4
	copy(tlv[4:8], addr[:])
	return tlv
}

// commonSessionParamsTLV builds a Common Session Parameters TLV (type 0x0600).
// value layout: protocol_version(2) + keepalive_time(2) + flags(1) +
// path_vector_limit(1) + max_pdu_length(2) + receiver_lsr_id(4) +
// receiver_label_space(2) = 14 bytes.
// Total TLV = 4 + 14 = 18 bytes.
func commonSessionParamsTLV(keepaliveTime uint16, maxPDULength uint16, receiverLSRID [4]byte, receiverLabelSpace uint16) []byte {
	tlv := make([]byte, 18)
	binary.BigEndian.PutUint16(tlv[0:2], 0x0600)
	binary.BigEndian.PutUint16(tlv[2:4], 14) // length = 14
	binary.BigEndian.PutUint16(tlv[4:6], 1)  // protocol_version = 1
	binary.BigEndian.PutUint16(tlv[6:8], keepaliveTime)
	// flags[8] = 0, path_vector_limit[9] = 0
	binary.BigEndian.PutUint16(tlv[10:12], maxPDULength)
	copy(tlv[12:16], receiverLSRID[:])
	binary.BigEndian.PutUint16(tlv[16:18], receiverLabelSpace)
	return tlv
}

// genericLabelTLV builds a Generic Label TLV (type 0x0300).
// value = 4-byte label value; total TLV = 4 + 4 = 8 bytes.
func genericLabelTLV(label uint32) []byte {
	tlv := make([]byte, 8)
	binary.BigEndian.PutUint16(tlv[0:2], 0x0300)
	binary.BigEndian.PutUint16(tlv[2:4], 4) // length = 4
	binary.BigEndian.PutUint32(tlv[4:8], label)
	return tlv
}

// buildPDU assembles a complete LDP PDU from an LSR ID, label space, a
// message type, message ID, and TLV payload.
func buildPDU(lsrID [4]byte, labelSpace uint16, msgType uint16, msgID uint32, tlvs []byte) []byte {
	// msgLength = 4 (message_id) + len(tlvs)
	msgLength := uint16(4 + len(tlvs))
	msg := ldpMsgHeader(msgType, msgLength, msgID)
	msg = append(msg, tlvs...)

	// pduLength = 6 (lsr_id + label_space) + len(msg)
	pduLength := uint16(6 + len(msg))
	hdr := ldpPDUHeader(pduLength, lsrID, labelSpace)
	return append(hdr, msg...)
}

// TestDecode_Hello_WithCommonHelloParams tests a Hello PDU containing a
// Common Hello Parameters TLV and an IPv4 Transport Address TLV — the
// canonical LDP Hello shape sent on UDP/646.
func TestDecode_Hello_WithCommonHelloParams(t *testing.T) {
	lsrID := [4]byte{192, 0, 2, 1}
	var tlvs []byte
	tlvs = append(tlvs, commonHelloParamsTLV(15, false, false)...) // hold=15s, link Hello
	tlvs = append(tlvs, ipv4TransportAddressTLV([4]byte{192, 0, 2, 1})...)

	pkt := buildPDU(lsrID, 0, 0x0100, 1, tlvs)
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatal(err)
	}
	if r.MessageTypeName != "Hello" {
		t.Errorf("message_type_name=%q, want Hello", r.MessageTypeName)
	}
	if !r.IsHello {
		t.Error("expected IsHello=true")
	}
	if r.LSRID != "192.0.2.1" {
		t.Errorf("lsr_id=%q, want 192.0.2.1", r.LSRID)
	}
	if r.LabelSpace != 0 {
		t.Errorf("label_space=%d, want 0", r.LabelSpace)
	}
	if !r.HasHelloParams {
		t.Error("expected HasHelloParams=true")
	}
	if r.HoldTime != 15 {
		t.Errorf("hold_time=%d, want 15", r.HoldTime)
	}
	if r.Targeted {
		t.Error("expected Targeted=false for link Hello")
	}
	if !r.HasTransportAddress {
		t.Error("expected HasTransportAddress=true")
	}
	if r.TransportAddress != "192.0.2.1" {
		t.Errorf("transport_address=%q, want 192.0.2.1", r.TransportAddress)
	}
	if r.TLVCount != 2 {
		t.Errorf("tlv_count=%d, want 2", r.TLVCount)
	}
}

// TestDecode_Hello_Targeted tests a Targeted Hello PDU (T-bit set).
func TestDecode_Hello_Targeted(t *testing.T) {
	lsrID := [4]byte{10, 0, 0, 1}
	tlvs := commonHelloParamsTLV(45, true, false) // targeted Hello, hold=45s

	pkt := buildPDU(lsrID, 0, 0x0100, 2, tlvs)
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatal(err)
	}
	if !r.IsHello {
		t.Error("expected IsHello=true")
	}
	if !r.HasHelloParams {
		t.Error("expected HasHelloParams=true")
	}
	if !r.Targeted {
		t.Error("expected Targeted=true")
	}
	if r.RequestTargeted {
		t.Error("expected RequestTargeted=false")
	}
	if r.HoldTime != 45 {
		t.Errorf("hold_time=%d, want 45", r.HoldTime)
	}
}

// TestDecode_Initialization tests an Initialization PDU with Common Session
// Parameters TLV.
func TestDecode_Initialization(t *testing.T) {
	lsrID := [4]byte{10, 0, 0, 1}
	receiverLSRID := [4]byte{10, 0, 0, 2}
	tlvs := commonSessionParamsTLV(60, 4096, receiverLSRID, 0)

	pkt := buildPDU(lsrID, 0, 0x0200, 100, tlvs)
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatal(err)
	}
	if r.MessageTypeName != "Initialization" {
		t.Errorf("message_type_name=%q, want Initialization", r.MessageTypeName)
	}
	if !r.IsInitialization {
		t.Error("expected IsInitialization=true")
	}
	if !r.HasSessionParams {
		t.Error("expected HasSessionParams=true")
	}
	if r.KeepaliveTime != 60 {
		t.Errorf("keepalive_time=%d, want 60", r.KeepaliveTime)
	}
	if r.MaxPDULength != 4096 {
		t.Errorf("max_pdu_length=%d, want 4096", r.MaxPDULength)
	}
	if r.ReceiverLSRID != "10.0.0.2" {
		t.Errorf("receiver_lsr_id=%q, want 10.0.0.2", r.ReceiverLSRID)
	}
}

// TestDecode_KeepAlive tests a KeepAlive PDU (no TLVs).
func TestDecode_KeepAlive(t *testing.T) {
	lsrID := [4]byte{10, 0, 0, 1}
	pkt := buildPDU(lsrID, 0, 0x0201, 200, nil)
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatal(err)
	}
	if r.MessageTypeName != "KeepAlive" {
		t.Errorf("message_type_name=%q, want KeepAlive", r.MessageTypeName)
	}
	if !r.IsKeepalive {
		t.Error("expected IsKeepalive=true")
	}
	if r.TLVCount != 0 {
		t.Errorf("tlv_count=%d, want 0", r.TLVCount)
	}
}

// TestDecode_LabelMapping tests a Label Mapping PDU with a Generic Label TLV.
func TestDecode_LabelMapping(t *testing.T) {
	lsrID := [4]byte{10, 0, 0, 1}
	tlvs := genericLabelTLV(100)

	pkt := buildPDU(lsrID, 0, 0x0400, 300, tlvs)
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatal(err)
	}
	if r.MessageTypeName != "Label Mapping" {
		t.Errorf("message_type_name=%q, want Label Mapping", r.MessageTypeName)
	}
	if !r.IsLabelMapping {
		t.Error("expected IsLabelMapping=true")
	}
	if !r.HasGenericLabel {
		t.Error("expected HasGenericLabel=true")
	}
	if r.LabelValue != 100 {
		t.Errorf("label_value=%d, want 100", r.LabelValue)
	}
}

// TestDecode_RejectsEmpty checks that an empty hex string returns an error.
func TestDecode_RejectsEmpty(t *testing.T) {
	_, err := Decode("")
	if err == nil {
		t.Fatal("want error for empty input")
	}
}

// TestDecode_RejectsTruncated checks that a buffer shorter than the 10-byte
// PDU header returns an error.
func TestDecode_RejectsTruncated(t *testing.T) {
	_, err := Decode("00010000") // 4 bytes, below 10
	if err == nil {
		t.Fatal("want error for truncated input")
	}
}

// TestDecode_SeparatorTolerance verifies that colon-separated hex is accepted.
func TestDecode_SeparatorTolerance(t *testing.T) {
	lsrID := [4]byte{10, 0, 0, 1}
	pkt := buildPDU(lsrID, 0, 0x0100, 1, commonHelloParamsTLV(15, false, false))
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
	if r.MessageTypeName != "Hello" {
		t.Errorf("message_type_name=%q, want Hello", r.MessageTypeName)
	}
}

// TestDecode_LSRIDDottedQuad verifies that the LSR ID is formatted as a
// dotted-quad IPv4 string.
func TestDecode_LSRIDDottedQuad(t *testing.T) {
	lsrID := [4]byte{172, 16, 0, 1}
	pkt := buildPDU(lsrID, 0, 0x0201, 1, nil)
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatal(err)
	}
	if r.LSRID != "172.16.0.1" {
		t.Errorf("lsr_id=%q, want 172.16.0.1", r.LSRID)
	}
}
