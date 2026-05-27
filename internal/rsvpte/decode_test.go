package rsvpte

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// rsvpHeader builds the 8-byte RSVP common header.
// version=1 is encoded in the high nibble of byte 0; flags in the low nibble.
func rsvpHeader(msgType uint8, sendTTL uint8, totalLength uint16) []byte {
	hdr := make([]byte, rsvpHeaderSize)
	hdr[0] = 1 << 4 // version=1, flags=0
	hdr[1] = msgType
	// checksum [2:4] = 0x0000
	hdr[4] = sendTTL
	// reserved [5] = 0
	binary.BigEndian.PutUint16(hdr[6:8], totalLength)
	return hdr
}

// rsvpObject builds a single RSVP object with the given class_num, c_type,
// and value bytes. total length = 4 + len(value).
func rsvpObject(classNum, cType uint8, value []byte) []byte {
	totalLen := 4 + len(value)
	obj := make([]byte, totalLen)
	binary.BigEndian.PutUint16(obj[0:2], uint16(totalLen))
	obj[2] = classNum
	obj[3] = cType
	copy(obj[4:], value)
	return obj
}

// sessionLSPTunnelIPv4 builds the value for a SESSION object C-Type 7.
// IPv4 tunnel endpoint(4) + reserved(2) + tunnel_id(2 BE) + extended_tunnel_id(4)
func sessionLSPTunnelIPv4(endpoint [4]byte, tunnelID uint16, extTunnelID [4]byte) []byte {
	v := make([]byte, 12)
	copy(v[0:4], endpoint[:])
	// v[4:6] = reserved, zero
	binary.BigEndian.PutUint16(v[6:8], tunnelID)
	copy(v[8:12], extTunnelID[:])
	return v
}

// hopIPv4 builds the value for a HOP object C-Type 1.
// next/previous_hop_address(4) + logical_interface_handle(4)
func hopIPv4(hopAddr [4]byte) []byte {
	v := make([]byte, 8)
	copy(v[0:4], hopAddr[:])
	// logical_interface_handle = 0
	return v
}

// timeValuesValue builds the value for a TIME_VALUES object C-Type 1.
func timeValuesValue(refreshMs uint32) []byte {
	v := make([]byte, 4)
	binary.BigEndian.PutUint32(v[0:4], refreshMs)
	return v
}

// senderTemplateLSPTunnelIPv4 builds the value for a SENDER_TEMPLATE object
// C-Type 7. IPv4 sender(4) + reserved(2) + lsp_id(2 BE)
func senderTemplateLSPTunnelIPv4(sender [4]byte, lspID uint16) []byte {
	v := make([]byte, 8)
	copy(v[0:4], sender[:])
	// v[4:6] = reserved
	binary.BigEndian.PutUint16(v[6:8], lspID)
	return v
}

// labelRequestValue builds the value for a LABEL_REQUEST object C-Type 1.
// reserved(2) + L3PID(2 BE)
func labelRequestValue(l3pid uint16) []byte {
	v := make([]byte, 4)
	binary.BigEndian.PutUint16(v[2:4], l3pid)
	return v
}

// labelValue builds the value for a LABEL object C-Type 1.
// label(4 BE)
func labelValue(label uint32) []byte {
	v := make([]byte, 4)
	binary.BigEndian.PutUint32(v[0:4], label)
	return v
}

// sessionAttributeValue builds the value for a SESSION_ATTRIBUTE object
// C-Type 7. setup_priority(1) + holding_priority(1) + flags(1) +
// name_length(1) + session_name(variable)
func sessionAttributeValue(setupPri, holdingPri, flags uint8, name string) []byte {
	v := make([]byte, 4+len(name))
	v[0] = setupPri
	v[1] = holdingPri
	v[2] = flags
	v[3] = uint8(len(name))
	copy(v[4:], name)
	return v
}

// eroIPv4SubObject builds a single ERO IPv4 prefix sub-object.
// L-bit(1b)+type=1(7b)(1 byte) + length(1) + IPv4(4) + prefix_len(1) + flags(1)
func eroIPv4SubObject(loose bool, addr [4]byte, prefixLen uint8) []byte {
	sub := make([]byte, 8)
	typeByte := uint8(1) // type = 1 (IPv4 prefix)
	if loose {
		typeByte |= 0x80
	}
	sub[0] = typeByte
	sub[1] = 8 // length = 8
	copy(sub[2:6], addr[:])
	sub[6] = prefixLen
	// sub[7] = flags = 0
	return sub
}

// buildPathPacket builds a complete RSVP Path message with SESSION, HOP,
// SENDER_TEMPLATE, ERO (2 hops), LABEL_REQUEST, and SESSION_ATTRIBUTE.
func buildPathPacket() []byte {
	var objects []byte

	// SESSION object: class=1, c_type=7
	sessVal := sessionLSPTunnelIPv4(
		[4]byte{192, 168, 100, 1},
		42,
		[4]byte{10, 0, 0, 1},
	)
	objects = append(objects, rsvpObject(1, 7, sessVal)...)

	// HOP object: class=3, c_type=1
	hopVal := hopIPv4([4]byte{10, 1, 1, 1})
	objects = append(objects, rsvpObject(3, 1, hopVal)...)

	// TIME_VALUES object: class=5, c_type=1; refresh = 30000 ms
	tvVal := timeValuesValue(30000)
	objects = append(objects, rsvpObject(5, 1, tvVal)...)

	// SENDER_TEMPLATE object: class=11, c_type=7
	stVal := senderTemplateLSPTunnelIPv4([4]byte{10, 0, 0, 1}, 100)
	objects = append(objects, rsvpObject(11, 7, stVal)...)

	// ERO object: class=20, c_type=1
	// Two IPv4 hops: strict 10.1.1.2/32, loose 10.2.2.2/32
	var eroVal []byte
	eroVal = append(eroVal, eroIPv4SubObject(false, [4]byte{10, 1, 1, 2}, 32)...)
	eroVal = append(eroVal, eroIPv4SubObject(true, [4]byte{10, 2, 2, 2}, 32)...)
	objects = append(objects, rsvpObject(20, 1, eroVal)...)

	// LABEL_REQUEST object: class=19, c_type=1; L3PID=0x0800 (IPv4)
	lrVal := labelRequestValue(0x0800)
	objects = append(objects, rsvpObject(19, 1, lrVal)...)

	// SESSION_ATTRIBUTE object: class=207, c_type=7
	saVal := sessionAttributeValue(7, 0, 0, "test-lsp")
	objects = append(objects, rsvpObject(207, 7, saVal)...)

	totalLen := uint16(rsvpHeaderSize + len(objects))
	hdr := rsvpHeader(1 /* Path */, 64, totalLen)
	return append(hdr, objects...)
}

// buildResvPacket builds a minimal RSVP Resv message with a LABEL object.
func buildResvPacket() []byte {
	var objects []byte

	// SESSION object: class=1, c_type=7
	sessVal := sessionLSPTunnelIPv4(
		[4]byte{192, 168, 100, 1},
		42,
		[4]byte{10, 0, 0, 1},
	)
	objects = append(objects, rsvpObject(1, 7, sessVal)...)

	// HOP object: class=3, c_type=1
	hopVal := hopIPv4([4]byte{10, 1, 1, 1})
	objects = append(objects, rsvpObject(3, 1, hopVal)...)

	// LABEL object: class=16, c_type=1; MPLS label 3000
	lVal := labelValue(3000)
	objects = append(objects, rsvpObject(16, 1, lVal)...)

	totalLen := uint16(rsvpHeaderSize + len(objects))
	hdr := rsvpHeader(2 /* Resv */, 64, totalLen)
	return append(hdr, objects...)
}

// buildHelloPacket builds a minimal RSVP Hello message (no objects).
func buildHelloPacket() []byte {
	totalLen := uint16(rsvpHeaderSize)
	return rsvpHeader(12 /* Hello */, 255, totalLen)
}

// TestDecode_PathMessage tests a full Path message with SESSION, HOP,
// SENDER_TEMPLATE, ERO (2 hops), LABEL_REQUEST, and SESSION_ATTRIBUTE.
func TestDecode_PathMessage(t *testing.T) {
	pkt := buildPathPacket()
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatal(err)
	}

	if r.Version != 1 {
		t.Errorf("version=%d, want 1", r.Version)
	}
	if r.MsgType != 1 {
		t.Errorf("msg_type=%d, want 1", r.MsgType)
	}
	if r.MsgTypeName != "Path" {
		t.Errorf("msg_type_name=%q, want Path", r.MsgTypeName)
	}
	if !r.IsPath {
		t.Error("expected is_path=true")
	}
	if r.IsResv || r.IsHello || r.IsPathTear || r.IsResvTear {
		t.Error("unexpected classification flag set")
	}
	if r.SendTTL != 64 {
		t.Errorf("send_ttl=%d, want 64", r.SendTTL)
	}

	// SESSION
	if !r.HasSession {
		t.Error("expected has_session=true")
	}
	if r.TunnelEndpoint != "192.168.100.1" {
		t.Errorf("tunnel_endpoint=%q, want 192.168.100.1", r.TunnelEndpoint)
	}
	if r.TunnelID != 42 {
		t.Errorf("tunnel_id=%d, want 42", r.TunnelID)
	}
	if r.ExtendedTunnelID != "10.0.0.1" {
		t.Errorf("extended_tunnel_id=%q, want 10.0.0.1", r.ExtendedTunnelID)
	}

	// HOP
	if !r.HasHop {
		t.Error("expected has_hop=true")
	}
	if r.HopAddress != "10.1.1.1" {
		t.Errorf("hop_address=%q, want 10.1.1.1", r.HopAddress)
	}

	// TIME_VALUES
	if !r.HasTimeValues {
		t.Error("expected has_time_values=true")
	}
	if r.RefreshPeriodMs != 30000 {
		t.Errorf("refresh_period_ms=%d, want 30000", r.RefreshPeriodMs)
	}

	// SENDER_TEMPLATE
	if !r.HasSenderTemplate {
		t.Error("expected has_sender_template=true")
	}
	if r.SenderAddress != "10.0.0.1" {
		t.Errorf("sender_address=%q, want 10.0.0.1", r.SenderAddress)
	}
	if r.LSPID != 100 {
		t.Errorf("lsp_id=%d, want 100", r.LSPID)
	}

	// ERO
	if !r.HasERO {
		t.Error("expected has_ero=true")
	}
	if r.EROHopCount != 2 {
		t.Errorf("ero_hop_count=%d, want 2", r.EROHopCount)
	}
	if len(r.EROHops) != 2 {
		t.Fatalf("len(ero_hops)=%d, want 2", len(r.EROHops))
	}
	if r.EROHops[0].Address != "10.1.1.2" {
		t.Errorf("ero_hops[0].address=%q, want 10.1.1.2", r.EROHops[0].Address)
	}
	if r.EROHops[0].PrefixLength != 32 {
		t.Errorf("ero_hops[0].prefix_length=%d, want 32", r.EROHops[0].PrefixLength)
	}
	if r.EROHops[0].Loose {
		t.Error("ero_hops[0].loose: expected false (strict)")
	}
	if r.EROHops[1].Address != "10.2.2.2" {
		t.Errorf("ero_hops[1].address=%q, want 10.2.2.2", r.EROHops[1].Address)
	}
	if !r.EROHops[1].Loose {
		t.Error("ero_hops[1].loose: expected true (loose)")
	}

	// LABEL_REQUEST
	if !r.HasLabelRequest {
		t.Error("expected has_label_request=true")
	}
	if r.L3PID != 0x0800 {
		t.Errorf("l3pid=0x%04x, want 0x0800", r.L3PID)
	}

	// SESSION_ATTRIBUTE
	if !r.HasSessionAttribute {
		t.Error("expected has_session_attribute=true")
	}
	if r.SetupPriority != 7 {
		t.Errorf("setup_priority=%d, want 7", r.SetupPriority)
	}
	if r.HoldingPriority != 0 {
		t.Errorf("holding_priority=%d, want 0", r.HoldingPriority)
	}
	if r.SessionName != "test-lsp" {
		t.Errorf("session_name=%q, want test-lsp", r.SessionName)
	}

	// Object count: SESSION + HOP + TIME_VALUES + SENDER_TEMPLATE + ERO +
	// LABEL_REQUEST + SESSION_ATTRIBUTE = 7
	if r.ObjectCount != 7 {
		t.Errorf("object_count=%d, want 7", r.ObjectCount)
	}
}

// TestDecode_ResvMessage tests a Resv message containing a LABEL object.
func TestDecode_ResvMessage(t *testing.T) {
	pkt := buildResvPacket()
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatal(err)
	}
	if r.MsgTypeName != "Resv" {
		t.Errorf("msg_type_name=%q, want Resv", r.MsgTypeName)
	}
	if !r.IsResv {
		t.Error("expected is_resv=true")
	}
	if r.IsPath {
		t.Error("unexpected is_path=true")
	}
	if !r.HasLabel {
		t.Error("expected has_label=true")
	}
	if r.LabelValue != 3000 {
		t.Errorf("label_value=%d, want 3000", r.LabelValue)
	}
	if !r.HasSession {
		t.Error("expected has_session=true")
	}
	if r.TunnelID != 42 {
		t.Errorf("tunnel_id=%d, want 42", r.TunnelID)
	}
}

// TestDecode_HelloMessage tests a Hello message header decode.
func TestDecode_HelloMessage(t *testing.T) {
	pkt := buildHelloPacket()
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatal(err)
	}
	if r.MsgTypeName != "Hello" {
		t.Errorf("msg_type_name=%q, want Hello", r.MsgTypeName)
	}
	if !r.IsHello {
		t.Error("expected is_hello=true")
	}
	if r.IsPath || r.IsResv || r.IsPathTear || r.IsResvTear {
		t.Error("unexpected classification flag set on Hello")
	}
	if r.ObjectCount != 0 {
		t.Errorf("object_count=%d, want 0", r.ObjectCount)
	}
	if r.Version != 1 {
		t.Errorf("version=%d, want 1", r.Version)
	}
	if r.SendTTL != 255 {
		t.Errorf("send_ttl=%d, want 255", r.SendTTL)
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
// header returns an error.
func TestDecode_RejectsTruncated(t *testing.T) {
	_, err := Decode("10010000") // 4 bytes, below 8-byte minimum
	if err == nil {
		t.Fatal("want error for truncated input")
	}
}

// TestDecode_SeparatorTolerance verifies that colon-separated hex is accepted.
func TestDecode_SeparatorTolerance(t *testing.T) {
	pkt := buildHelloPacket()
	raw := hex.EncodeToString(pkt)
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
	if r.MsgTypeName != "Hello" {
		t.Errorf("msg_type_name=%q, want Hello", r.MsgTypeName)
	}
}

// TestDecode_MsgTypeNames verifies the message type name table for all
// documented RSVP-TE message types.
func TestDecode_MsgTypeNames(t *testing.T) {
	cases := []struct {
		msgType  int
		wantName string
	}{
		{1, "Path"},
		{2, "Resv"},
		{3, "PathErr"},
		{4, "ResvErr"},
		{5, "PathTear"},
		{6, "ResvTear"},
		{7, "ResvConf"},
		{10, "Bundle"},
		{12, "Hello"},
		{13, "Srefresh"},
		{20, "Notify"},
		{99, "msg_type_99"},
	}
	for _, tc := range cases {
		got := msgTypeName(tc.msgType)
		if got != tc.wantName {
			t.Errorf("msgTypeName(%d)=%q, want %q", tc.msgType, got, tc.wantName)
		}
	}
}

// TestDecode_PathTear verifies that a PathTear message sets is_path_tear.
func TestDecode_PathTear(t *testing.T) {
	hdr := rsvpHeader(5 /* PathTear */, 64, uint16(rsvpHeaderSize))
	r, err := Decode(hex.EncodeToString(hdr))
	if err != nil {
		t.Fatal(err)
	}
	if !r.IsPathTear {
		t.Error("expected is_path_tear=true")
	}
	if r.IsPath || r.IsResv {
		t.Error("unexpected classification flag set")
	}
}

// TestDecode_ResvTear verifies that a ResvTear message sets is_resv_tear.
func TestDecode_ResvTear(t *testing.T) {
	hdr := rsvpHeader(6 /* ResvTear */, 64, uint16(rsvpHeaderSize))
	r, err := Decode(hex.EncodeToString(hdr))
	if err != nil {
		t.Fatal(err)
	}
	if !r.IsResvTear {
		t.Error("expected is_resv_tear=true")
	}
}
