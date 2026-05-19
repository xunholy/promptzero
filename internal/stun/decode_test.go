package stun

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

// TestDecode_BindingRequest pins a typical STUN Binding
// Request with a USERNAME + SOFTWARE attribute.
func TestDecode_BindingRequest(t *testing.T) {
	pkt := buildBindingRequest(t, []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06})
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.MethodName != "Binding" {
		t.Errorf("MethodName = %q", got.MethodName)
	}
	if got.MessageClassName != "Request" {
		t.Errorf("MessageClassName = %q", got.MessageClassName)
	}
	if got.MagicCookieHex != "0x2112A442" {
		t.Errorf("MagicCookieHex = %q", got.MagicCookieHex)
	}
	if got.TransactionIDHex != "AABBCCDDEEFF010203040506" {
		t.Errorf("TransactionIDHex = %q", got.TransactionIDHex)
	}
	// Verify USERNAME + SOFTWARE attributes
	var username, software *Attribute
	for _, a := range got.Attributes {
		switch a.Type {
		case 0x0006:
			username = a
		case 0x8022:
			software = a
		}
	}
	if username == nil || username.String != "alice@example.com" {
		t.Errorf("USERNAME = %v", username)
	}
	if software == nil || software.String != "PromptZero/test" {
		t.Errorf("SOFTWARE = %v", software)
	}
}

// TestDecode_BindingResponse_XORMappedAddress pins a STUN
// Binding Success Response with an XOR-MAPPED-ADDRESS that
// correctly un-XORs to the real client IP + port.
func TestDecode_BindingResponse_XORMappedAddress(t *testing.T) {
	txID := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C}
	realIP := net.ParseIP("192.0.2.100").To4()
	realPort := uint16(12345)
	pkt := buildBindingResponseXOR(t, txID, realIP, realPort)
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.MessageClassName != "Success Response" {
		t.Errorf("MessageClassName = %q", got.MessageClassName)
	}
	var xma *Attribute
	for _, a := range got.Attributes {
		if a.Type == 0x0020 {
			xma = a
			break
		}
	}
	if xma == nil {
		t.Fatal("XOR-MAPPED-ADDRESS not found")
	}
	if xma.XORAddress == nil {
		t.Fatal("XORAddress nil")
	}
	if xma.XORAddress.IP != "192.0.2.100" {
		t.Errorf("XORAddress.IP = %q; want 192.0.2.100", xma.XORAddress.IP)
	}
	if xma.XORAddress.Port != int(realPort) {
		t.Errorf("XORAddress.Port = %d; want %d", xma.XORAddress.Port, realPort)
	}
}

// TestDecode_BindingError_ErrorCode pins a Binding Error
// Response with an ERROR-CODE attribute (401 Unauthenticated).
func TestDecode_BindingError_ErrorCode(t *testing.T) {
	txID := make([]byte, 12)
	for i := range txID {
		txID[i] = byte(i)
	}
	// Build header: message type for Binding Error Response =
	// class bits 11 + method 0x001 = 0x0111
	hdr := make([]byte, 20)
	binary.BigEndian.PutUint16(hdr[0:2], 0x0111)
	binary.BigEndian.PutUint32(hdr[4:8], magicCookie)
	copy(hdr[8:20], txID)

	// ERROR-CODE attribute: type 0x0009, len = 4 + reason
	reason := "Unauthenticated"
	body := []byte{0x00, 0x00, 0x04, 0x01} // reserved + class 4 + number 01 (= 401)
	body = append(body, []byte(reason)...)
	attr := make([]byte, 4+len(body))
	binary.BigEndian.PutUint16(attr[0:2], 0x0009)
	binary.BigEndian.PutUint16(attr[2:4], uint16(len(body)))
	copy(attr[4:], body)
	// Pad to 4-byte boundary
	for len(attr)%4 != 0 {
		attr = append(attr, 0x00)
	}
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(attr)))
	pkt := append(hdr, attr...)

	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.MessageClassName != "Error Response" {
		t.Errorf("MessageClassName = %q", got.MessageClassName)
	}
	var ec *Attribute
	for _, a := range got.Attributes {
		if a.Type == 0x0009 {
			ec = a
			break
		}
	}
	if ec == nil || ec.ErrorCode == nil {
		t.Fatal("ERROR-CODE not found")
	}
	if ec.ErrorCode.Code != 401 {
		t.Errorf("ErrorCode.Code = %d", ec.ErrorCode.Code)
	}
	if ec.ErrorCode.Name != "Unauthenticated" {
		t.Errorf("ErrorCode.Name = %q", ec.ErrorCode.Name)
	}
	if ec.ErrorCode.Reason != "Unauthenticated" {
		t.Errorf("ErrorCode.Reason = %q", ec.ErrorCode.Reason)
	}
}

// TestDecode_TURN_Allocate pins an Allocate request (method
// 0x003) with REQUESTED-TRANSPORT = UDP.
func TestDecode_TURN_Allocate(t *testing.T) {
	hdr := make([]byte, 20)
	// Allocate Request: method 0x003 + class 0x00.
	// Per RFC 5389 §6 encoding: bits arranged as M11..C0..
	// For method=0x003 + class=0, type = 0x0003.
	binary.BigEndian.PutUint16(hdr[0:2], 0x0003)
	binary.BigEndian.PutUint32(hdr[4:8], magicCookie)
	for i := 8; i < 20; i++ {
		hdr[i] = byte(i)
	}
	// REQUESTED-TRANSPORT = UDP (17 in top byte)
	rtBody := []byte{17, 0, 0, 0}
	rt := []byte{0x00, 0x19, 0x00, 0x04}
	rt = append(rt, rtBody...)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(rt)))
	pkt := append(hdr, rt...)
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.MethodName != "Allocate (TURN)" {
		t.Errorf("MethodName = %q", got.MethodName)
	}
	var rtAttr *Attribute
	for _, a := range got.Attributes {
		if a.Type == 0x0019 {
			rtAttr = a
			break
		}
	}
	if rtAttr == nil {
		t.Fatal("REQUESTED-TRANSPORT not found")
	}
	if rtAttr.UInt32Name != "UDP" {
		t.Errorf("REQUESTED-TRANSPORT name = %q; want 'UDP'", rtAttr.UInt32Name)
	}
}

// TestDecode_BadMagicCookie rejects a packet with the wrong
// magic cookie.
func TestDecode_BadMagicCookie(t *testing.T) {
	hdr := make([]byte, 20)
	binary.BigEndian.PutUint16(hdr[0:2], 0x0001)
	binary.BigEndian.PutUint32(hdr[4:8], 0xDEADBEEF) // wrong cookie
	if _, err := DecodeBytes(hdr); err == nil {
		t.Error("bad magic cookie: want error")
	}
}

// TestDecode_TooShort rejects packets < 20 bytes.
func TestDecode_TooShort(t *testing.T) {
	if _, err := Decode("00 01 02 03"); err == nil {
		t.Error("4-byte input: want error")
	}
}

// TestDecode_TopBitsNonZero rejects packets where the top 2
// bits of the message type are non-zero (likely TURN
// ChannelData).
func TestDecode_TopBitsNonZero(t *testing.T) {
	hdr := make([]byte, 20)
	hdr[0] = 0x40 // top bit set
	binary.BigEndian.PutUint32(hdr[4:8], magicCookie)
	if _, err := DecodeBytes(hdr); err == nil {
		t.Error("top bits non-zero: want error")
	}
}

// TestDecode_BadHex rejects garbage.
func TestDecode_BadHex(t *testing.T) {
	if _, err := Decode(""); err == nil {
		t.Error("empty: want error")
	}
	if _, err := Decode("ZZ"); err == nil {
		t.Error("invalid hex: want error")
	}
}

// TestSplitMessageType pins the bit-encoding gymnastics
// per RFC 5389 §6.
func TestSplitMessageType(t *testing.T) {
	cases := []struct {
		mt         int
		wantMethod int
		wantClass  int
	}{
		{0x0001, 0x001, 0}, // Binding Request
		{0x0101, 0x001, 2}, // Binding Success Response
		{0x0111, 0x001, 3}, // Binding Error Response
		{0x0003, 0x003, 0}, // Allocate Request
		{0x0113, 0x003, 3}, // Allocate Error Response
	}
	for _, c := range cases {
		m, cl := splitMessageType(c.mt)
		if m != c.wantMethod {
			t.Errorf("mt 0x%04X: method = 0x%03X; want 0x%03X", c.mt, m, c.wantMethod)
		}
		if cl != c.wantClass {
			t.Errorf("mt 0x%04X: class = %d; want %d", c.mt, cl, c.wantClass)
		}
	}
}

// TestAttributeNameTable spot-checks.
func TestAttributeNameTable(t *testing.T) {
	cases := map[int]string{
		0x0001: "MAPPED-ADDRESS",
		0x0006: "USERNAME",
		0x0008: "MESSAGE-INTEGRITY (HMAC-SHA1)",
		0x0009: "ERROR-CODE",
		0x000C: "CHANNEL-NUMBER (TURN)",
		0x0014: "REALM",
		0x0020: "XOR-MAPPED-ADDRESS",
		0x8022: "SOFTWARE",
		0x8028: "FINGERPRINT (CRC-32)",
		0x802A: "ICE-CONTROLLING (ICE)",
	}
	for typ, want := range cases {
		if got := attributeName(typ); got != want {
			t.Errorf("attributeName(0x%04X) = %q; want %q", typ, got, want)
		}
	}
}

// TestErrorCodeNameTable spot-checks.
func TestErrorCodeNameTable(t *testing.T) {
	cases := map[int]string{
		300: "Try Alternate",
		400: "Bad Request",
		401: "Unauthenticated",
		420: "Unknown Attribute",
		438: "Stale Nonce",
		500: "Server Error",
	}
	for c, want := range cases {
		if got := errorCodeName(c); got != want {
			t.Errorf("errorCodeName(%d) = %q; want %q", c, got, want)
		}
	}
}

// TestDecode_MappedAddress_IPv4 pins a plain (non-XOR)
// MAPPED-ADDRESS decode.
func TestDecode_MappedAddress_IPv4(t *testing.T) {
	hdr := make([]byte, 20)
	binary.BigEndian.PutUint16(hdr[0:2], 0x0001)
	binary.BigEndian.PutUint32(hdr[4:8], magicCookie)
	// MAPPED-ADDRESS: family=1, port=8080, IP=203.0.113.5
	body := []byte{0x00, 0x01, 0x1F, 0x90, 203, 0, 113, 5}
	attr := []byte{0x00, 0x01, 0x00, 0x08}
	attr = append(attr, body...)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(attr)))
	pkt := append(hdr, attr...)
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	a := got.Attributes[0]
	if a.MappedAddress == nil {
		t.Fatal("MappedAddress nil")
	}
	if a.MappedAddress.IP != "203.0.113.5" {
		t.Errorf("IP = %q", a.MappedAddress.IP)
	}
	if a.MappedAddress.Port != 8080 {
		t.Errorf("Port = %d", a.MappedAddress.Port)
	}
}

// --- test helpers --------------------------------------------------

func buildBindingRequest(t *testing.T, txID []byte) []byte {
	t.Helper()
	hdr := make([]byte, 20)
	binary.BigEndian.PutUint16(hdr[0:2], 0x0001) // Binding Request
	binary.BigEndian.PutUint32(hdr[4:8], magicCookie)
	copy(hdr[8:20], txID)

	// USERNAME = "alice@example.com" (17 bytes, padded to 20)
	username := []byte("alice@example.com")
	user := []byte{0x00, 0x06}
	user = append(user, []byte{0x00, byte(len(username))}...)
	user = append(user, username...)
	for len(user)%4 != 0 {
		user = append(user, 0x00)
	}

	// SOFTWARE = "PromptZero/test" (15 bytes, padded to 16)
	soft := []byte("PromptZero/test")
	softw := []byte{0x80, 0x22}
	softw = append(softw, []byte{0x00, byte(len(soft))}...)
	softw = append(softw, soft...)
	for len(softw)%4 != 0 {
		softw = append(softw, 0x00)
	}

	attrs := append(user, softw...)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(attrs)))
	return append(hdr, attrs...)
}

func buildBindingResponseXOR(t *testing.T, txID []byte, ip net.IP, port uint16) []byte {
	t.Helper()
	hdr := make([]byte, 20)
	// Binding Success Response = method 0x001 + class 0x02 = 0x0101
	binary.BigEndian.PutUint16(hdr[0:2], 0x0101)
	binary.BigEndian.PutUint32(hdr[4:8], magicCookie)
	copy(hdr[8:20], txID)

	// XOR-MAPPED-ADDRESS body: 0x00 (reserved) + family + xor-port + xor-ip
	cookie := uint32(magicCookie)
	xorPort := port ^ uint16(cookie>>16)
	xorIP := make([]byte, 4)
	xorIP[0] = ip[0] ^ byte(cookie>>24)
	xorIP[1] = ip[1] ^ byte(cookie>>16)
	xorIP[2] = ip[2] ^ byte(cookie>>8)
	xorIP[3] = ip[3] ^ byte(cookie)

	body := []byte{0x00, 0x01}
	body = append(body, byte(xorPort>>8), byte(xorPort))
	body = append(body, xorIP...)

	attr := []byte{0x00, 0x20, 0x00, 0x08}
	attr = append(attr, body...)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(attr)))
	return append(hdr, attr...)
}

// Stub usage to silence unused import warnings if any test
// is removed during refactoring.
var _ = strings.HasPrefix
