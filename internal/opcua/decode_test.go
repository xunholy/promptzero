package opcua

import (
	"fmt"
	"strings"
	"testing"
)

// TestDecodeHello pins a canonical HEL message — the first
// message in every OPC UA Binary session.
func TestDecodeHello(t *testing.T) {
	// Header: "HEL" + "F" + MessageSize=0x32 (50 bytes total).
	// Body: ProtocolVersion=0, ReceiveBufferSize=0x10000 (65536),
	// SendBufferSize=0x10000, MaxMessageSize=0x4000000,
	// MaxChunkCount=0; EndpointURL="opc.tcp://srv:4840" (18 bytes).
	// Total = header (8) + body (5*4 + 4 + 18) = 50 = 0x32.
	url := "opc.tcp://srv:4840"
	urlBytes := []byte(url)
	if len(urlBytes) != 18 {
		t.Fatalf("URL len = %d, expected 18", len(urlBytes))
	}
	in := "48454C46 32000000 " + // "HEL" + "F" + size 0x32 LE
		"00000000 00000100 00000100 00000004 00000000 " +
		// Five LE uint32: 0, 65536, 65536, 67108864, 0
		"12000000 " + // URL length 18 LE
		"6F70632E7463703A2F2F7372763A34383430" // URL UTF-8 bytes
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.MessageType != "HEL" || r.MessageTypeName != "Hello" {
		t.Errorf("messageType: got %q/%q want HEL/Hello",
			r.MessageType, r.MessageTypeName)
	}
	if r.ChunkType != "F" || r.ChunkTypeName != "Final" {
		t.Errorf("chunkType: got %q/%q want F/Final",
			r.ChunkType, r.ChunkTypeName)
	}
	if r.MessageSize != 0x32 {
		t.Errorf("messageSize: got %d want 50", r.MessageSize)
	}
	if r.ReceiveBufferSize != 65536 {
		t.Errorf("recvBuf: got %d want 65536", r.ReceiveBufferSize)
	}
	if r.SendBufferSize != 65536 {
		t.Errorf("sendBuf: got %d want 65536", r.SendBufferSize)
	}
	if r.MaxMessageSize != 67108864 {
		t.Errorf("maxMsg: got %d want 67108864", r.MaxMessageSize)
	}
	if r.EndpointURL != url {
		t.Errorf("endpointURL: got %q want %q", r.EndpointURL, url)
	}
}

// TestDecodeAcknowledge pins a canonical ACK — server agrees on
// buffer sizes.
func TestDecodeAcknowledge(t *testing.T) {
	in := "41434B46 1C000000 " + // "ACK" + "F" + size 0x1C = 28
		"00000000 00000100 00000100 00000004 00000000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.MessageTypeName != "Acknowledge" {
		t.Errorf("messageType: got %q want Acknowledge", r.MessageTypeName)
	}
	if r.ReceiveBufferSize != 65536 {
		t.Errorf("recvBuf: got %d want 65536", r.ReceiveBufferSize)
	}
	if r.EndpointURL != "" {
		t.Errorf("ACK should not carry URL, got %q", r.EndpointURL)
	}
}

// TestDecodeError pins an ERR — server returns a status code +
// reason.
func TestDecodeError(t *testing.T) {
	// "ERR" + "F" + size 0x18 (24); StatusCode = 0x80020000
	// (BadInternalError); Reason = "fail" (4 bytes).
	in := "45525246 18000000 " +
		"00000280 " + // StatusCode 0x80020000 LE
		"04000000 66 61 69 6C" // Reason length 4 + "fail"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.MessageTypeName != "Error" {
		t.Errorf("messageType: got %q want Error", r.MessageTypeName)
	}
	if r.StatusCodeHex != "0x80020000" {
		t.Errorf("statusCode: got %q want 0x80020000", r.StatusCodeHex)
	}
	if r.Reason != "fail" {
		t.Errorf("reason: got %q want fail", r.Reason)
	}
}

// TestDecodeOpenSecureChannel pins an OPN with full security
// header.
func TestDecodeOpenSecureChannel(t *testing.T) {
	// SecureChannelID = 0x000001A4 (420);
	// SecurityPolicyURI = "http://opcfoundation.org/UA/SecurityPolicy#None"
	// (47 bytes);
	// SenderCertificate = null (length -1);
	// ReceiverThumbprint = null (length -1);
	// SequenceNumber = 1; RequestID = 1.
	// Service body = 6 trailing opaque bytes AABBCCDDEEFF.
	uri := "http://opcfoundation.org/UA/SecurityPolicy#None"
	if len(uri) != 47 {
		t.Fatalf("URI len = %d, expected 47", len(uri))
	}
	uriHex := ""
	for _, c := range uri {
		uriHex += fmt.Sprintf("%02X", byte(c))
	}
	// MessageSize = 8 (hdr) + 4 (ChannelID) + 4+47 (URI) +
	// 4 (null sender cert) + 4 (null thumb) + 4+4 (seq+req) +
	// 6 (body) = 85 = 0x55.
	in := "4F504E46 55000000 " +
		"A4010000 " + // SecureChannelID = 0x1A4 = 420
		"2F000000 " + uriHex + " " + // URI length 47 + bytes
		"FFFFFFFF " + // SenderCertificate length -1 (null)
		"FFFFFFFF " + // ReceiverThumbprint length -1 (null)
		"01000000 01000000 " + // SequenceNumber + RequestID
		"AABBCCDDEEFF"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.MessageTypeName != "OpenSecureChannel" {
		t.Errorf("messageType: got %q want OpenSecureChannel", r.MessageTypeName)
	}
	if r.SecureChannelID != 420 {
		t.Errorf("secureChannelID: got %d want 420", r.SecureChannelID)
	}
	if r.SecurityPolicyURI != uri {
		t.Errorf("securityPolicyURI: got %q want %q", r.SecurityPolicyURI, uri)
	}
	if r.SequenceNumber != 1 || r.RequestID != 1 {
		t.Errorf("seq/req: got %d/%d want 1/1", r.SequenceNumber, r.RequestID)
	}
	if r.ServiceBodyHex != "AABBCCDDEEFF" {
		t.Errorf("serviceBody: got %q want AABBCCDDEEFF", r.ServiceBodyHex)
	}
}

// TestDecodeMessage pins a symmetric MSG with TokenId and
// trailing service body.
func TestDecodeMessage(t *testing.T) {
	// SecureChannelID = 0x000001A4; TokenId = 5; Sequence = 100;
	// RequestId = 7; body = "ABCDEFGH" (8 bytes).
	in := "4D534746 20000000 " + // "MSG" + "F" + size 32
		"A4010000 05000000 64000000 07000000 " +
		"4142434445464748"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.MessageTypeName != "Message" {
		t.Errorf("messageType: got %q want Message", r.MessageTypeName)
	}
	if r.SecureChannelID != 0x1A4 {
		t.Errorf("secureChannelID: got 0x%X want 0x1A4", r.SecureChannelID)
	}
	if r.TokenID != 5 {
		t.Errorf("tokenID: got %d want 5", r.TokenID)
	}
	if r.SequenceNumber != 100 {
		t.Errorf("seq: got %d want 100", r.SequenceNumber)
	}
	if r.RequestID != 7 {
		t.Errorf("requestID: got %d want 7", r.RequestID)
	}
	if r.ServiceBodyHex != "4142434445464748" {
		t.Errorf("serviceBody: got %q want 4142434445464748", r.ServiceBodyHex)
	}
}

// TestDecodeClose pins a CLO (CloseSecureChannel) message —
// same symmetric header as MSG.
func TestDecodeClose(t *testing.T) {
	in := "434C4F46 10000000 " + // "CLO" + "F" + size 16
		"A4010000 05000000 64000000 07000000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.MessageTypeName != "CloseSecureChannel" {
		t.Errorf("messageType: got %q want CloseSecureChannel", r.MessageTypeName)
	}
	if r.TokenID != 5 || r.SequenceNumber != 100 || r.RequestID != 7 {
		t.Errorf("symmetric header fields: got %d/%d/%d",
			r.TokenID, r.SequenceNumber, r.RequestID)
	}
}

// TestDecodeChunkTypes covers each catalogued chunk type.
func TestDecodeChunkTypes(t *testing.T) {
	cases := map[string]string{
		"F": "Final",
		"C": "Intermediate",
		"A": "Abort",
	}
	for k, v := range cases {
		if got := chunkTypeName(k); got != v {
			t.Errorf("chunkTypeName(%q) = %q want %q", k, got, v)
		}
	}
	if !strings.HasPrefix(chunkTypeName("X"), "uncatalogued") {
		t.Errorf("uncatalogued chunk type should be flagged")
	}
}

// TestMessageTypeNameTable covers each catalogued message type.
func TestMessageTypeNameTable(t *testing.T) {
	cases := map[string]string{
		"HEL": "Hello", "ACK": "Acknowledge", "ERR": "Error",
		"MSG": "Message", "OPN": "OpenSecureChannel",
		"CLO": "CloseSecureChannel", "RHE": "ReverseHello",
	}
	for k, v := range cases {
		if got := messageTypeName(k); got != v {
			t.Errorf("messageTypeName(%q) = %q want %q", k, got, v)
		}
	}
	if !strings.HasPrefix(messageTypeName("XYZ"), "uncatalogued") {
		t.Errorf("uncatalogued message type should be flagged")
	}
}

// TestReadUAStringNull pins null-string handling (length = -1).
func TestReadUAStringNull(t *testing.T) {
	b := []byte{0xFF, 0xFF, 0xFF, 0xFF}
	s, n := readUAString(b)
	if s != "" || n != 4 {
		t.Errorf("null string: got (%q,%d) want (\"\",4)", s, n)
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
	if _, err := Decode("48454C46"); err == nil {
		t.Fatal("want error for short header")
	}
}

func TestDecodeRejectsBadHex(t *testing.T) {
	if _, err := Decode("ZZ" + strings.Repeat("00", 7)); err == nil {
		t.Fatal("want error for non-hex chars")
	}
}
