package wireguard

import (
	"strings"
	"testing"
)

// makeBytes returns a hex string of the given length filled
// with byte b.
func makeBytes(n int, b byte) string {
	const digits = "0123456789ABCDEF"
	out := make([]byte, n*2)
	for i := 0; i < n; i++ {
		out[i*2] = digits[b>>4]
		out[i*2+1] = digits[b&0x0F]
	}
	return string(out)
}

func TestDecode_HandshakeInitiation(t *testing.T) {
	// Type 1, reserved 0, sender_index = 0x11223344 (LE: 44332211),
	// ephemeral 32 bytes of 0xAA, encrypted_static 48 bytes of
	// 0xBB, encrypted_timestamp 28 bytes of 0xCC, MAC1 16 bytes
	// of 0xDD, MAC2 16 bytes of zero (no cookie).
	in := "01" + "000000" + "44332211" +
		makeBytes(32, 0xAA) +
		makeBytes(48, 0xBB) +
		makeBytes(28, 0xCC) +
		makeBytes(16, 0xDD) +
		makeBytes(16, 0x00)
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MessageType != 1 || r.MessageTypeName != "Handshake Initiation" {
		t.Errorf("type: %d %q", r.MessageType, r.MessageTypeName)
	}
	if r.Initiation == nil {
		t.Fatal("Initiation nil")
	}
	if r.Initiation.SenderIndex != 0x11223344 {
		t.Errorf("sender_index: 0x%08X", r.Initiation.SenderIndex)
	}
	if !r.Initiation.MAC2Zero {
		t.Errorf("MAC2 should be detected as zero")
	}
	if r.Initiation.EphemeralPubKeyHex != strings.Repeat("AA", 32) {
		t.Errorf("ephemeral key mismatch")
	}
	// One note about MAC2 being zero.
	if len(r.Notes) != 1 {
		t.Errorf("expected 1 note, got %v", r.Notes)
	}
}

func TestDecode_HandshakeResponse(t *testing.T) {
	// Type 2, sender_index 0x55667788, receiver_index 0x99AABBCC,
	// ephemeral 32 bytes of 0x11, encrypted_nothing 16 bytes of
	// 0x22, MAC1 16 bytes of 0x33, MAC2 16 bytes of 0x44 (with
	// cookie applied).
	in := "02" + "000000" + "88776655" + "CCBBAA99" +
		makeBytes(32, 0x11) +
		makeBytes(16, 0x22) +
		makeBytes(16, 0x33) +
		makeBytes(16, 0x44)
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MessageType != 2 {
		t.Fatalf("type: %d", r.MessageType)
	}
	if r.Response.SenderIndex != 0x55667788 {
		t.Errorf("sender_index: 0x%08X", r.Response.SenderIndex)
	}
	if r.Response.ReceiverIndex != 0x99AABBCC {
		t.Errorf("receiver_index: 0x%08X", r.Response.ReceiverIndex)
	}
	if r.Response.MAC2Zero {
		t.Errorf("MAC2 should NOT be detected as zero")
	}
}

func TestDecode_CookieReply(t *testing.T) {
	// Type 3, receiver_index 0xDEADBEEF, nonce 24 bytes of 0x55,
	// encrypted_cookie 32 bytes of 0x66.
	in := "03" + "000000" + "EFBEADDE" +
		makeBytes(24, 0x55) +
		makeBytes(32, 0x66)
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MessageType != 3 {
		t.Fatalf("type: %d", r.MessageType)
	}
	if r.Cookie.ReceiverIndex != 0xDEADBEEF {
		t.Errorf("receiver_index: 0x%08X", r.Cookie.ReceiverIndex)
	}
	if r.Cookie.NonceHex != strings.Repeat("55", 24) {
		t.Errorf("nonce mismatch")
	}
	if r.Cookie.EncryptedCookie != strings.Repeat("66", 32) {
		t.Errorf("encrypted cookie mismatch")
	}
}

func TestDecode_TransportData(t *testing.T) {
	// Type 4, receiver_index 0xCAFEBABE, counter 12345.
	// Encrypted payload: 32 bytes inner plaintext + 16 byte tag = 48.
	in := "04" + "000000" + "BEBAFECA" +
		"3930000000000000" + // counter 12345 LE
		makeBytes(32, 0x77) +
		makeBytes(16, 0x99)
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Transport.Counter != 12345 {
		t.Errorf("counter: %d", r.Transport.Counter)
	}
	if r.Transport.ReceiverIndex != 0xCAFEBABE {
		t.Errorf("receiver_index: 0x%08X", r.Transport.ReceiverIndex)
	}
	if r.Transport.EncryptedPayloadLen != 48 {
		t.Errorf("encrypted_payload_len: %d", r.Transport.EncryptedPayloadLen)
	}
	if r.Transport.InnerPlaintextLen != 32 {
		t.Errorf("inner_plaintext_len: %d", r.Transport.InnerPlaintextLen)
	}
	if r.Transport.KeepAlive {
		t.Errorf("should NOT be keep-alive")
	}
}

func TestDecode_TransportKeepAlive(t *testing.T) {
	// Transport packet with empty inner plaintext — only the
	// 16-byte Poly1305 tag is present. This is a keep-alive.
	in := "04" + "000000" + "BEBAFECA" +
		"3930000000000000" + // counter 12345 LE
		makeBytes(16, 0x00) // just the AEAD tag
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Transport.InnerPlaintextLen != 0 {
		t.Errorf("inner length: %d", r.Transport.InnerPlaintextLen)
	}
	if !r.Transport.KeepAlive {
		t.Error("should be detected as keep-alive")
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "keep-alive") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected keep-alive note in %v", r.Notes)
	}
}

func TestDecode_ReservedNonZero(t *testing.T) {
	// Type 4 with non-zero reserved bytes (some forks abuse).
	in := "04" + "AABBCC" + "00000000" +
		"0000000000000000" +
		makeBytes(16, 0x00)
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.ReservedZero {
		t.Errorf("ReservedZero should be false")
	}
	if r.ReservedHex != "AABBCC" {
		t.Errorf("ReservedHex: %q", r.ReservedHex)
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "non-zero") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected non-zero note in %v", r.Notes)
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":               "",
		"odd hex":             "010",
		"bad hex":             "ZZ000000",
		"too short":           "010000",
		"init wrong len":      "01000000" + makeBytes(50, 0xAA),
		"response wrong len":  "02000000" + makeBytes(50, 0xAA),
		"cookie wrong len":    "03000000" + makeBytes(30, 0xAA),
		"transport too short": "04" + "000000" + "00000000" + "0000000000000000",
		"unknown type":        "05" + "000000" + makeBytes(50, 0xAA),
	}
	for name, in := range cases {
		_, err := Decode(in)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestMessageTypeName(t *testing.T) {
	cases := map[int]string{
		1: "Handshake Initiation",
		2: "Handshake Response",
		3: "Cookie Reply",
		4: "Transport Data",
	}
	for k, v := range cases {
		if got := messageTypeName(k); got != v {
			t.Errorf("messageTypeName(%d): got %q want %q", k, got, v)
		}
	}
	if !strings.Contains(messageTypeName(0xFF), "Unknown") {
		t.Errorf("unknown type fallback")
	}
}
