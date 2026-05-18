package eapol

import (
	"strings"
	"testing"
)

// makeFrame builds a synthetic 802.1X + EAPOL-Key frame for
// testing. The 95-byte EAPOL-Key body lives after the 4-byte
// header. ANonce is set to FE…FE (32 bytes), MIC to AA…AA (16
// bytes), KeyData to whatever the caller passes.
func makeFrame(t *testing.T, keyInfo uint16, keyData []byte) []byte {
	t.Helper()
	bodyLen := 95 + len(keyData)
	out := make([]byte, 4+bodyLen)
	// Header: version=2, type=3 (EAPOL-Key), body length BE
	out[0] = 0x02
	out[1] = 0x03
	out[2] = byte(bodyLen >> 8)
	out[3] = byte(bodyLen & 0xFF)
	// Descriptor type 2 (RSN)
	out[4] = 0x02
	// Key info (2 bytes BE)
	out[5] = byte(keyInfo >> 8)
	out[6] = byte(keyInfo & 0xFF)
	// Key length 16
	out[7] = 0x00
	out[8] = 0x10
	// Replay counter (8 bytes) — leave zero
	// ANonce: bytes 17..49, fill with 0xFE
	for i := 17; i < 49; i++ {
		out[i] = 0xFE
	}
	// MIC: bytes 81..97, fill with 0xAA
	for i := 81; i < 97; i++ {
		out[i] = 0xAA
	}
	// Key data length BE
	out[97] = byte(len(keyData) >> 8)
	out[98] = byte(len(keyData) & 0xFF)
	// Key data
	copy(out[99:], keyData)
	return out
}

// TestDecode_M1 — M1 has Ack=1 (0x0080), MIC=0, Install=0,
// Secure=0, KeyType=Pairwise (0x08), DescriptorVersion=2 (CCMP).
// Key info = 0x008A.
func TestDecode_M1(t *testing.T) {
	frame := makeFrame(t, 0x008A, nil)
	got, err := DecodeBytes(frame)
	if err != nil {
		t.Fatalf("DecodeBytes: %v", err)
	}
	if got.Header.TypeName != "EAPOL-Key" {
		t.Errorf("TypeName = %q; want 'EAPOL-Key'", got.Header.TypeName)
	}
	if got.DescriptorTypeName != "RSN (WPA2 / WPA3)" {
		t.Errorf("DescriptorTypeName = %q", got.DescriptorTypeName)
	}
	if got.KeyInfo.DescriptorVersion != 2 {
		t.Errorf("DescriptorVersion = %d; want 2 (CCMP)", got.KeyInfo.DescriptorVersion)
	}
	if got.KeyInfo.KeyType != 1 {
		t.Errorf("KeyType = %d; want 1 (Pairwise)", got.KeyInfo.KeyType)
	}
	if !got.KeyInfo.KeyAck {
		t.Error("KeyAck should be true for M1")
	}
	if got.KeyInfo.KeyMIC {
		t.Error("KeyMIC should be false for M1")
	}
	if got.HandshakeMessage != "M1" {
		t.Errorf("HandshakeMessage = %q; want 'M1'", got.HandshakeMessage)
	}
	// ANonce filled with 0xFE
	if !strings.HasPrefix(got.KeyNonce, "FEFEFEFE") {
		t.Errorf("KeyNonce = %s; want it to start with FEFEFEFE", got.KeyNonce[:8])
	}
}

// TestDecode_M2 — Ack=0, MIC=1 (0x0100), Install=0, Secure=0,
// KeyType=Pairwise. Key info = 0x010A.
func TestDecode_M2(t *testing.T) {
	frame := makeFrame(t, 0x010A, nil)
	got, err := DecodeBytes(frame)
	if err != nil {
		t.Fatalf("DecodeBytes: %v", err)
	}
	if got.HandshakeMessage != "M2" {
		t.Errorf("HandshakeMessage = %q; want 'M2'", got.HandshakeMessage)
	}
	if !got.KeyInfo.KeyMIC {
		t.Error("KeyMIC should be true for M2")
	}
	if got.KeyInfo.KeyAck {
		t.Error("KeyAck should be false for M2")
	}
}

// TestDecode_M3 — Ack=1, MIC=1, Install=1 (0x0040), Secure=1
// (0x0200), KeyType=Pairwise. Key info = 0x03CA.
func TestDecode_M3(t *testing.T) {
	frame := makeFrame(t, 0x03CA, nil)
	got, err := DecodeBytes(frame)
	if err != nil {
		t.Fatalf("DecodeBytes: %v", err)
	}
	if got.HandshakeMessage != "M3" {
		t.Errorf("HandshakeMessage = %q; want 'M3'", got.HandshakeMessage)
	}
	if !got.KeyInfo.Install {
		t.Error("Install should be true for M3")
	}
	if !got.KeyInfo.Secure {
		t.Error("Secure should be true for M3")
	}
}

// TestDecode_M4 — Ack=0, MIC=1, Install=0, Secure=1,
// KeyType=Pairwise. Key info = 0x030A.
func TestDecode_M4(t *testing.T) {
	frame := makeFrame(t, 0x030A, nil)
	got, err := DecodeBytes(frame)
	if err != nil {
		t.Fatalf("DecodeBytes: %v", err)
	}
	if got.HandshakeMessage != "M4" {
		t.Errorf("HandshakeMessage = %q; want 'M4'", got.HandshakeMessage)
	}
}

// TestDecode_RSNIE_InKeyData — M3 carries the RSN IE in its Key
// Data field. The walker should parse it as a single KDE with
// OUI "rsn".
func TestDecode_RSNIE_InKeyData(t *testing.T) {
	// RSN IE: 0x30 (element ID), 0x14 (length 20), then 20 bytes
	// of RSN body (version + group cipher + pairwise count +
	// pairwise cipher + AKM count + AKM + RSN capabilities).
	rsnIE := []byte{
		0x30, 0x14,
		0x01, 0x00, // RSN version
		0x00, 0x0F, 0xAC, 0x04, // Group: CCMP
		0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, // Pairwise: 1 × CCMP
		0x01, 0x00, 0x00, 0x0F, 0xAC, 0x02, // AKM: 1 × PSK
		0x00, 0x00, // RSN capabilities
	}
	frame := makeFrame(t, 0x03CA, rsnIE)
	got, err := DecodeBytes(frame)
	if err != nil {
		t.Fatalf("DecodeBytes: %v", err)
	}
	if got.HandshakeMessage != "M3" {
		t.Fatalf("expected M3, got %q", got.HandshakeMessage)
	}
	if got.KeyDataLength != len(rsnIE) {
		t.Errorf("KeyDataLength = %d; want %d", got.KeyDataLength, len(rsnIE))
	}
	if len(got.KDEs) != 1 {
		t.Fatalf("KDEs count = %d; want 1", len(got.KDEs))
	}
	kde := got.KDEs[0]
	if kde.OUI != "rsn" {
		t.Errorf("KDE OUI = %q; want 'rsn'", kde.OUI)
	}
	if kde.TypeName != "RSN Information Element" {
		t.Errorf("KDE TypeName = %q", kde.TypeName)
	}
}

// TestDecode_GTKKDE_InKeyData — group-key handshake KDE: vendor
// header 0xDD + length, then OUI 00-0F-AC + type 1 (GTK) +
// KeyID/Tx + reserved + actual GTK bytes.
func TestDecode_GTKKDE_InKeyData(t *testing.T) {
	// KDE: 0xDD, 0x16 (length 22), 00 0F AC 01 (OUI + type=GTK),
	// 00 00 (Key ID + reserved), then 16 bytes of GTK.
	gtk := []byte{
		0xDD, 0x16,
		0x00, 0x0F, 0xAC, 0x01,
		0x00, 0x00,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
	}
	frame := makeFrame(t, 0x03CA, gtk)
	got, err := DecodeBytes(frame)
	if err != nil {
		t.Fatalf("DecodeBytes: %v", err)
	}
	if len(got.KDEs) != 1 {
		t.Fatalf("KDEs count = %d; want 1", len(got.KDEs))
	}
	kde := got.KDEs[0]
	if kde.OUI != "000FAC" {
		t.Errorf("KDE OUI = %q; want '000FAC'", kde.OUI)
	}
	if kde.DataType != 1 {
		t.Errorf("KDE DataType = %d; want 1 (GTK)", kde.DataType)
	}
	if kde.TypeName != "GTK" {
		t.Errorf("KDE TypeName = %q; want 'GTK'", kde.TypeName)
	}
}

// TestDecode_EncryptedKeyDataSkipsKDEs — when the encrypted
// flag (bit 12 = 0x1000) is set, the Key Data field is opaque;
// we should not try to walk KDEs.
func TestDecode_EncryptedKeyDataSkipsKDEs(t *testing.T) {
	frame := makeFrame(t, 0x13CA, []byte{0xDD, 0x16, 0x00, 0x0F, 0xAC, 0x01, 0x00, 0x00})
	got, err := DecodeBytes(frame)
	if err != nil {
		t.Fatalf("DecodeBytes: %v", err)
	}
	if !got.KeyInfo.EncryptedKeyData {
		t.Error("EncryptedKeyData flag should be set")
	}
	if got.KDEs != nil {
		t.Errorf("KDEs = %v; want nil when EncryptedKeyData is set", got.KDEs)
	}
	if got.KeyData == "" {
		t.Error("KeyData should be populated even when encrypted")
	}
}

// TestDecode_NonKeyFrameRejected — a frame whose type byte isn't
// 0x03 (EAPOL-Key) returns an operator-facing error.
func TestDecode_NonKeyFrameRejected(t *testing.T) {
	// Header: version=2, type=1 (EAPOL-Start), body length 0
	_, err := DecodeBytes([]byte{0x02, 0x01, 0x00, 0x00})
	if err == nil {
		t.Fatal("want error for non-Key frame")
	}
	if !strings.Contains(err.Error(), "not EAPOL-Key") {
		t.Errorf("err = %v", err)
	}
}

// TestDecode_TruncatedHeader — frame shorter than 4-byte 802.1X
// header.
func TestDecode_TruncatedHeader(t *testing.T) {
	_, err := DecodeBytes([]byte{0x02, 0x03})
	if err == nil {
		t.Fatal("want error for short frame")
	}
}

// TestDecode_TruncatedKeyFrame — header says EAPOL-Key but
// frame is shorter than the 99-byte minimum.
func TestDecode_TruncatedKeyFrame(t *testing.T) {
	_, err := DecodeBytes([]byte{0x02, 0x03, 0x00, 0x5F, 0x02, 0x00, 0x8A})
	if err == nil {
		t.Fatal("want error for truncated key frame")
	}
	if !strings.Contains(err.Error(), "minimum") {
		t.Errorf("err = %v; want 'minimum' wording", err)
	}
}

// TestDecode_KeyDataLengthExceedsBuffer — declared key data
// length is longer than the remaining bytes.
func TestDecode_KeyDataLengthExceedsBuffer(t *testing.T) {
	// Build a minimum-length frame but lie about key data length.
	frame := makeFrame(t, 0x008A, nil)
	frame[97] = 0xFF
	frame[98] = 0xFF
	_, err := DecodeBytes(frame)
	if err == nil {
		t.Fatal("want error for over-declared key data length")
	}
}

// TestDecode_EmptyAndInvalidHex — input validation.
func TestDecode_BadInput(t *testing.T) {
	if _, err := Decode(""); err == nil {
		t.Error("empty input: want error")
	}
	if _, err := Decode("ZZ"); err == nil {
		t.Error("invalid hex: want error")
	}
}

// TestDecode_ToleratesSeparators — ':' / '-' / '_' / whitespace.
func TestDecode_ToleratesSeparators(t *testing.T) {
	frame := makeFrame(t, 0x008A, nil)
	// Build a hex string with colons between every byte.
	var sb strings.Builder
	for i, b := range frame {
		if i > 0 {
			sb.WriteByte(':')
		}
		const hexChars = "0123456789ABCDEF"
		sb.WriteByte(hexChars[b>>4])
		sb.WriteByte(hexChars[b&0x0F])
	}
	got, err := Decode(sb.String())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.HandshakeMessage != "M1" {
		t.Errorf("HandshakeMessage = %q; want 'M1'", got.HandshakeMessage)
	}
}

// TestDescriptorVersionNames pins the public name table.
func TestDescriptorVersionNames(t *testing.T) {
	cases := map[int]string{
		1: "HMAC-MD5 MIC + ARC4 encryption (TKIP)",
		2: "HMAC-SHA1 MIC + AES encryption (CCMP)",
		3: "AES-128-CMAC MIC (PMF / 802.11w)",
	}
	for v, want := range cases {
		if got := descriptorVersionName(v); got != want {
			t.Errorf("descriptorVersionName(%d) = %q; want %q", v, got, want)
		}
	}
}

// TestKDETypeNames spot-checks the documented KDE types.
func TestKDETypeNames(t *testing.T) {
	cases := map[byte]string{
		1: "GTK",
		2: "MAC address",
		4: "PMKID",
		6: "IGTK",
		8: "WPA specification",
	}
	for v, want := range cases {
		if got := kdeTypeName(v); got != want {
			t.Errorf("kdeTypeName(%d) = %q; want %q", v, got, want)
		}
	}
}
