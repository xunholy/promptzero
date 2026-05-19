package sshdecode

import (
	"crypto/md5" //nolint:gosec // HASSH defines MD5.
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// TestDecode_VersionBanner_OpenSSH pins a typical OpenSSH
// banner with the optional comment field.
func TestDecode_VersionBanner_OpenSSH(t *testing.T) {
	line := "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n"
	got, err := Decode(line)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.VersionBanner == nil {
		t.Fatal("VersionBanner nil")
	}
	if got.VersionBanner.ProtocolVersion != "2.0" {
		t.Errorf("ProtocolVersion = %q", got.VersionBanner.ProtocolVersion)
	}
	if got.VersionBanner.SoftwareVersion != "OpenSSH_8.9p1" {
		t.Errorf("SoftwareVersion = %q", got.VersionBanner.SoftwareVersion)
	}
	if got.VersionBanner.Comment != "Ubuntu-3ubuntu0.10" {
		t.Errorf("Comment = %q", got.VersionBanner.Comment)
	}
}

// TestDecode_VersionBanner_Dropbear pins a Dropbear banner
// (no comment field).
func TestDecode_VersionBanner_Dropbear(t *testing.T) {
	line := "SSH-2.0-dropbear_2022.83"
	got, err := Decode(line)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.VersionBanner.SoftwareVersion != "dropbear_2022.83" {
		t.Errorf("SoftwareVersion = %q", got.VersionBanner.SoftwareVersion)
	}
	if got.VersionBanner.Comment != "" {
		t.Errorf("Comment = %q; want empty", got.VersionBanner.Comment)
	}
}

// TestDecode_VersionBanner_SSH199 pins a backwards-compat
// "SSH-1.99-..." banner (server speaks both v1 and v2).
func TestDecode_VersionBanner_SSH199(t *testing.T) {
	got, err := Decode("SSH-1.99-Cisco-1.25\n")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.VersionBanner.ProtocolVersion != "1.99" {
		t.Errorf("ProtocolVersion = %q", got.VersionBanner.ProtocolVersion)
	}
	if got.VersionBanner.SoftwareVersion != "Cisco-1.25" {
		t.Errorf("SoftwareVersion = %q", got.VersionBanner.SoftwareVersion)
	}
}

// TestDecode_KEXInit_MinimalLists builds a minimal KEXINIT and
// verifies every list + HASSH/HASSHServer computation.
func TestDecode_KEXInit_MinimalLists(t *testing.T) {
	kexInit := buildKEXInitPayload(t,
		"diffie-hellman-group14-sha1",
		"ssh-rsa",
		"aes128-ctr", "aes128-ctr",
		"hmac-sha2-256", "hmac-sha2-256",
		"none", "none",
		"", "",
	)
	pkt := wrapBinaryPacket(t, kexInit)
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("DecodeBytes: %v", err)
	}
	if got.BinaryPacket == nil {
		t.Fatal("BinaryPacket nil")
	}
	if got.BinaryPacket.MessageType != 20 {
		t.Errorf("MessageType = %d; want 20", got.BinaryPacket.MessageType)
	}
	if got.BinaryPacket.MessageName != "SSH_MSG_KEXINIT" {
		t.Errorf("MessageName = %q", got.BinaryPacket.MessageName)
	}
	kx := got.BinaryPacket.KEXInit
	if kx == nil {
		t.Fatal("KEXInit nil")
	}
	if len(kx.KexAlgorithms) != 1 || kx.KexAlgorithms[0] != "diffie-hellman-group14-sha1" {
		t.Errorf("KexAlgorithms = %v", kx.KexAlgorithms)
	}
	if kx.MACAlgorithmsClientToServer[0] != "hmac-sha2-256" {
		t.Errorf("MAC c2s = %v", kx.MACAlgorithmsClientToServer)
	}
	if kx.HASSH != "diffie-hellman-group14-sha1;aes128-ctr;hmac-sha2-256;none" {
		t.Errorf("HASSH = %q", kx.HASSH)
	}
	expectedHash := md5HashOf("diffie-hellman-group14-sha1;aes128-ctr;hmac-sha2-256;none")
	if kx.HASSHHash != expectedHash {
		t.Errorf("HASSHHash = %q; want %q", kx.HASSHHash, expectedHash)
	}
	// HASSHServer is the same as HASSH here because c2s == s2c
	if kx.HASSHServer != kx.HASSH {
		t.Errorf("HASSHServer = %q; want same as HASSH for symmetric lists", kx.HASSHServer)
	}
}

// TestDecode_KEXInit_AsymmetricLists pins a KEXINIT with
// different c2s and s2c lists, so HASSH != HASSHServer.
func TestDecode_KEXInit_AsymmetricLists(t *testing.T) {
	kexInit := buildKEXInitPayload(t,
		"curve25519-sha256,ecdh-sha2-nistp256",
		"ssh-ed25519,rsa-sha2-512",
		"aes128-ctr", "aes256-gcm@openssh.com",
		"hmac-sha2-256", "hmac-sha2-512",
		"none", "zlib@openssh.com",
		"", "",
	)
	pkt := wrapBinaryPacket(t, kexInit)
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	kx := got.BinaryPacket.KEXInit
	if kx.HASSH == kx.HASSHServer {
		t.Error("HASSH should differ from HASSHServer when c2s != s2c")
	}
	if !strings.Contains(kx.HASSH, "aes128-ctr") {
		t.Errorf("HASSH = %q; want aes128-ctr", kx.HASSH)
	}
	if !strings.Contains(kx.HASSHServer, "aes256-gcm@openssh.com") {
		t.Errorf("HASSHServer = %q; want aes256-gcm", kx.HASSHServer)
	}
}

// TestDecode_BinaryPacket_OtherMessageType pins a NEWKEYS
// message (type 21) — labeled but no body decode.
func TestDecode_BinaryPacket_OtherMessageType(t *testing.T) {
	// Just a 1-byte payload: msg type 21.
	pkt := wrapBinaryPacket(t, []byte{21})
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.BinaryPacket.MessageType != 21 {
		t.Errorf("MessageType = %d", got.BinaryPacket.MessageType)
	}
	if got.BinaryPacket.MessageName != "SSH_MSG_NEWKEYS" {
		t.Errorf("MessageName = %q", got.BinaryPacket.MessageName)
	}
	if got.BinaryPacket.KEXInit != nil {
		t.Error("KEXInit should be nil for non-KEXINIT messages")
	}
}

// TestDecode_BinaryPacket_BadLength rejects a packet where
// declared length exceeds buffer.
func TestDecode_BinaryPacket_BadLength(t *testing.T) {
	// length = 1000 but only 6 bytes of buffer
	pkt := []byte{0x00, 0x00, 0x03, 0xE8, 0x04, 0x14}
	if _, err := DecodeBytes(pkt); err == nil {
		t.Error("declared length 1000 > buffer: want error")
	}
}

// TestDecode_BinaryPacket_TooShort rejects buffers shorter
// than the 6-byte minimum (4 length + 1 padlen + 1 msgtype).
func TestDecode_BinaryPacket_TooShort(t *testing.T) {
	if _, err := Decode("00 00 00"); err == nil {
		t.Error("3-byte input: want error")
	}
}

// TestDecode_BadInput rejects garbage.
func TestDecode_BadInput(t *testing.T) {
	if _, err := Decode(""); err == nil {
		t.Error("empty: want error")
	}
	if _, err := Decode("ZZ"); err == nil {
		t.Error("garbage hex: want error")
	}
}

// TestDecode_VersionBanner_BadFormat rejects a banner that
// doesn't have the protoversion-softwareversion dash.
func TestDecode_VersionBanner_BadFormat(t *testing.T) {
	if _, err := Decode("SSH-foobar"); err == nil {
		t.Error("missing protoversion-softwareversion dash: want error")
	}
}

// TestMessageTypeNameTable spot-checks the table.
func TestMessageTypeNameTable(t *testing.T) {
	cases := map[int]string{
		1:   "SSH_MSG_DISCONNECT",
		2:   "SSH_MSG_IGNORE",
		20:  "SSH_MSG_KEXINIT",
		21:  "SSH_MSG_NEWKEYS",
		50:  "SSH_MSG_USERAUTH_REQUEST",
		52:  "SSH_MSG_USERAUTH_SUCCESS",
		90:  "SSH_MSG_CHANNEL_OPEN",
		94:  "SSH_MSG_CHANNEL_DATA",
		100: "SSH_MSG_CHANNEL_FAILURE",
	}
	for v, want := range cases {
		if got := messageTypeName(v); got != want {
			t.Errorf("messageTypeName(%d) = %q; want %q", v, got, want)
		}
	}
}

// TestReadNameList_Empty handles the empty list case.
func TestReadNameList_Empty(t *testing.T) {
	body := []byte{0x00, 0x00, 0x00, 0x00, 0xFF}
	list, n, err := readNameList(body, 0)
	if err != nil {
		t.Fatalf("readNameList: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("len(list) = %d; want 0", len(list))
	}
	if n != 4 {
		t.Errorf("n = %d; want 4", n)
	}
}

// --- test helpers --------------------------------------------------

func encodeNameList(s string) []byte {
	out := make([]byte, 4+len(s))
	binary.BigEndian.PutUint32(out[0:4], uint32(len(s)))
	copy(out[4:], s)
	return out
}

func buildKEXInitPayload(t *testing.T,
	kex, hostKey, encC2S, encS2C, macC2S, macS2C,
	compC2S, compS2C, langC2S, langS2C string,
) []byte {
	t.Helper()
	body := []byte{20} // message type
	// 16-byte cookie (zero-filled for determinism)
	body = append(body, make([]byte, 16)...)
	for _, s := range []string{kex, hostKey, encC2S, encS2C, macC2S, macS2C, compC2S, compS2C, langC2S, langS2C} {
		body = append(body, encodeNameList(s)...)
	}
	body = append(body, 0x00)                   // first_kex_packet_follows = false
	body = append(body, 0x00, 0x00, 0x00, 0x00) // reserved
	return body
}

// wrapBinaryPacket wraps a payload in an SSH binary-packet
// envelope: [pkt_len:4][pad_len:1][payload][padding]. The
// MAC is omitted (we're not pre-encryption). Padding is
// chosen so that (1+payload+padding) is a multiple of 8 and
// padding ≥ 4 per RFC 4253 §6.
func wrapBinaryPacket(t *testing.T, payload []byte) []byte {
	t.Helper()
	// Compute padding to align to 8 bytes with minimum 4.
	const block = 8
	padLen := block - ((1 + len(payload) + 1) % block)
	if padLen < 4 {
		padLen += block
	}
	pktLen := 1 + len(payload) + padLen
	hdr := make([]byte, 5)
	binary.BigEndian.PutUint32(hdr[0:4], uint32(pktLen))
	hdr[4] = byte(padLen)
	out := append(hdr, payload...)
	out = append(out, make([]byte, padLen)...)
	return out
}

func md5HashOf(s string) string {
	sum := md5.Sum([]byte(s)) //nolint:gosec // HASSH defines MD5.
	return hex.EncodeToString(sum[:])
}
