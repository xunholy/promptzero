package tlsdecode

import (
	"encoding/hex"
	"strings"
	"testing"
)

// TestDecode_ClientHello_RoundTrip builds a realistic TLS 1.3
// ClientHello with SNI "example.com", ALPN [h2, http/1.1],
// supported_versions [TLS 1.3], cipher suites [TLS_AES_128_GCM_SHA256,
// TLS_AES_256_GCM_SHA384], supported_groups [x25519, secp256r1].
// Pin every documented field through decode.
func TestDecode_ClientHello_RoundTrip(t *testing.T) {
	frame := buildClientHelloFrame(t)
	got, err := DecodeBytes(frame)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(got.Records) != 1 {
		t.Fatalf("Records count = %d; want 1", len(got.Records))
	}
	rec := got.Records[0]
	if rec.ContentType != 22 {
		t.Errorf("ContentType = %d; want 22 (Handshake)", rec.ContentType)
	}
	if rec.ContentName != "Handshake" {
		t.Errorf("ContentName = %q", rec.ContentName)
	}
	if rec.VersionName != "TLS 1.0" {
		// Note: outer record version is typically TLS 1.0 for
		// compatibility, even on TLS 1.3 sessions.
		t.Errorf("VersionName = %q; want 'TLS 1.0' (record-layer compat)", rec.VersionName)
	}
	if len(rec.Handshakes) != 1 {
		t.Fatalf("Handshakes count = %d; want 1", len(rec.Handshakes))
	}
	hs := rec.Handshakes[0]
	if hs.MessageType != 1 {
		t.Errorf("MessageType = %d; want 1", hs.MessageType)
	}
	if hs.MessageName != "ClientHello" {
		t.Errorf("MessageName = %q", hs.MessageName)
	}
	ch := hs.ClientHello
	if ch == nil {
		t.Fatal("ClientHello nil")
	}
	if ch.VersionName != "TLS 1.2" {
		t.Errorf("VersionName = %q; want 'TLS 1.2' (legacy_version)", ch.VersionName)
	}
	if len(ch.CipherSuites) != 2 {
		t.Fatalf("CipherSuites count = %d; want 2", len(ch.CipherSuites))
	}
	if ch.CipherSuites[0].Name != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("CipherSuites[0].Name = %q", ch.CipherSuites[0].Name)
	}
	if ch.CipherSuites[1].Name != "TLS_AES_256_GCM_SHA384" {
		t.Errorf("CipherSuites[1].Name = %q", ch.CipherSuites[1].Name)
	}
	if ch.ServerName != "example.com" {
		t.Errorf("ServerName = %q; want 'example.com'", ch.ServerName)
	}
	if len(ch.ALPNProtocols) != 2 || ch.ALPNProtocols[0] != "h2" || ch.ALPNProtocols[1] != "http/1.1" {
		t.Errorf("ALPNProtocols = %v", ch.ALPNProtocols)
	}
	if len(ch.SupportedVersions) != 1 || ch.SupportedVersions[0] != "TLS 1.3" {
		t.Errorf("SupportedVersions = %v", ch.SupportedVersions)
	}
	if len(ch.SupportedGroups) != 2 || ch.SupportedGroups[0] != "x25519" {
		t.Errorf("SupportedGroups = %v", ch.SupportedGroups)
	}
	if len(ch.SignatureAlgorithms) == 0 {
		t.Error("SignatureAlgorithms empty")
	}
	if ch.JA3 == "" {
		t.Error("JA3 empty")
	}
	if len(ch.JA3Hash) != 32 {
		t.Errorf("JA3Hash length = %d; want 32 (MD5 hex)", len(ch.JA3Hash))
	}
	// JA3 string should start with "771," (TLS 1.2 = 0x0303 = 771)
	if !strings.HasPrefix(ch.JA3, "771,") {
		t.Errorf("JA3 = %q; want 771,... prefix", ch.JA3)
	}
}

// TestDecode_ClientHello_GREASE verifies that GREASE values
// (RFC 8701) in the cipher_suites and extensions lists are
// stripped from the JA3 fingerprint.
func TestDecode_ClientHello_GREASE(t *testing.T) {
	// Build a ClientHello with one GREASE cipher (0x0A0A) and
	// one real cipher (0x1301).
	body := buildClientHelloBody(t, []uint16{0x0A0A, 0x1301}, "test.local")
	frame := wrapAsRecord(t, body)
	got, err := DecodeBytes(frame)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	ch := got.Records[0].Handshakes[0].ClientHello
	if ch == nil {
		t.Fatal("ClientHello nil")
	}
	// GREASE cipher should be present in the structured list
	// but excluded from JA3.
	if len(ch.CipherSuites) != 2 {
		t.Errorf("CipherSuites count = %d", len(ch.CipherSuites))
	}
	// JA3 cipher list section (between first and second comma)
	// should contain "4865" (0x1301) but not "2570" (0x0A0A).
	sections := strings.Split(ch.JA3, ",")
	if len(sections) != 5 {
		t.Fatalf("JA3 sections = %d; want 5", len(sections))
	}
	if !strings.Contains(sections[1], "4865") {
		t.Errorf("JA3 ciphers section %q should contain 4865", sections[1])
	}
	if strings.Contains(sections[1], "2570") {
		t.Errorf("JA3 ciphers section %q should NOT contain 2570 (GREASE)", sections[1])
	}
}

// TestDecode_ServerHello pins a ServerHello round-trip.
func TestDecode_ServerHello(t *testing.T) {
	frame := buildServerHelloFrame(t)
	got, err := DecodeBytes(frame)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	hs := got.Records[0].Handshakes[0]
	if hs.MessageType != 2 {
		t.Errorf("MessageType = %d; want 2", hs.MessageType)
	}
	if hs.MessageName != "ServerHello" {
		t.Errorf("MessageName = %q", hs.MessageName)
	}
	sh := hs.ServerHello
	if sh == nil {
		t.Fatal("ServerHello nil")
	}
	if sh.CipherSuite.Name != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("CipherSuite.Name = %q", sh.CipherSuite.Name)
	}
	if sh.NegotiatedVersion != "TLS 1.3" {
		t.Errorf("NegotiatedVersion = %q", sh.NegotiatedVersion)
	}
}

// TestDecode_RecordTooShort rejects buffers smaller than the
// 5-byte record header.
func TestDecode_RecordTooShort(t *testing.T) {
	if _, err := Decode("16 03 01"); err == nil {
		t.Error("3-byte input: want error")
	}
}

// TestDecode_BadHex rejects garbage.
func TestDecode_BadHex(t *testing.T) {
	if _, err := Decode("ZZ"); err == nil {
		t.Error("bad hex: want error")
	}
	if _, err := Decode(""); err == nil {
		t.Error("empty: want error")
	}
}

// TestDecode_LengthMismatch rejects a record whose declared
// length exceeds the buffer.
func TestDecode_LengthMismatch(t *testing.T) {
	if _, err := Decode("16 03 01 FF FF 00 01 02"); err == nil {
		t.Error("length 65535 > buffer: want error")
	}
}

// TestDecode_NonHandshakeRecord verifies that ChangeCipherSpec
// (content type 20) is labeled but body is surfaced as raw hex.
func TestDecode_NonHandshakeRecord(t *testing.T) {
	got, err := Decode("14 03 03 00 01 01")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Records[0].ContentName != "ChangeCipherSpec" {
		t.Errorf("ContentName = %q", got.Records[0].ContentName)
	}
	if got.Records[0].BodyHex != "01" {
		t.Errorf("BodyHex = %q; want '01'", got.Records[0].BodyHex)
	}
}

// TestContentTypeNameTable spot-checks.
func TestContentTypeNameTable(t *testing.T) {
	cases := map[int]string{
		20: "ChangeCipherSpec",
		21: "Alert",
		22: "Handshake",
		23: "ApplicationData",
	}
	for ct, want := range cases {
		if got := contentTypeName(ct); got != want {
			t.Errorf("contentTypeName(%d) = %q; want %q", ct, got, want)
		}
	}
}

// TestVersionNameTable spot-checks.
func TestVersionNameTable(t *testing.T) {
	cases := []struct {
		maj, min int
		want     string
	}{
		{3, 1, "TLS 1.0"},
		{3, 3, "TLS 1.2"},
		{3, 4, "TLS 1.3"},
	}
	for _, c := range cases {
		if got := versionName(c.maj, c.min); got != c.want {
			t.Errorf("versionName(%d, %d) = %q; want %q", c.maj, c.min, got, c.want)
		}
	}
}

// TestHandshakeMessageNameTable spot-checks.
func TestHandshakeMessageNameTable(t *testing.T) {
	cases := map[int]string{
		0:  "HelloRequest",
		1:  "ClientHello",
		2:  "ServerHello",
		8:  "EncryptedExtensions",
		11: "Certificate",
		20: "Finished",
	}
	for mt, want := range cases {
		if got := handshakeMessageName(mt); got != want {
			t.Errorf("handshakeMessageName(%d) = %q; want %q", mt, got, want)
		}
	}
}

// TestCipherSuiteTable spot-checks the major TLS 1.3 suites.
func TestCipherSuiteTable(t *testing.T) {
	cases := map[uint16]string{
		0x1301: "TLS_AES_128_GCM_SHA256",
		0x1302: "TLS_AES_256_GCM_SHA384",
		0x1303: "TLS_CHACHA20_POLY1305_SHA256",
		0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		0x00FF: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
	}
	for v, want := range cases {
		if got := cipherSuiteName(v); got != want {
			t.Errorf("cipherSuiteName(0x%04X) = %q; want %q", v, got, want)
		}
	}
}

// TestExtensionTypeTable spot-checks.
func TestExtensionTypeTable(t *testing.T) {
	cases := map[int]string{
		0:  "server_name (SNI)",
		10: "supported_groups",
		13: "signature_algorithms",
		16: "application_layer_protocol_negotiation (ALPN)",
		43: "supported_versions",
		51: "key_share",
	}
	for v, want := range cases {
		if got := extensionTypeName(v); got != want {
			t.Errorf("extensionTypeName(%d) = %q; want %q", v, got, want)
		}
	}
}

// TestNamedGroupTable spot-checks.
func TestNamedGroupTable(t *testing.T) {
	cases := map[uint16]string{
		0x0017: "secp256r1 (P-256)",
		0x0018: "secp384r1 (P-384)",
		0x001D: "x25519",
		0x001E: "x448",
		0x0100: "ffdhe2048",
	}
	for v, want := range cases {
		if got := namedGroupName(v); got != want {
			t.Errorf("namedGroupName(0x%04X) = %q; want %q", v, got, want)
		}
	}
}

// TestIsGREASE spot-checks GREASE detection.
func TestIsGREASE(t *testing.T) {
	greaseValues := []uint16{0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0xCACA, 0xDADA, 0xFAFA}
	for _, v := range greaseValues {
		if !isGREASE(v) {
			t.Errorf("isGREASE(0x%04X) = false; want true", v)
		}
	}
	nonGrease := []uint16{0x0000, 0x1301, 0xC02F, 0x0A0B, 0x1B1B}
	for _, v := range nonGrease {
		if isGREASE(v) {
			t.Errorf("isGREASE(0x%04X) = true; want false", v)
		}
	}
}

// TestDecode_Separators tolerates ',', '-', '_', whitespace.
func TestDecode_Separators(t *testing.T) {
	got, err := Decode("14:03-03_00 01 01")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Records[0].ContentName != "ChangeCipherSpec" {
		t.Errorf("ContentName = %q", got.Records[0].ContentName)
	}
}

// buildClientHelloFrame is a test helper that wraps a
// canonical ClientHello body in a TLS record envelope.
func buildClientHelloFrame(t *testing.T) []byte {
	t.Helper()
	body := buildClientHelloBody(t, []uint16{0x1301, 0x1302}, "example.com")
	return wrapAsRecord(t, body)
}

// buildClientHelloBody builds a TLS Handshake ClientHello
// (header + body) per RFC 8446.
func buildClientHelloBody(t *testing.T, cipherSuites []uint16, sni string) []byte {
	t.Helper()
	// ClientHello body:
	//   legacy_version (2): 03 03
	//   random (32): zero-filled for determinism
	//   legacy_session_id (1+0)
	//   cipher_suites (2 + N*2)
	//   compression_methods (1 + 1): 00
	//   extensions (2 + N): see below
	var ch []byte
	ch = append(ch, 0x03, 0x03)          // version TLS 1.2
	ch = append(ch, make([]byte, 32)...) // random
	ch = append(ch, 0x00)                // session ID len = 0
	// cipher suites
	csBytes := make([]byte, 2+len(cipherSuites)*2)
	csBytes[0] = byte(len(cipherSuites) * 2 >> 8)
	csBytes[1] = byte(len(cipherSuites) * 2)
	for i, c := range cipherSuites {
		csBytes[2+i*2] = byte(c >> 8)
		csBytes[2+i*2+1] = byte(c)
	}
	ch = append(ch, csBytes...)
	// compression methods: 1 method, null
	ch = append(ch, 0x01, 0x00)

	// Build extensions
	var exts []byte

	// 1. server_name (type 0)
	if sni != "" {
		var sniExt []byte
		// list_len(2) + name_type(1) + name_len(2) + name
		nameLen := len(sni)
		listLen := 1 + 2 + nameLen
		sniExt = append(sniExt, byte(listLen>>8), byte(listLen))
		sniExt = append(sniExt, 0x00)
		sniExt = append(sniExt, byte(nameLen>>8), byte(nameLen))
		sniExt = append(sniExt, []byte(sni)...)
		exts = append(exts, makeExtension(0, sniExt)...)
	}

	// 2. supported_groups (type 10): x25519, secp256r1
	groups := []uint16{0x001D, 0x0017}
	sg := make([]byte, 2+len(groups)*2)
	sg[0] = byte(len(groups) * 2 >> 8)
	sg[1] = byte(len(groups) * 2)
	for i, g := range groups {
		sg[2+i*2] = byte(g >> 8)
		sg[2+i*2+1] = byte(g)
	}
	exts = append(exts, makeExtension(10, sg)...)

	// 3. ec_point_formats (type 11): one format, uncompressed
	exts = append(exts, makeExtension(11, []byte{0x01, 0x00})...)

	// 4. signature_algorithms (type 13): ecdsa_secp256r1_sha256
	sigs := []uint16{0x0403, 0x0804}
	sa := make([]byte, 2+len(sigs)*2)
	sa[0] = byte(len(sigs) * 2 >> 8)
	sa[1] = byte(len(sigs) * 2)
	for i, s := range sigs {
		sa[2+i*2] = byte(s >> 8)
		sa[2+i*2+1] = byte(s)
	}
	exts = append(exts, makeExtension(13, sa)...)

	// 5. ALPN (type 16): h2, http/1.1
	alpn := []string{"h2", "http/1.1"}
	var alpnList []byte
	for _, p := range alpn {
		alpnList = append(alpnList, byte(len(p)))
		alpnList = append(alpnList, []byte(p)...)
	}
	alpnExt := append([]byte{byte(len(alpnList) >> 8), byte(len(alpnList))}, alpnList...)
	exts = append(exts, makeExtension(16, alpnExt)...)

	// 6. supported_versions (type 43): TLS 1.3
	exts = append(exts, makeExtension(43, []byte{0x02, 0x03, 0x04})...)

	// Wrap extensions block
	extsBlock := make([]byte, 2+len(exts))
	extsBlock[0] = byte(len(exts) >> 8)
	extsBlock[1] = byte(len(exts))
	copy(extsBlock[2:], exts)
	ch = append(ch, extsBlock...)

	// Build handshake header: msg type (1) + length (3)
	hsLen := len(ch)
	hs := []byte{0x01, byte(hsLen >> 16), byte(hsLen >> 8), byte(hsLen)}
	hs = append(hs, ch...)
	return hs
}

// buildServerHelloFrame is a test helper for a minimal TLS 1.3
// ServerHello.
func buildServerHelloFrame(t *testing.T) []byte {
	t.Helper()
	var sh []byte
	sh = append(sh, 0x03, 0x03)          // legacy_version
	sh = append(sh, make([]byte, 32)...) // random
	sh = append(sh, 0x00)                // session ID len = 0
	sh = append(sh, 0x13, 0x01)          // cipher suite TLS_AES_128_GCM_SHA256
	sh = append(sh, 0x00)                // compression method = null
	// extension supported_versions selecting TLS 1.3:
	// (2-byte type + 2-byte len + 2-byte value)
	ext := makeExtension(43, []byte{0x03, 0x04})
	extsBlock := make([]byte, 2+len(ext))
	extsBlock[0] = byte(len(ext) >> 8)
	extsBlock[1] = byte(len(ext))
	copy(extsBlock[2:], ext)
	sh = append(sh, extsBlock...)
	// Handshake header
	hsLen := len(sh)
	hs := []byte{0x02, byte(hsLen >> 16), byte(hsLen >> 8), byte(hsLen)}
	hs = append(hs, sh...)
	return wrapAsRecord(t, hs)
}

// makeExtension returns a 2-byte type + 2-byte len + body
// extension blob.
func makeExtension(typ int, body []byte) []byte {
	out := []byte{byte(typ >> 8), byte(typ), byte(len(body) >> 8), byte(len(body))}
	return append(out, body...)
}

// wrapAsRecord wraps a handshake message in a TLS record-layer
// envelope.
func wrapAsRecord(t *testing.T, hs []byte) []byte {
	t.Helper()
	hsLen := len(hs)
	rec := []byte{0x16, 0x03, 0x01, byte(hsLen >> 8), byte(hsLen)}
	return append(rec, hs...)
}

// Diagnostic helper, not used in test asserts but useful when
// debugging mismatched test vectors.
var _ = func() string {
	b, _ := hex.DecodeString("")
	_ = b
	return ""
}
