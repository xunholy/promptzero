// SPDX-License-Identifier: AGPL-3.0-or-later

package tlsdecode

import (
	"encoding/hex"
	"testing"
)

// TestJA4FoxIOExample anchors computeJA4 byte-for-byte to the FoxIO worked
// example (technical_details/JA4.md): a TLS 1.3 client over TCP, SNI present,
// 15 ciphers, 16 extensions (SNI + ALPN included in the count, removed from the
// hash), 8 signature algorithms in order, ALPN h2 ->
// t13d1516h2_8daaf6152771_e5627efa2ab1.
func TestJA4FoxIOExample(t *testing.T) {
	ciphers := []CipherSuite{}
	for _, v := range []uint16{0x002f, 0x0035, 0x009c, 0x009d, 0x1301, 0x1302, 0x1303,
		0xc013, 0xc014, 0xc02b, 0xc02c, 0xc02f, 0xc030, 0xcca8, 0xcca9} {
		ciphers = append(ciphers, CipherSuite{Value: v})
	}
	var exts []*Extension
	// 16 extensions: SNI(0) + ALPN(16) + the 14 that survive into the hash.
	for _, typ := range []int{0, 16, 5, 10, 11, 13, 18, 21, 23, 27, 35, 43, 45, 51, 0x4469, 0xff01} {
		exts = append(exts, &Extension{Type: typ})
	}
	sigAlgs := []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601}
	versions := []uint16{0x0304} // supported_versions: TLS 1.3

	got := computeJA4("t", 0x03, 0x03, ciphers, exts, []string{"h2"}, versions, sigAlgs)
	const want = "t13d1516h2_8daaf6152771_e5627efa2ab1"
	if got != want {
		t.Errorf("JA4 = %q, want %q", got, want)
	}
}

// GREASE values must be excluded from both the counts and the hashes.
func TestJA4GreaseExcluded(t *testing.T) {
	base := []CipherSuite{}
	for _, v := range []uint16{0x002f, 0x0035, 0x009c, 0x009d, 0x1301, 0x1302, 0x1303,
		0xc013, 0xc014, 0xc02b, 0xc02c, 0xc02f, 0xc030, 0xcca8, 0xcca9} {
		base = append(base, CipherSuite{Value: v})
	}
	// Prepend a GREASE cipher + GREASE extension; result must be unchanged.
	greasyCiphers := append([]CipherSuite{{Value: 0x0a0a}}, base...)
	var exts []*Extension
	for _, typ := range []int{0x1a1a, 0, 16, 5, 10, 11, 13, 18, 21, 23, 27, 35, 43, 45, 51, 0x4469, 0xff01} {
		exts = append(exts, &Extension{Type: typ})
	}
	got := computeJA4("t", 0x03, 0x03, greasyCiphers, exts,
		[]string{"h2"}, []uint16{0x0a0a, 0x0304}, []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601})
	const want = "t13d1516h2_8daaf6152771_e5627efa2ab1"
	if got != want {
		t.Errorf("JA4 with GREASE = %q, want %q (GREASE must be ignored)", got, want)
	}
}

// ALPN and version edge encodings.
func TestJA4Pieces(t *testing.T) {
	// No ALPN, no SNI, no extensions, no ciphers, TLS 1.2 -> "00" hashes.
	got := computeJA4("t", 0x03, 0x03, nil, nil, nil, nil, nil)
	if got != "t12i000000_000000000000_000000000000" {
		t.Errorf("empty JA4 = %q, want t12i000000_000000000000_000000000000", got)
	}
	// http/1.1 ALPN -> "h1".
	if a := ja4ALPN([]string{"http/1.1"}); a != "h1" {
		t.Errorf("ja4ALPN(http/1.1) = %q, want h1", a)
	}
	if a := ja4ALPN(nil); a != "00" {
		t.Errorf("ja4ALPN(nil) = %q, want 00", a)
	}
}

// TestJA4SFoxIOAnchors anchors computeJA4S byte-for-byte to two real FoxIO
// snapshot outputs (rust/ja4/src/snapshots/ja4__insta@tls-handshake.pcapng.snap):
// the same two TLS 1.3 ServerHello extensions (key_share 0x0033, supported_versions
// 0x002b) in opposite wire order produce different JA4S_c hashes, proving the
// extensions are kept in wire order (not sorted).
func TestJA4SFoxIOAnchors(t *testing.T) {
	// Google stack: key_share THEN supported_versions, cipher 0x1301.
	google := computeJA4S("t", 0x03, 0x03, 0x1301,
		[]*Extension{{Type: 0x0033}, {Type: 0x002b}}, "", "TLS 1.3")
	if google != "t130200_1301_234ea6891581" {
		t.Errorf("Google JA4S = %q, want t130200_1301_234ea6891581", google)
	}
	// LastPass stack: supported_versions THEN key_share, cipher 0x1302.
	lastpass := computeJA4S("t", 0x03, 0x03, 0x1302,
		[]*Extension{{Type: 0x002b}, {Type: 0x0033}}, "", "TLS 1.3")
	if lastpass != "t130200_1302_a56c5b993250" {
		t.Errorf("LastPass JA4S = %q, want t130200_1302_a56c5b993250", lastpass)
	}
}

// TestComputeJA4SQUIC confirms the JA4S "q" variant: the same TLS 1.3
// ServerHello extension order that yields t130200_1301_234ea6891581 over TCP
// yields q130200_1301_234ea6891581 over QUIC — the only difference is the
// protocol prefix (FoxIO chrome-cloudflare-quic snapshot).
func TestComputeJA4SQUIC(t *testing.T) {
	got := computeJA4S("q", 0x03, 0x03, 0x1301,
		[]*Extension{{Type: 0x0033}, {Type: 0x002b}}, "", "TLS 1.3")
	const want = "q130200_1301_234ea6891581"
	if got != want {
		t.Errorf("JA4S(q) = %q, want %q", got, want)
	}
}

// foxioQUICClientHello is the bare TLS ClientHello handshake message (no record
// envelope) extracted from the CRYPTO stream of the QUIC Initial in FoxIO's
// pcap/quic-tls-handshake.pcapng (SNI www.google.com). Chrome's QUIC JA4 is
// published in FoxIO's snapshot as q13d0310h3_55b375c5d22e_cd85d2d88918.
const foxioQUICClientHello = "010001250303383d3bcc378f2dad654f7b937409876967b41befe42ba1acdebb" +
	"8b9445787b84000006130113021303010000f6002d00020101001b0003020002" +
	"446900050003026833000d001400120403080404010503080505010806060102" +
	"01002b000302030400000013001100000e7777772e676f6f676c652e636f6d00" +
	"0a00080006001d0017001800390067040480f000000f00060480600000030245" +
	"c0050480600000712702502480ff73db0c00000001aada0a7a00000001080240" +
	"647128045256434d07048060000020048001000009024067d71be2ff92c99efc" +
	"060efac8e782f280004752040000000101048000753000100005000302683300" +
	"3300260024001d00201dab42d2c5adfce8c137239e8de6b042bbd706b97af5dc" +
	"7331dae4b80d1c5937"

// TestQUICHandshakeJA4ClientHello anchors the QUIC JA4 ("q" prefix) path
// byte-for-byte to FoxIO's published QUIC snapshot, over a real Chrome QUIC
// ClientHello parsed as a bare handshake message.
func TestQUICHandshakeJA4ClientHello(t *testing.T) {
	b, err := hex.DecodeString(foxioQUICClientHello)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	fp, kind, err := QUICHandshakeJA4(b)
	if err != nil {
		t.Fatalf("QUICHandshakeJA4: %v", err)
	}
	if kind != "ClientHello" {
		t.Errorf("kind = %q, want ClientHello", kind)
	}
	const want = "q13d0310h3_55b375c5d22e_cd85d2d88918"
	if fp != want {
		t.Errorf("JA4 = %q, want %q", fp, want)
	}
}

// TestQUICHandshakeJA4Rejects covers the non-Hello and truncated paths.
func TestQUICHandshakeJA4Rejects(t *testing.T) {
	if _, _, err := QUICHandshakeJA4([]byte{0x0b, 0x00, 0x00, 0x00}); err == nil {
		t.Error("expected error for non-Hello handshake type")
	}
	if _, _, err := QUICHandshakeJA4([]byte{0x01, 0xff, 0xff, 0xff}); err == nil {
		t.Error("expected error for length exceeding buffer")
	}
}
