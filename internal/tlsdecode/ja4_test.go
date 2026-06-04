// SPDX-License-Identifier: AGPL-3.0-or-later

package tlsdecode

import "testing"

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

	got := computeJA4(0x03, 0x03, ciphers, exts, []string{"h2"}, versions, sigAlgs)
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
	got := computeJA4(0x03, 0x03, greasyCiphers, exts,
		[]string{"h2"}, []uint16{0x0a0a, 0x0304}, []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601})
	const want = "t13d1516h2_8daaf6152771_e5627efa2ab1"
	if got != want {
		t.Errorf("JA4 with GREASE = %q, want %q (GREASE must be ignored)", got, want)
	}
}

// ALPN and version edge encodings.
func TestJA4Pieces(t *testing.T) {
	// No ALPN, no SNI, no extensions, no ciphers, TLS 1.2 -> "00" hashes.
	got := computeJA4(0x03, 0x03, nil, nil, nil, nil, nil)
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
	google := computeJA4S(0x03, 0x03, 0x1301,
		[]*Extension{{Type: 0x0033}, {Type: 0x002b}}, "", "TLS 1.3")
	if google != "t130200_1301_234ea6891581" {
		t.Errorf("Google JA4S = %q, want t130200_1301_234ea6891581", google)
	}
	// LastPass stack: supported_versions THEN key_share, cipher 0x1302.
	lastpass := computeJA4S(0x03, 0x03, 0x1302,
		[]*Extension{{Type: 0x002b}, {Type: 0x0033}}, "", "TLS 1.3")
	if lastpass != "t130200_1302_a56c5b993250" {
		t.Errorf("LastPass JA4S = %q, want t130200_1302_a56c5b993250", lastpass)
	}
}
