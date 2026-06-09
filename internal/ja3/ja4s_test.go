package ja3

import "testing"

// JA4S vectors extracted from the FoxIO-LLC/ja4 reference pcaps, asserted
// against that project's own published "JA4S" / "JA4S_r" expected values
// (python/test/testdata/*.json). The ServerHello bytes were pulled from the
// matching pcap.
const (
	// socks-https-example.pcap ServerHello — TLS 1.0 (legacy version, no
	// supported_versions), one extension (ff01), no ALPN, chosen cipher 0005.
	ja4sSocksSH   = "0200004d0301529cbff584211aa7858df3c8edcf20c18c646764adc7d40b3382ef0da96840ee2085bbc584132410aa03c3d6aac195e2d81e7b8d24e63b314a4a5d214cbcf0080a0005000005ff01000100"
	ja4sSocksWant = "t100100_0005_bc98f8e001b5"
	ja4sSocksRaw  = "t100100_0005_ff01"

	// macos_tcp_flags.pcap ServerHello — TLS 1.3 (via supported_versions in the
	// ServerHello), two extensions in order (0033,002b), chosen cipher 1301.
	ja4sMacSH   = "020000760303167d192595920754340a9a5048e82ad51285a76c40247c8bb6f34a002aff191520bd61910adcce0b8d48d6424d7bb5dc597ddee64fe024e0320e9055d67c965b91130100002e00330024001d0020dd56ab683c6067f60725850e55d57f9bc384bfbc89fac073bb82be7a99677c45002b00020304"
	ja4sMacWant = "t130200_1301_234ea6891581"
	ja4sMacRaw  = "t130200_1301_0033,002b"
)

func TestJA4S_SocksLegacy(t *testing.T) {
	res, err := JA4SDecode(ja4sSocksSH)
	if err != nil {
		t.Fatalf("JA4SDecode: %v", err)
	}
	if res.JA4S != ja4sSocksWant {
		t.Errorf("JA4S\n got %q\nwant %q", res.JA4S, ja4sSocksWant)
	}
	if res.JA4SR != ja4sSocksRaw {
		t.Errorf("JA4S_r\n got %q\nwant %q", res.JA4SR, ja4sSocksRaw)
	}
	if res.TLSVersion != "10" {
		t.Errorf("version = %q, want 10", res.TLSVersion)
	}
	if res.Cipher != "0005" {
		t.Errorf("cipher = %q, want 0005", res.Cipher)
	}
}

// TestJA4S_MacSupportedVersions covers reading the negotiated version from the
// ServerHello's supported_versions extension (TLS 1.3) and in-order extension
// hashing.
func TestJA4S_MacSupportedVersions(t *testing.T) {
	res, err := JA4SDecode(ja4sMacSH)
	if err != nil {
		t.Fatalf("JA4SDecode: %v", err)
	}
	if res.JA4S != ja4sMacWant {
		t.Errorf("JA4S\n got %q\nwant %q", res.JA4S, ja4sMacWant)
	}
	if res.JA4SR != ja4sMacRaw {
		t.Errorf("JA4S_r\n got %q\nwant %q", res.JA4SR, ja4sMacRaw)
	}
	if res.TLSVersion != "13" {
		t.Errorf("version = %q, want 13", res.TLSVersion)
	}
}

// TestJA4S_ClientHelloRejected confirms a ClientHello is steered to the client
// tool rather than mis-fingerprinted.
func TestJA4S_ClientHelloRejected(t *testing.T) {
	_, err := JA4SDecode(ja4SocksHello)
	if err == nil {
		t.Fatal("want error on ClientHello, got nil")
	}
}

func TestJA4SErrors(t *testing.T) {
	for _, in := range []string{"", "zz", "0200"} {
		if _, err := JA4SDecode(in); err == nil {
			t.Errorf("JA4SDecode(%q): want error", in)
		}
	}
}
