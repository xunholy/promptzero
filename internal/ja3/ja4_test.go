package ja3

import "testing"

// These vectors are extracted from the FoxIO-LLC/ja4 reference pcaps; wantJA4 /
// wantJA4R are that project's own published expected values (python/test/
// testdata/*.json — "JA4.1" / "JA4_r.1"). The ClientHello bytes were pulled
// from the matching pcap and cross-checked: each hello's sorted cipher list
// reproduces the published JA4_r exactly.
const (
	// tls-sni.pcapng — TLS 1.3 (via supported_versions), GREASE in ciphers +
	// extensions, SNI present, ALPN h2, signature_algorithms present.
	ja4SNIHello = "010001fc03030f9e38acb9a54a7c6e00e29a70ac2feee180ff76d7f25dca84932a66a42d1e5a20bc58b92f865e6b9aa4a6371cadcb0afe1da1c0f705209a11d52357f56d5dd9620020aaaa130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010001939a9a0000ff010001000033002b00290a0a000100001d0020cf55af2603e92f59eb321779706a18fa6b96b16c16404c2264ed687a59401878002d00020101000500050100000000446900050003026832000d00120010040308040401050308050501080606010010000e000c02683208687474702f312e3100230000001b0003020002002b0007060a0a0304030300000022002000001d636c69656e7473657276696365732e676f6f676c65617069732e636f6d00120000000a000a00080a0a001d0017001800170000000b000201006a6a000100001500ba000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	ja4SNIWant  = "t13d1516h2_8daaf6152771_e5627efa2ab1"
	ja4SNIRaw   = "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601"

	// socks-https-example.pcap — TLS 1.0 (legacy version, no supported_versions),
	// only a SNI extension (excluded from JA4_c → empty), no ALPN.
	ja4SocksHello = "0100006f0301529cbff829e8f23edf4bb09e1feaadd0131b7bc56eab3d7567b17e0374bd6b7500002e00390038003500160013000a00330032002f009a00990096000500040015001200090014001100080006000300ff0100001800000014001200000f7777772e6578616d706c652e636f6d"
	ja4SocksWant  = "t10d230100_6a57a6f57151_000000000000"
	ja4SocksRaw   = "t10d230100_0003,0004,0005,0006,0008,0009,000a,0011,0012,0013,0014,0015,0016,002f,0032,0033,0035,0038,0039,0096,0099,009a,00ff_"
)

func TestJA4_TLSSNI(t *testing.T) {
	res, err := JA4Decode(ja4SNIHello)
	if err != nil {
		t.Fatalf("JA4Decode: %v", err)
	}
	if res.JA4 != ja4SNIWant {
		t.Errorf("JA4\n got %q\nwant %q", res.JA4, ja4SNIWant)
	}
	if res.JA4R != ja4SNIRaw {
		t.Errorf("JA4_r\n got %q\nwant %q", res.JA4R, ja4SNIRaw)
	}
	if res.SNI != "clientservices.googleapis.com" {
		t.Errorf("SNI = %q", res.SNI)
	}
	if res.ALPN != "h2" {
		t.Errorf("ALPN = %q, want h2", res.ALPN)
	}
}

// TestJA4_SocksEmptyC covers the legacy-version path, no-ALPN ("00"), and the
// empty JA4_c ("000000000000") case (only extension is SNI, which is excluded).
func TestJA4_SocksEmptyC(t *testing.T) {
	res, err := JA4Decode(ja4SocksHello)
	if err != nil {
		t.Fatalf("JA4Decode: %v", err)
	}
	if res.JA4 != ja4SocksWant {
		t.Errorf("JA4\n got %q\nwant %q", res.JA4, ja4SocksWant)
	}
	if res.JA4R != ja4SocksRaw {
		t.Errorf("JA4_r\n got %q\nwant %q", res.JA4R, ja4SocksRaw)
	}
	if res.C != "000000000000" {
		t.Errorf("JA4_c = %q, want 000000000000", res.C)
	}
	if res.TLSVersion != "10" {
		t.Errorf("version = %q, want 10", res.TLSVersion)
	}
}

func TestJA4VersionLabels(t *testing.T) {
	cases := map[int]string{0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3", 0xfefd: "d2", 0x9999: "00"}
	for v, want := range cases {
		if got := tlsVersionLabel(v); got != want {
			t.Errorf("tlsVersionLabel(%#x) = %q, want %q", v, got, want)
		}
	}
}

func TestJA4ALPNEncoding(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{nil, "00"},
		{[]string{""}, "00"},
		{[]string{"h2"}, "h2"},
		{[]string{"http/1.1"}, "h1"},
		{[]string{"h2", "http/1.1"}, "h2"},
	}
	for _, c := range cases {
		if got := ja4ALPN(c.in); got != c.want {
			t.Errorf("ja4ALPN(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestJA4Errors(t *testing.T) {
	for _, in := range []string{"", "zz", "02000003030011"} {
		if _, err := JA4Decode(in); err == nil {
			t.Errorf("JA4Decode(%q): want error", in)
		}
	}
}
