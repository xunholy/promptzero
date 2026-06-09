package ja3

import (
	"crypto/md5" //nolint:gosec // verifying the JA3 spec's own MD5 example.
	"encoding/hex"
	"strings"
	"testing"
)

// realHello is a genuine TLS 1.3 ClientHello captured from `openssl s_client
// -connect example.com:443 -msg`. wantJA3 / wantDigest are the Salesforce
// reference implementation's (pyja3) output for these exact bytes — the
// authoritative oracle for the field extraction.
const (
	realHello = "010005fd0303024db9437ec0c3097ada827cf4a8705a73d52820186463a1df89db09cccad867202173a2c1113a8e35618154ed2a250d5fa062b5cb699c274627de3e26ff970e1e003c130213031301c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067c00ac0140039c009c0130033009d009c003d003c0035002f01000578ff0100010000000010000e00000b6578616d706c652e636f6d000b00020100000a0012001011ec001d0017001e0018001901000101002300000016000000170000000d0036003409050906090404030503060308070808081a081b081c0809080a080b080408050806040105010601030303010302040205020602002b00050403040303002d00020101003304ea04e811ec04c0b5d887b491486ef91bfcec5b3214a884346baac284a7255cd3469b4e2015ef6178d0d3b9734284f9cbaad740a6c825a264a79f95ccb67191236107085c439898e982b2788bfaabb9af40c8d7d31ee4376d33a58ed50320befabe16d06ad1f41cea618b62854b49254c4c13c0faab0ad451035552b35be65210f3921c019643998f65976e6c23aee8402e694c7948b26535fc4fb95b1bd27a9c8f9bc8ba1b590e303902030620e151e493659644a70b3010a2f64b68102a6fe4404aa8ca54f60c6d228ddc2a3622e7a990a5c827465fef5b3b45fa82d139b02cdc4d6b4c476df58dc2fa4d924288b58c192c836f0f053b1cb00e8c23b8f0430ce3006c64a90fbe343a6481c82f92beb4c25d17ca03727638ee3ca3400b395d1290d9a89c7ec2a8f60b75adfa64c5ac1b278b930c754bcd0c786f4912176983a97684ae60004c63129b8abb6a264315f6b01414bdaea0c777875587497347061d31875434614dd7020d0221827e36592a6cc6fa06c58cf8b7415932ae776601d0204584207b0a9a901993f8a3a1ef74589cd03af9339fb331be86d40cc7245cb9f9434c2b3eff66689391a3cfb8b6fc07d0adc44cc35b006d4bac5b006ff2157f6ac33a32d44bce27121057b76c099b3cc72f91e2253cf4420f350039a41b8fd244e3a661a76b0b4a4089cbe93fcb981b8c027948bc83c27a545922a81a18a908ccaf6dd12e8a6aab28025c9098a3324553d425b8498231706a126c44037ac0457559b10d8225ce36198f88812841c82fa28a0a2820b9715381a77802918fb25ba2f7236cc7487f6e9cbe5bc3291f358c9d837d510c3fca031f1af307007bbaaf4776233c21d52792082a02c21c1f7e651c026c885ce158729b04d140740ae29002ec69fd59b6d319b60bc609b04488e2ba6bb9d4c87d58241b2694776c7f7d92a5db343286b7bb203179c07256b3928ebc442b864145ef1a2e5913b0d6d0711df53832a37eee171bee388a7e65b43ce4b04c331e317c0aadb1a0d29cc17649b438854df59741eac081b9028225f3351fd50128186e7bd79d6cb3c326823a3e8c91df7934c2f2695cd876ed7053fdca4da5438a1f65054a36046ef61719c335a2b8655897264483ac379c3fc0c27dd87116b4fb483947350ae1416b8b98bfe2b88a5a7929a816266ca6b34277ef5749f2172865816accd96da5a2a3aac682f797c15452a918c636c9d1b7f71700570377b22c59c58ba3a2b34946c4a930a7ab54e0aadf2a190bdbb3674c1c11978591d379ede285f372431d27314ea09d344823c1b77f2475c93b919bffc893e24b10b0581b94c837740385fba904ee485e7ada4ec80b9b653948d218bd1ff05cdf25c09cf5a21f7999016769e4f750708a0d9d00b32da25f86f29d6eb5c8bd17c987a07e67eabe0cda33cf589da2e42332773a8f4b742d515ff8e91c0cb856ba8a44999491e9216db9c8ae8b29428311ce39a83e80b44d6457105e15bc7965384017acb992a35df821318363bf484b2ba21133c3611e889bbce73454805122b86025d5432491b5c5e816c57478cb745c82cb8c5f7c16ede17ad91cadb79c7d63e8b7bedaca6f9c96065539218c3ae8e52118a46a4550850186280cc7894da5f457f68784618317623cf9f834956b8e98891244647f6dfcf24fdf5f426149bdcad5410ff592aa8d8f6ef9d5a7884259cccc7b60930163b639ef43001d00200b3d8116e6a02a85815beac357944c5a292693356ddac0e1607d0e8a939c8c56"
	realJA3   = "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47,65281-0-11-10-35-22-23-13-43-45-51,4588-29-23-30-24-25-256-257,0"
	realDgst  = "0b85eb0d4981e69064e40753e4f0ac5f"

	// greaseHello is a hand-built ClientHello carrying GREASE values 0x1a1a
	// (cipher), 0x3a3a (extension), 0x2a2a (group); pyja3 strips them.
	greaseHello = "0100005d0303111111111111111111111111111111111111111111111111111111111111111100000a1a1a13011302c02f002f0100002a3a3a000000000010000e00000b6578616d706c652e636f6d000a000800062a2a001d0017000b00020100"
	greaseJA3   = "771,4865-4866-49199-47,0-10-11,29-23,0"
	greaseDgst  = "c8b1996d9cd777777fbe91c5650c3c37"
)

func TestRealClientHello(t *testing.T) {
	res, err := Decode(realHello)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if res.JA3 != realJA3 {
		t.Errorf("JA3 string mismatch\n got %q\nwant %q", res.JA3, realJA3)
	}
	if res.JA3Digest != realDgst {
		t.Errorf("digest = %q, want %q", res.JA3Digest, realDgst)
	}
	if res.SNI != "example.com" {
		t.Errorf("SNI = %q, want example.com", res.SNI)
	}
	if res.TLSVersion != 771 {
		t.Errorf("version = %d, want 771", res.TLSVersion)
	}
}

// TestGREASEStripped pins the GREASE-removal path to the reference oracle.
func TestGREASEStripped(t *testing.T) {
	res, err := Decode(greaseHello)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if res.JA3 != greaseJA3 {
		t.Errorf("JA3 string mismatch\n got %q\nwant %q", res.JA3, greaseJA3)
	}
	if res.JA3Digest != greaseDgst {
		t.Errorf("digest = %q, want %q", res.JA3Digest, greaseDgst)
	}
	for _, c := range res.Ciphers {
		if isGREASE(uint16(c)) {
			t.Errorf("GREASE cipher %d not stripped", c)
		}
	}
}

// TestSpecMD5Examples pins the string→MD5 step to the two worked examples in
// the JA3 specification (salesforce/ja3 README).
func TestSpecMD5Examples(t *testing.T) {
	cases := []struct{ s, want string }{
		{"769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0", "ada70206e40642a3e4461f35503241d5"},
		{"769,4-5-10-9-100-98-3-6-19-18-99,,,", "de350869b8c85de67a350c8d186f11e6"},
	}
	for _, c := range cases {
		sum := md5.Sum([]byte(c.s)) //nolint:gosec // spec example.
		if got := hex.EncodeToString(sum[:]); got != c.want {
			t.Errorf("MD5(%q) = %q, want %q", c.s, got, c.want)
		}
	}
}

// TestTLSRecordWrapper confirms a full TLS record (0x16 …) is unwrapped to the
// same JA3 as the bare handshake.
func TestTLSRecordWrapper(t *testing.T) {
	raw, _ := hex.DecodeString(greaseHello)
	rec := append([]byte{0x16, 0x03, 0x01, byte(len(raw) >> 8), byte(len(raw))}, raw...)
	res, err := FromClientHello(rec)
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if res.JA3Digest != greaseDgst {
		t.Errorf("digest = %q, want %q", res.JA3Digest, greaseDgst)
	}
}

func TestServerHelloRejected(t *testing.T) {
	// Handshake type 0x02 = ServerHello.
	_, err := Decode("02000003030011")
	if err == nil || !strings.Contains(err.Error(), "ServerHello") {
		t.Errorf("want ServerHello rejection, got %v", err)
	}
}

func TestErrors(t *testing.T) {
	cases := []string{"", "zz", "01", "0100ffff0303"}
	for _, c := range cases {
		if _, err := Decode(c); err == nil {
			t.Errorf("Decode(%q): want error, got nil", c)
		}
	}
}

// TestColonHexAccepted confirms colon/whitespace-delimited hex is accepted.
func TestColonHexAccepted(t *testing.T) {
	spaced := ""
	for i := 0; i < len(greaseHello); i += 2 {
		spaced += greaseHello[i:i+2] + " "
	}
	res, err := Decode(spaced)
	if err != nil {
		t.Fatalf("spaced hex: %v", err)
	}
	if res.JA3Digest != greaseDgst {
		t.Errorf("digest = %q, want %q", res.JA3Digest, greaseDgst)
	}
}
