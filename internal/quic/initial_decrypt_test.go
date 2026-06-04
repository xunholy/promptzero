// SPDX-License-Identifier: AGPL-3.0-or-later

package quic

import (
	"encoding/hex"
	"strings"
	"testing"
)

// rfc9001A2ProtectedPacket is the complete on-the-wire client Initial
// packet from RFC 9001 Appendix A.2 (1200 bytes, padded). DCID =
// 8394c8f03e515708, packet number 2.
const rfc9001A2ProtectedPacket = "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11" +
	"d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399" +
	"1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c" +
	"8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212" +
	"30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5" +
	"457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208" +
	"4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec" +
	"4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3" +
	"485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db" +
	"059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c" +
	"7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8" +
	"9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556" +
	"be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74" +
	"68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a" +
	"c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00" +
	"f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632" +
	"291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964" +
	"25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd" +
	"14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff" +
	"ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198" +
	"e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd" +
	"c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73" +
	"203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f" +
	"cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e" +
	"fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade" +
	"a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047" +
	"90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2" +
	"162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4" +
	"40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0" +
	"6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e" +
	"8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0" +
	"be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400" +
	"54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab" +
	"760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9" +
	"f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4" +
	"056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064" +
	"7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241" +
	"e221af44860018ab0856972e194cd934"

// rfc9001A2CryptoFrameHead is the start of the unprotected payload from
// RFC 9001 A.2 — a CRYPTO frame (type 0x06, offset 0, length 0xf1)
// carrying the ClientHello (handshake type 0x01).
const rfc9001A2CryptoFrameHead = "060040f1010000ed0303ebf8fa56f129"

// rfc9001A1Key / IV / HP are the derived client Initial secrets from
// RFC 9001 Appendix A.1, which DecryptInitial must reproduce.
const (
	rfc9001A1Key = "1f369613dd76d5467730efcbe3b1a22d"
	rfc9001A1IV  = "fa044b2f42a3fd3b46fb255c"
	rfc9001A1HP  = "9f50449e04a0e810283a1e9933adedd2"
)

func TestDecryptInitialRFC9001A2(t *testing.T) {
	pkt, err := hex.DecodeString(rfc9001A2ProtectedPacket)
	if err != nil {
		t.Fatalf("decode vector: %v", err)
	}
	d, err := DecryptInitial(pkt, "client")
	if err != nil {
		t.Fatalf("DecryptInitial: %v", err)
	}

	// Derived keys must match RFC 9001 A.1 byte-for-byte.
	if d.KeyHex != rfc9001A1Key {
		t.Errorf("key = %s, want %s", d.KeyHex, rfc9001A1Key)
	}
	if d.IVHex != rfc9001A1IV {
		t.Errorf("iv = %s, want %s", d.IVHex, rfc9001A1IV)
	}
	if d.HPHex != rfc9001A1HP {
		t.Errorf("hp = %s, want %s", d.HPHex, rfc9001A1HP)
	}
	if d.PacketNumber != 2 {
		t.Errorf("packet number = %d, want 2", d.PacketNumber)
	}
	if d.PacketNumberLen != 4 {
		t.Errorf("packet number length = %d, want 4", d.PacketNumberLen)
	}
	if d.PayloadLen != 1162 {
		t.Errorf("payload length = %d, want 1162", d.PayloadLen)
	}

	// The CRYPTO stream must be the ClientHello and start with the
	// documented handshake bytes (CRYPTO frame head minus its 4-byte
	// frame header 060040f1 → handshake body 010000ed0303...).
	wantCH := strings.ToUpper(strings.TrimPrefix(rfc9001A2CryptoFrameHead, "060040f1"))
	if !strings.HasPrefix(d.CryptoStreamHex, wantCH) {
		t.Errorf("crypto stream head = %.24s, want prefix %s", d.CryptoStreamHex, wantCH)
	}
	if d.CryptoStreamLen != 241 { // 0xf1
		t.Errorf("crypto stream length = %d, want 241", d.CryptoStreamLen)
	}
	if !strings.HasPrefix(d.TLSMessage, "ClientHello") {
		t.Errorf("tls message = %q, want ClientHello", d.TLSMessage)
	}

	// Frames: one CRYPTO at offset 0 length 241, then PADDING.
	var sawCrypto, sawPadding bool
	for _, f := range d.Frames {
		switch f.Type {
		case "CRYPTO":
			sawCrypto = true
			if f.Offset != 0 || f.Length != 241 {
				t.Errorf("CRYPTO frame offset/length = %d/%d, want 0/241", f.Offset, f.Length)
			}
		case "PADDING":
			sawPadding = true
			if f.Count != 917 { // 1162 - 245 (4-byte frame header + 241 data)
				t.Errorf("PADDING run = %d, want 917", f.Count)
			}
		}
	}
	if !sawCrypto || !sawPadding {
		t.Errorf("expected CRYPTO + PADDING frames, got %+v", d.Frames)
	}
}

// TestDecryptInitialViaDecode confirms the top-level Decode wires the
// decrypted view onto the Initial packet.
func TestDecryptInitialViaDecode(t *testing.T) {
	r, err := Decode(rfc9001A2ProtectedPacket)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Initial == nil {
		t.Fatal("no Initial packet decoded")
	}
	if r.Initial.Decrypted == nil {
		t.Fatal("Initial was not decrypted")
	}
	if r.Initial.Decrypted.Role != "client" {
		t.Errorf("role = %q, want client", r.Initial.Decrypted.Role)
	}
	if !strings.HasPrefix(r.Initial.Decrypted.TLSMessage, "ClientHello") {
		t.Errorf("tls message = %q, want ClientHello", r.Initial.Decrypted.TLSMessage)
	}
}

// TestDecryptInitialWrongRole asserts the client packet fails to
// authenticate under the server keys (AEAD integrity holds).
func TestDecryptInitialWrongRole(t *testing.T) {
	pkt, _ := hex.DecodeString(rfc9001A2ProtectedPacket)
	if _, err := DecryptInitial(pkt, "server"); err == nil {
		t.Error("expected GCM authentication failure decrypting a client Initial as server")
	}
}

func TestDecryptInitialRejectsBadInput(t *testing.T) {
	cases := []struct {
		name string
		hex  string
		role string
	}{
		{"bad role", rfc9001A2ProtectedPacket, "middlebox"},
		{"short header", "401234", "client"},
		{"too short", "c000", "client"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, _ := hex.DecodeString(c.hex)
			if _, err := DecryptInitial(b, c.role); err == nil {
				t.Errorf("expected error for %s", c.name)
			}
		})
	}
}

// FuzzDecryptInitial asserts the decrypt path never panics on arbitrary
// bytes — the frame walker, VLI reads, and slice math over an
// attacker-controlled (and only sometimes authentic) payload must stay
// in bounds. The RFC 9001 A.2 packet seeds the authentic path.
func FuzzDecryptInitial(f *testing.F) {
	seed, _ := hex.DecodeString(rfc9001A2ProtectedPacket)
	f.Add(seed)
	f.Add([]byte{})
	f.Add([]byte{0xc0, 0x00, 0x00, 0x00, 0x01})
	f.Fuzz(func(_ *testing.T, b []byte) {
		_, _ = DecryptInitial(b, "client")
		_, _ = DecryptInitial(b, "server")
	})
}
