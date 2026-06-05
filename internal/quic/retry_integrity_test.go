// SPDX-License-Identifier: AGPL-3.0-or-later

package quic

import (
	"encoding/hex"
	"testing"
)

// RFC 9001 Appendix A.4 Retry worked example: a Retry packet sent in
// response to the A.2 client Initial. The integrity check includes the
// client-chosen original DCID 0x8394c8f03e515708, which is NOT carried in
// the Retry packet itself.
const (
	rfc9001A4Retry = "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba"
	rfc9001A4ODCID = "8394c8f03e515708"
)

func TestVerifyRetryIntegrityRFC9001A4(t *testing.T) {
	pkt, _ := hex.DecodeString(rfc9001A4Retry)
	odcid, _ := hex.DecodeString(rfc9001A4ODCID)
	ok, err := VerifyRetryIntegrity(pkt, odcid)
	if err != nil {
		t.Fatalf("VerifyRetryIntegrity: %v", err)
	}
	if !ok {
		t.Error("RFC 9001 A.4 Retry tag should verify as authentic")
	}
}

func TestVerifyRetryIntegrityHex(t *testing.T) {
	// Same vector with separators, exercising the hex front door.
	ok, err := VerifyRetryIntegrityHex(
		"ff:00:00:00:01:00:08:f0:67:a5:50:2a:42:62:b5:74:6f:6b:65:6e:04:a2:65:ba:2e:ff:4d:82:90:58:fb:3f:0f:24:96:ba",
		"0x8394c8f03e515708")
	if err != nil {
		t.Fatalf("VerifyRetryIntegrityHex: %v", err)
	}
	if !ok {
		t.Error("separated A.4 vector should verify")
	}
}

func TestVerifyRetryIntegrityTampered(t *testing.T) {
	pkt, _ := hex.DecodeString(rfc9001A4Retry)
	odcid, _ := hex.DecodeString(rfc9001A4ODCID)

	// Flip one bit of the tag → must fail.
	tampered := append([]byte(nil), pkt...)
	tampered[len(tampered)-1] ^= 0x01
	if ok, err := VerifyRetryIntegrity(tampered, odcid); err != nil || ok {
		t.Errorf("tampered tag verified=%v err=%v, want verified=false err=nil", ok, err)
	}

	// Flip one bit of the token (covered by the tag) → must fail.
	tampered2 := append([]byte(nil), pkt...)
	tampered2[18] ^= 0x01
	if ok, _ := VerifyRetryIntegrity(tampered2, odcid); ok {
		t.Error("tampered Retry body should not verify")
	}

	// Wrong original DCID → must fail.
	wrong, _ := hex.DecodeString("0000000000000000")
	if ok, _ := VerifyRetryIntegrity(pkt, wrong); ok {
		t.Error("wrong original DCID should not verify")
	}
}

func TestVerifyRetryIntegrityRejects(t *testing.T) {
	odcid, _ := hex.DecodeString(rfc9001A4ODCID)
	cases := []struct {
		name string
		hex  string
	}{
		{"too short", "ff000000"},
		{"not retry (Initial type)", "c0000000010800000000000000000000000000000000000000"},
		{"v2 unsupported", "f06b3343cf0008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, _ := hex.DecodeString(c.hex)
			if _, err := VerifyRetryIntegrity(b, odcid); err == nil {
				t.Errorf("expected error for %s", c.name)
			}
		})
	}
}

// TestDecodeRetryViaTool-style: the Decode path surfaces the tag; the
// verification is wired in the tool handler, but confirm Decode still
// classifies the A.4 packet as a Retry with the right tag.
func TestDecodeRetryClassifiesA4(t *testing.T) {
	r, err := Decode(rfc9001A4Retry)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Retry == nil {
		t.Fatal("A.4 packet not classified as Retry")
	}
	const wantTag = "04A265BA2EFF4D829058FB3F0F2496BA"
	if r.Retry.IntegrityTagHex != wantTag {
		t.Errorf("integrity tag = %s, want %s", r.Retry.IntegrityTagHex, wantTag)
	}
}

// FuzzVerifyRetryIntegrity asserts the verifier never panics on arbitrary
// packet/odcid bytes — slice math over attacker-controlled lengths must
// stay in bounds.
func FuzzVerifyRetryIntegrity(f *testing.F) {
	seed, _ := hex.DecodeString(rfc9001A4Retry)
	f.Add(seed, []byte{0x83, 0x94})
	f.Add([]byte{}, []byte{})
	f.Add([]byte{0xff, 0x00, 0x00, 0x00, 0x01}, []byte("toolong-toolong-toolong-x"))
	f.Fuzz(func(_ *testing.T, pkt, odcid []byte) {
		_, _ = VerifyRetryIntegrity(pkt, odcid)
	})
}
