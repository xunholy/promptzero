// SPDX-License-Identifier: AGPL-3.0-or-later

package uuidinfo

import (
	"encoding/binary"
	"fmt"
	"testing"
)

// Expected values are Python's reference uuid module's.
func TestV1(t *testing.T) {
	r, err := Decode("a8098c1a-f86e-11da-bd1a-00112444be1e")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 1 {
		t.Errorf("version = %d, want 1", r.Version)
	}
	if r.TimestampUTC != "2006-06-10T10:48:31.013993Z" {
		t.Errorf("timestamp = %q, want 2006-06-10T10:48:31.013993Z", r.TimestampUTC)
	}
	if r.Node != "00:11:24:44:be:1e" || !r.NodeIsMAC {
		t.Errorf("node = %q is_mac=%v, want 00:11:24:44:be:1e / true (MAC leak)", r.Node, r.NodeIsMAC)
	}
	if r.ClockSeq != 15642 {
		t.Errorf("clock_seq = %d, want 15642", r.ClockSeq)
	}
}

// A v1 with the node multicast bit set is a randomized node, not a MAC leak.
func TestV1RandomizedNode(t *testing.T) {
	r, _ := Decode("a8098c1a-f86e-11da-bd1a-01112444be1e") // node 01.. -> multicast bit set
	if r.NodeIsMAC {
		t.Error("node_is_mac = true, want false for a multicast-bit-set node")
	}
}

func TestV7(t *testing.T) {
	r, err := Decode("017f22e2-79b0-7cc3-98c4-dc0c0c07398f")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 7 || r.UnixMillis != 1645557742000 {
		t.Errorf("v7 version=%d ms=%d, want 7/1645557742000", r.Version, r.UnixMillis)
	}
	if r.TimestampUTC != "2022-02-22T19:22:22Z" {
		t.Errorf("v7 timestamp = %q, want 2022-02-22T19:22:22Z", r.TimestampUTC)
	}
}

func TestVersionDetection(t *testing.T) {
	cases := map[string]int{
		"f47ac10b-58cc-4372-a567-0e02b2c3d479": 4,
		"3d813cbb-47fb-32ba-91df-831e1593ac29": 3,
		"21f7f8de-8051-5b89-8680-0195ef798b6a": 5,
	}
	for s, want := range cases {
		r, err := Decode(s)
		if err != nil || r.Version != want {
			t.Errorf("Decode(%s) version = %d (%v), want %d", s, r.Version, err, want)
		}
		if r.TimestampUTC != "" || r.Node != "" {
			t.Errorf("Decode(%s) leaked timestamp/node on a non-time UUID", s)
		}
	}
}

// v6 cross-check: a v6 UUID encoding the same 60-bit instant as the v1 example
// must decode to the same UTC timestamp (the reference module does not decode v6
// time, so this anchors v6 against the oracle-verified v1 instant).
func TestV6CrossCheck(t *testing.T) {
	const ticks = 133692293110139930 // the v1 example's time_ticks (oracle)
	var b [16]byte
	binary.BigEndian.PutUint32(b[0:4], uint32(ticks>>28))
	binary.BigEndian.PutUint16(b[4:6], uint16((ticks>>12)&0xffff))
	binary.BigEndian.PutUint16(b[6:8], 0x6000|uint16(ticks&0x0fff)) // version 6
	b[8] = 0x80                                                     // RFC variant
	copy(b[10:16], []byte{0x00, 0x11, 0x24, 0x44, 0xbe, 0x1e})
	r, err := Decode(fmt.Sprintf("%x", b[:]))
	if err != nil {
		t.Fatalf("Decode v6: %v", err)
	}
	if r.Version != 6 || r.TimestampUTC != "2006-06-10T10:48:31.013993Z" {
		t.Errorf("v6 version=%d ts=%q, want 6 / same instant as v1", r.Version, r.TimestampUTC)
	}
	if r.Node != "00:11:24:44:be:1e" {
		t.Errorf("v6 node = %q, want 00:11:24:44:be:1e", r.Node)
	}
}

func TestNilAndForms(t *testing.T) {
	r, _ := Decode("00000000-0000-0000-0000-000000000000")
	if r.VersionName != "nil UUID" {
		t.Errorf("nil version_name = %q", r.VersionName)
	}
	// urn / braces / no-dashes forms all parse to the same UUID.
	for _, s := range []string{
		"urn:uuid:a8098c1a-f86e-11da-bd1a-00112444be1e",
		"{a8098c1a-f86e-11da-bd1a-00112444be1e}",
		"a8098c1af86e11dabd1a00112444be1e",
	} {
		r, err := Decode(s)
		if err != nil || r.UUID != "a8098c1a-f86e-11da-bd1a-00112444be1e" {
			t.Errorf("Decode(%q) = %q (%v)", s, r.UUID, err)
		}
	}
}

func TestRejects(t *testing.T) {
	for _, in := range []string{"", "not-a-uuid", "a8098c1a-f86e-11da-bd1a-00112444be1", "zzzzzzzz-f86e-11da-bd1a-00112444be1e"} {
		if _, err := Decode(in); err == nil {
			t.Errorf("Decode(%q) = nil error, want rejection", in)
		}
	}
}
