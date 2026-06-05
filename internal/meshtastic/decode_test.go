// SPDX-License-Identifier: AGPL-3.0-or-later

package meshtastic

import "testing"

// sampleBroadcast is a Meshtastic packet built to the firmware
// PacketHeader wire layout (RadioInterface.h): to = 0xFFFFFFFF
// (broadcast), from = 0x433A1B2C (little-endian on the wire), id =
// 0x12345678, flags = 0x69 (hop_limit 1, want_ack set, hop_start 3),
// channel hash 0x08, next_hop 0x2C, relay_node 0x00, then a 4-byte
// (encrypted) payload.
const sampleBroadcast = "FFFFFFFF2C1B3A437856341269082C00AABBCCDD"

func TestDecodeBroadcast(t *testing.T) {
	r, err := Decode(sampleBroadcast)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.Broadcast || r.To != "^all (broadcast)" || r.ToHex != "0xFFFFFFFF" {
		t.Errorf("to = %s / %s / %v", r.To, r.ToHex, r.Broadcast)
	}
	if r.From != "!433a1b2c" || r.FromHex != "0x433A1B2C" {
		t.Errorf("from = %s / %s, want !433a1b2c", r.From, r.FromHex)
	}
	if r.PacketID != 0x12345678 {
		t.Errorf("packet id = 0x%08X, want 0x12345678", r.PacketID)
	}
	if r.HopLimit != 1 || r.HopStart != 3 || !r.WantAck || r.ViaMQTT {
		t.Errorf("flags = limit %d start %d ack %v mqtt %v", r.HopLimit, r.HopStart, r.WantAck, r.ViaMQTT)
	}
	if r.HopsTaken == nil || *r.HopsTaken != 2 {
		t.Errorf("hops_taken = %v, want 2", r.HopsTaken)
	}
	if r.ChannelHash != "0x08" || r.NextHop != "0x2C" || r.RelayNode != "0x00" {
		t.Errorf("channel/nexthop/relay = %s / %s / %s", r.ChannelHash, r.NextHop, r.RelayNode)
	}
	if r.PayloadLength != 4 || r.PayloadHex != "AABBCCDD" {
		t.Errorf("payload = %d / %s", r.PayloadLength, r.PayloadHex)
	}
}

func TestDecodeDirected(t *testing.T) {
	// Directed packet to !a1b2c3d4 (LE D4 C3 B2 A1), via MQTT, no want-ack.
	r, err := Decode("D4C3B2A1 2C1B3A43 01000000 10 1F 00 00")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Broadcast || r.To != "!a1b2c3d4" {
		t.Errorf("to = %s (broadcast %v), want !a1b2c3d4", r.To, r.Broadcast)
	}
	if !r.ViaMQTT || r.WantAck {
		t.Errorf("flags via_mqtt/want_ack = %v / %v, want true/false", r.ViaMQTT, r.WantAck)
	}
	if r.HopLimit != 0 || r.HopStart != 0 || r.HopsTaken != nil {
		t.Errorf("hops = limit %d start %d taken %v", r.HopLimit, r.HopStart, r.HopsTaken)
	}
	if r.PayloadLength != 0 {
		t.Errorf("payload length = %d, want 0", r.PayloadLength)
	}
}

func TestDecodeRejectsShort(t *testing.T) {
	for _, c := range []string{"", "FFFFFFFF", "FFFFFFFF2C1B3A437856341269082C", "zz"} {
		if _, err := Decode(c); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(sampleBroadcast)
	f.Add("FFFFFFFF2C1B3A437856341269082C00")
	f.Add("")
	f.Add("00")
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s)
	})
}
