// SPDX-License-Identifier: AGPL-3.0-or-later

package cyfral

import (
	"fmt"
	"testing"
)

// Encode then Decode must reproduce the key for every 16-bit value, and the
// emitted frame must always start/stop with 0b0001 and use only valid data
// nibbles — the strongest verification for an inverse generator (the shipped
// decoder is the independent oracle, and the format has no checksum beyond the
// nibble constraints).
func TestEncode_RoundTripAll(t *testing.T) {
	for key := 0; key <= 0xFFFF; key++ {
		b := Encode(uint16(key))
		if len(b) != 5 {
			t.Fatalf("Encode(%#04x): got %d bytes, want 5", key, len(b))
		}
		got, err := Decode(fmt.Sprintf("%X", b))
		if err != nil {
			t.Fatalf("Decode of Encode(%#04x)=%X: %v", key, b, err)
		}
		if got.Key != key {
			t.Fatalf("round-trip: Encode(%#04x) decoded to %#04x", key, got.Key)
		}
	}
}

// Hand-checkable boundary vectors: all-ones data nibbles are 0xE, all-zero are
// 0x7, framed by the 0x1 start/stop.
func TestEncode_AnchorVectors(t *testing.T) {
	cases := []struct {
		key  uint16
		want string
	}{
		{0xFFFF, "1EEEEEEEE1"}, // every pair 11 -> E
		{0x0000, "1777777771"}, // every pair 00 -> 7
		{0xE4E4, "1EDB7EDB71"}, // the decoder's published hand-traced vector
	}
	for _, c := range cases {
		if got := EncodeHex(c.key); got != c.want {
			t.Errorf("EncodeHex(%#04x) = %s, want %s", c.key, got, c.want)
		}
	}
}
