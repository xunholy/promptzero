package tools

import (
	"strings"
	"testing"
)

// TestEncodeEM4100Frame_Invariants independently re-derives the EM4100 frame
// structure from the encoder's output — header, every row parity, every
// column parity, the stop bit, and the recovered nibbles — and asserts they
// match. This verifies the encoder against the documented frame definition
// without a (potentially co-buggy) decoder.
func TestEncodeEM4100Frame_Invariants(t *testing.T) {
	ids := [][]byte{
		{0x00, 0x00, 0x00, 0x00, 0x00},
		{0x12, 0x34, 0x56, 0x78, 0x90},
		{0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		{0xDE, 0xAD, 0xBE, 0xEF, 0x01},
	}
	for _, id := range ids {
		f, err := EncodeEM4100Frame(id)
		if err != nil {
			t.Fatalf("EncodeEM4100Frame(%X): %v", id, err)
		}
		if len(f) != 64 {
			t.Fatalf("%X: frame len %d, want 64", id, len(f))
		}
		if f[:9] != "111111111" {
			t.Errorf("%X: header = %q, want 9 ones", id, f[:9])
		}
		if f[63] != '0' {
			t.Errorf("%X: stop bit = %c, want 0", id, f[63])
		}
		nibbles := make([]int, 10)
		var cols [4]int
		for r := 0; r < 10; r++ {
			base := 9 + r*5
			ones, nib := 0, 0
			for b := 0; b < 4; b++ {
				bit := int(f[base+b] - '0')
				nib = nib<<1 | bit
				ones += bit
				cols[b] ^= bit
			}
			nibbles[r] = nib
			if int(f[base+4]-'0') != ones&1 {
				t.Errorf("%X: row %d parity wrong", id, r)
			}
		}
		for i := 0; i < 5; i++ {
			if got := byte(nibbles[2*i]<<4 | nibbles[2*i+1]); got != id[i] {
				t.Errorf("%X: recovered byte %d = %02X", id, i, got)
			}
		}
		for c := 0; c < 4; c++ {
			if int(f[59+c]-'0') != cols[c]&1 {
				t.Errorf("%X: column %d parity wrong", id, c)
			}
		}
	}
}

// TestEncodeEM4100Frame_ZeroVector pins the all-zeros frame: 9 header ones
// then 55 zeros (50 data+row-parity + 4 column-parity + 1 stop, all zero).
func TestEncodeEM4100Frame_ZeroVector(t *testing.T) {
	f, err := EncodeEM4100Frame([]byte{0, 0, 0, 0, 0})
	if err != nil {
		t.Fatalf("EncodeEM4100Frame: %v", err)
	}
	want := "111111111" + strings.Repeat("0", 55)
	if f != want {
		t.Errorf("zero frame = %q, want %q", f, want)
	}
}

func TestEncodeEM4100Frame_BadLength(t *testing.T) {
	for _, id := range [][]byte{{}, {0x01}, {0, 0, 0, 0}, {0, 0, 0, 0, 0, 0}} {
		if _, err := EncodeEM4100Frame(id); err == nil {
			t.Errorf("EncodeEM4100Frame(%d bytes): expected error", len(id))
		}
	}
}
