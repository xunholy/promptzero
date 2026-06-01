package tools

import (
	"encoding/hex"
	"strings"
	"testing"
)

// TestEM4100Frame_RoundTrip is the verification anchor: EncodeEM4100Frame is
// the tested ground truth, so encode -> decode must recover every ID with all
// parities valid, needing no external reference vector.
func TestEM4100Frame_RoundTrip(t *testing.T) {
	ids := []string{
		"0000000000", "FFFFFFFFFF", "1234567890", "DEADBEEF01", "A5A5A5A5A5",
	}
	for _, idHex := range ids {
		id, err := hex.DecodeString(idHex)
		if err != nil {
			t.Fatalf("bad id %s: %v", idHex, err)
		}
		frame, err := EncodeEM4100Frame(id)
		if err != nil {
			t.Fatalf("encode %s: %v", idHex, err)
		}
		dec, err := DecodeEM4100Frame(frame)
		if err != nil {
			t.Fatalf("decode %s: %v", idHex, err)
		}
		if dec.IDHex != idHex {
			t.Errorf("id = %s, want %s", dec.IDHex, idHex)
		}
		if !dec.Valid || !dec.HeaderValid || !dec.RowParityOK || !dec.ColumnParityOK || !dec.StopBitValid {
			t.Errorf("%s: expected fully-valid frame, got %+v", idHex, dec)
		}
	}
}

// TestEM4100Frame_HandVectorZero checks an independently-constructed frame
// (no encoder): all-zero data -> all parities 0.
func TestEM4100Frame_HandVectorZero(t *testing.T) {
	frame := "111111111" + strings.Repeat("00000", 10) + "0000" + "0"
	if len(frame) != 64 {
		t.Fatalf("hand frame len %d, want 64", len(frame))
	}
	dec, err := DecodeEM4100Frame(frame)
	if err != nil {
		t.Fatal(err)
	}
	if dec.IDHex != "0000000000" || !dec.Valid {
		t.Errorf("zero frame -> %s valid=%v, want 0000000000/true", dec.IDHex, dec.Valid)
	}
}

// TestEM4100Frame_HandVectorOnes: all-one data -> each row has 4 ones (even,
// parity 0), each column 10 ones (even, parity 0).
func TestEM4100Frame_HandVectorOnes(t *testing.T) {
	frame := "111111111" + strings.Repeat("11110", 10) + "0000" + "0"
	dec, err := DecodeEM4100Frame(frame)
	if err != nil {
		t.Fatal(err)
	}
	if dec.IDHex != "FFFFFFFFFF" || !dec.Valid {
		t.Errorf("ones frame -> %s valid=%v, want FFFFFFFFFF/true", dec.IDHex, dec.Valid)
	}
}

func TestEM4100Frame_CorruptedParity(t *testing.T) {
	id, _ := hex.DecodeString("1234567890")
	frame, _ := EncodeEM4100Frame(id)
	// Flip the first data bit (row 0, MSB) without touching its parity bit:
	// breaks row 0 parity AND column 0 parity.
	b := []byte(frame)
	if b[9] == '0' {
		b[9] = '1'
	} else {
		b[9] = '0'
	}
	dec, err := DecodeEM4100Frame(string(b))
	if err != nil {
		t.Fatal(err)
	}
	if dec.Valid {
		t.Error("flipped data bit should invalidate the frame")
	}
	if dec.RowParityOK && dec.ColumnParityOK {
		t.Error("expected a row or column parity failure")
	}
	if len(dec.Notes) == 0 {
		t.Error("expected a parity-failure note")
	}
}

func TestEM4100Frame_Errors(t *testing.T) {
	bad := []string{
		"",                                    // empty
		strings.Repeat("1", 63),               // wrong length
		"011111111" + strings.Repeat("0", 55), // header not all ones
		"111111111" + strings.Repeat("0", 54) + "2", // non-binary char
	}
	for i, s := range bad {
		if _, err := DecodeEM4100Frame(s); err == nil {
			t.Errorf("case %d (len %d): expected error", i, len(s))
		}
	}
}
