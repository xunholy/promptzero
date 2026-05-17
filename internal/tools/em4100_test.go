package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestDecodeEM4100_KnownVectors pins the decoder against published
// EM4100 examples. Vectors picked from the Wikipedia EM4100 article
// and the public Flipper firmware lfrfid testdata.
func TestDecodeEM4100_KnownVectors(t *testing.T) {
	cases := []struct {
		in                   string
		wantHexID            string
		wantVersion          uint8
		wantCardNumber       uint32
		wantCardNumDecimal10 string
		wantFacility16       uint16
		wantCard16           uint16
	}{
		{
			in:                   "1A2B3C4D5E",
			wantHexID:            "1A2B3C4D5E",
			wantVersion:          0x1A,
			wantCardNumber:       0x2B3C4D5E,
			wantCardNumDecimal10: "0725372254",
			wantFacility16:       0x2B3C,
			wantCard16:           0x4D5E,
		},
		// Mixed case + separators tolerated.
		{
			in:                   "00:08:12:a3:c5",
			wantHexID:            "000812A3C5",
			wantVersion:          0x00,
			wantCardNumber:       0x0812A3C5,
			wantCardNumDecimal10: "0135439301",
			wantFacility16:       0x0812,
			wantCard16:           0xA3C5,
		},
		{
			in:                   "ff-ff-ff-ff-ff",
			wantHexID:            "FFFFFFFFFF",
			wantVersion:          0xFF,
			wantCardNumber:       0xFFFFFFFF,
			wantCardNumDecimal10: "4294967295",
			wantFacility16:       0xFFFF,
			wantCard16:           0xFFFF,
		},
		// Whitespace separators.
		{
			in:                   "01 02 03 04 05",
			wantHexID:            "0102030405",
			wantVersion:          0x01,
			wantCardNumber:       0x02030405,
			wantCardNumDecimal10: "0033752069",
			wantFacility16:       0x0203,
			wantCard16:           0x0405,
		},
	}
	for _, c := range cases {
		got, err := DecodeEM4100(c.in)
		if err != nil {
			t.Errorf("DecodeEM4100(%q): %v", c.in, err)
			continue
		}
		if got.HexID != c.wantHexID {
			t.Errorf("HexID = %q; want %q", got.HexID, c.wantHexID)
		}
		if got.VersionByte != c.wantVersion {
			t.Errorf("VersionByte = 0x%02X; want 0x%02X", got.VersionByte, c.wantVersion)
		}
		if got.CardNumber != c.wantCardNumber {
			t.Errorf("CardNumber = %d (0x%X); want %d (0x%X)",
				got.CardNumber, got.CardNumber, c.wantCardNumber, c.wantCardNumber)
		}
		if got.CardNumberDecimal10 != c.wantCardNumDecimal10 {
			t.Errorf("CardNumberDecimal10 = %q; want %q",
				got.CardNumberDecimal10, c.wantCardNumDecimal10)
		}
		if got.FacilityCode16 != c.wantFacility16 {
			t.Errorf("FacilityCode16 = %d; want %d", got.FacilityCode16, c.wantFacility16)
		}
		if got.CardNumber16 != c.wantCard16 {
			t.Errorf("CardNumber16 = %d; want %d", got.CardNumber16, c.wantCard16)
		}
	}
}

func TestDecodeEM4100_SentinelFlags(t *testing.T) {
	zero, err := DecodeEM4100("0000000000")
	if err != nil {
		t.Fatalf("zero: %v", err)
	}
	if !zero.AllZero {
		t.Error("all-zero input must set AllZero=true")
	}
	if zero.AllFF {
		t.Error("all-zero input must NOT set AllFF=true")
	}

	ff, err := DecodeEM4100("FFFFFFFFFF")
	if err != nil {
		t.Fatalf("FF: %v", err)
	}
	if !ff.AllFF {
		t.Error("all-FF input must set AllFF=true")
	}
	if ff.AllZero {
		t.Error("all-FF input must NOT set AllZero=true")
	}

	normal, err := DecodeEM4100("0102030405")
	if err != nil {
		t.Fatalf("normal: %v", err)
	}
	if normal.AllZero || normal.AllFF {
		t.Errorf("normal input flagged as sentinel: AllZero=%v AllFF=%v", normal.AllZero, normal.AllFF)
	}
}

func TestDecodeEM4100_Errors(t *testing.T) {
	cases := []string{
		"",
		"   ",
		"1A2B3C4D5",   // 9 chars — too short
		"1A2B3C4D5EF", // 11 chars — too long
		"GGGGGGGGGG",  // non-hex
		"1A:2B:3C",    // too short after strip
	}
	for _, in := range cases {
		_, err := DecodeEM4100(in)
		if err == nil {
			t.Errorf("DecodeEM4100(%q) = nil; want error", in)
		}
	}
}

func TestEM4100DecodeHandler_HappyPathProducesJSON(t *testing.T) {
	out, err := em4100DecodeHandler(context.Background(), nil, map[string]any{
		"hex": "1A2B3C4D5E",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	var card EM4100Card
	if err := json.Unmarshal([]byte(out), &card); err != nil {
		t.Fatalf("output not valid JSON: %v\n%s", err, out)
	}
	if card.HexID != "1A2B3C4D5E" {
		t.Errorf("round-trip HexID = %q; want 1A2B3C4D5E", card.HexID)
	}
}

func TestEM4100DecodeHandler_RejectsEmpty(t *testing.T) {
	for _, in := range []string{"", "   "} {
		_, err := em4100DecodeHandler(context.Background(), nil, map[string]any{"hex": in})
		if err == nil {
			t.Errorf("handler(hex=%q) = nil; want 'hex is required' error", in)
		}
		if err != nil && !strings.Contains(err.Error(), "hex") {
			t.Errorf("err = %v; want mention of hex field", err)
		}
	}
}
