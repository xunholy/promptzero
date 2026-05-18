package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestMifareClassicDecodeBlockHandler_DefaultTrailer pins that
// the Spec handler decodes the canonical FFFFFFFFFFFFFF078069 …
// transport trailer through to JSON with the access-bits decoded.
func TestMifareClassicDecodeBlockHandler_DefaultTrailer(t *testing.T) {
	out, err := mifareClassicDecodeBlockHandler(context.Background(), nil, map[string]any{
		"hex":   "FFFFFFFFFFFFFF078069FFFFFFFFFFFF",
		"index": float64(3),
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"kind": "sector_trailer"`) {
		t.Errorf("kind sector_trailer missing:\n%s", out)
	}
	if !strings.Contains(out, `"access_bits_valid": true`) {
		t.Errorf("access_bits_valid true missing:\n%s", out)
	}
	var v struct {
		Trailer struct {
			KeyAHex string `json:"key_a_hex"`
			KeyBHex string `json:"key_b_hex"`
		} `json:"trailer"`
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, out)
	}
	if v.Trailer.KeyAHex != "FFFFFFFFFFFF" {
		t.Errorf("KeyAHex = %q", v.Trailer.KeyAHex)
	}
}

func TestMifareClassicDecodeBlockHandler_RejectsEmpty(t *testing.T) {
	_, err := mifareClassicDecodeBlockHandler(context.Background(), nil, map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}

// TestMifareClassicDecodeDumpHandler_FullDumpShape decodes a
// fabricated 4-sector dump and confirms the response includes
// block_count + an array of structured blocks.
func TestMifareClassicDecodeDumpHandler_FullDumpShape(t *testing.T) {
	const (
		mfr     = "04895C9F4E08040000000000000000FF"
		zero    = "00000000000000000000000000000000"
		trailer = "FFFFFFFFFFFFFF078069FFFFFFFFFFFF"
	)
	var sb strings.Builder
	for sector := 0; sector < 4; sector++ {
		for b := 0; b < 4; b++ {
			switch {
			case sector == 0 && b == 0:
				sb.WriteString(mfr)
			case b == 3:
				sb.WriteString(trailer)
			default:
				sb.WriteString(zero)
			}
		}
	}
	out, err := mifareClassicDecodeDumpHandler(context.Background(), nil, map[string]any{
		"hex": sb.String(),
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"block_count": 16`) {
		t.Errorf("block_count 16 missing:\n%s", out)
	}
	if !strings.Contains(out, `"kind": "manufacturer"`) {
		t.Errorf("manufacturer kind missing:\n%s", out)
	}
}
