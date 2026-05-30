package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// encodeManchesterIEEE encodes payload bytes (MSB-first) to a '0'/'1'
// bit string under the IEEE 802.3 convention (data 0 = "10", data
// 1 = "01"). It is the inverse of the decoder's line stage, so a
// round trip exercises the Spec handler without a real sensor
// capture. Kept local to the tools package (the internal/tpms
// encoder is test-private there).
func encodeManchesterIEEE(payload []byte) string {
	var sb strings.Builder
	for _, b := range payload {
		for j := 7; j >= 0; j-- {
			if (b>>uint(j))&1 == 1 {
				sb.WriteString("01")
			} else {
				sb.WriteString("10")
			}
		}
	}
	return sb.String()
}

// crc8x07 computes the CRC-8/SMBUS (poly 0x07, init 0x00) used to
// build a payload whose trailing byte validates, so the handler
// reports the convention as CRC-disambiguated rather than ambiguous.
func crc8x07(data []byte) byte {
	var crc byte
	for _, b := range data {
		crc ^= b
		for i := 0; i < 8; i++ {
			if crc&0x80 != 0 {
				crc = crc<<1 ^ 0x07
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// TestTpmsDecodeHandler_HappyPath feeds a Manchester-encoded payload
// with a valid trailing CRC-8 and confirms the Spec handler decodes
// it into JSON the agent can re-render: sensor ID, decoded hex, and
// CRC match all surface.
func TestTpmsDecodeHandler_HappyPath(t *testing.T) {
	data := []byte{0x1A, 0x2B, 0x3C, 0x4D, 0x80, 0x55}
	payload := append(append([]byte{}, data...), crc8x07(data))
	bits := encodeManchesterIEEE(payload)

	out, err := tpmsDecodeHandler(context.Background(), nil, map[string]any{"bits": bits})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	var got struct {
		LineCoding      string   `json:"line_coding"`
		DecodedHex      string   `json:"decoded_hex"`
		SensorID        string   `json:"sensor_id"`
		SensorIDDecimal *uint32  `json:"sensor_id_decimal"`
		CRC8Matches     []string `json:"crc8_matches"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output not valid JSON: %v\n%s", err, out)
	}
	if got.SensorID != "1A2B3C4D" {
		t.Errorf("SensorID = %q; want 1A2B3C4D\n%s", got.SensorID, out)
	}
	if got.SensorIDDecimal == nil || *got.SensorIDDecimal != 0x1A2B3C4D {
		t.Errorf("SensorIDDecimal = %v; want 0x1A2B3C4D", got.SensorIDDecimal)
	}
	if !strings.HasPrefix(got.DecodedHex, "1A2B3C4D8055") {
		t.Errorf("DecodedHex = %q; want 1A2B3C4D8055 prefix", got.DecodedHex)
	}
	var hasCRC bool
	for _, m := range got.CRC8Matches {
		if m == "CRC-8/0x07" {
			hasCRC = true
		}
	}
	if !hasCRC {
		t.Errorf("CRC8Matches = %v; want to contain CRC-8/0x07", got.CRC8Matches)
	}
	if !strings.HasPrefix(got.LineCoding, "Manchester (IEEE") {
		t.Errorf("LineCoding = %q; want IEEE convention", got.LineCoding)
	}
}

func TestTpmsDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := tpmsDecodeHandler(context.Background(), nil, map[string]any{})
	if err == nil {
		t.Fatal("want error for missing bits")
	}
	if !strings.Contains(err.Error(), "required") {
		t.Errorf("err = %v; want 'required'", err)
	}
}

func TestTpmsDecodeHandler_RejectsNonBinary(t *testing.T) {
	_, err := tpmsDecodeHandler(context.Background(), nil, map[string]any{"bits": "0102"})
	if err == nil {
		t.Fatal("want error for non-binary bit-stream")
	}
}
