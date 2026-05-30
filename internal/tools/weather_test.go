package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestWeatherDecodeHandler_Acurite609 builds a valid Acurite 609TXC
// frame (8-bit sum checksum) as hex and confirms the Spec handler
// decodes it into JSON with the interpreted reading.
func TestWeatherDecodeHandler_Acurite609(t *testing.T) {
	// id=0x5A, temp 21.7°C (raw 0x0D9 → b1 nibble 0x0, b2 0xD9... built
	// here directly): b1 = temp[11:8], b2 = temp[7:0], b4 = sum.
	raw := int16(217) // 21.7 * 10
	b := []byte{0x5A, byte((uint16(raw) >> 8) & 0x0f), byte(uint16(raw) & 0xff), 48, 0}
	b[4] = b[0] + b[1] + b[2] + b[3]
	hexFrame := ""
	for _, by := range b {
		hexFrame += string("0123456789ABCDEF"[by>>4]) + string("0123456789ABCDEF"[by&0x0f])
	}

	out, err := weatherDecodeHandler(context.Background(), nil, map[string]any{"bytes": hexFrame})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	var got struct {
		Readings []struct {
			Protocol     string  `json:"protocol"`
			SensorID     string  `json:"sensor_id"`
			TemperatureC float64 `json:"temperature_c"`
			Humidity     int     `json:"humidity_percent"`
		} `json:"readings"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output not valid JSON: %v\n%s", err, out)
	}
	if len(got.Readings) != 1 {
		t.Fatalf("Readings = %d; want 1\n%s", len(got.Readings), out)
	}
	rd := got.Readings[0]
	if rd.Protocol != "Acurite-609TXC" {
		t.Errorf("Protocol = %q; want Acurite-609TXC", rd.Protocol)
	}
	if rd.SensorID != "5A" {
		t.Errorf("SensorID = %q; want 5A", rd.SensorID)
	}
	if rd.TemperatureC != 21.7 {
		t.Errorf("TemperatureC = %v; want 21.7", rd.TemperatureC)
	}
	if rd.Humidity != 48 {
		t.Errorf("Humidity = %d; want 48", rd.Humidity)
	}
}

func TestWeatherDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := weatherDecodeHandler(context.Background(), nil, map[string]any{})
	if err == nil {
		t.Fatal("want error for missing bytes/bits")
	}
	if !strings.Contains(err.Error(), "required") {
		t.Errorf("err = %v; want 'required'", err)
	}
}

func TestWeatherDecodeHandler_RejectsBoth(t *testing.T) {
	_, err := weatherDecodeHandler(context.Background(), nil, map[string]any{
		"bytes": "0102030405",
		"bits":  strings.Repeat("0", 40),
	})
	if err == nil {
		t.Fatal("want error when both bytes and bits are set")
	}
	if !strings.Contains(err.Error(), "not both") {
		t.Errorf("err = %v; want 'not both'", err)
	}
}
