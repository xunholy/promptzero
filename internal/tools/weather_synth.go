// weather_synth.go — host-side 433 MHz weather-station frame synthesizer
// Spec, the inverse of subghz_weather_decode, delegating to
// internal/weather.Synth.
//
// Wrap-vs-native: native — the LaCrosse / Acurite layouts + checksums are a
// public deterministic transform; the encoder reuses the package's own
// checksum/LFSR functions, so the frame is round-trip-verified against
// subghz_weather_decode.

package tools

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/weather"
)

func init() { //nolint:gochecknoinits
	Register(weatherSynthSpec)
}

var weatherSynthSpec = Spec{
	Name: "subghz_weather_synth",
	Description: "Synthesize a 433 MHz weather-station sensor frame (the LaCrosse / Acurite families " +
		"subghz_weather_decode covers) from an interpreted reading — the offline inverse of the " +
		"decoder. Packs sensor ID, temperature, humidity, battery + (LaCrosse) channel/test-button " +
		"into the family's exact 5-byte (40-bit) envelope and seals it with the family's checksum " +
		"(Acurite: 8-bit sum; LaCrosse: lfsr_digest8_reflect), reusing the decoder's own checksum " +
		"functions so the frame is round-trip-verified against subghz_weather_decode. The bit-" +
		"generator behind a weather-sensor spoof payload — generation only, it transmits nothing " +
		"(pair with an OOK TX stage), so it is Low risk like the decoder.\n\n" +
		"Covered: **Acurite-609TXC** (12-bit two's-complement temp ×0.1 °C, -204.8..204.7) and " +
		"**LaCrosse-TX141TH-Bv2** ((raw-500)×0.1 °C, -50.0..359.5; channel 0-3 + test-button). " +
		"Output is the 5 frame bytes (hex), the 40-bit stream, and the frame decoded back for " +
		"confirmation.\n\n" +
		"Companion to subghz_weather_decode (gap-analysis §3 rank 5). Wrap-vs-native: native — " +
		"public layouts + checksums, pure byte maths, no hardware.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"protocol":{"type":"string","description":"Acurite-609TXC or LaCrosse-TX141TH-Bv2."},
			"sensor_id":{"type":"integer","description":"Sensor ID 0-255."},
			"temperature_c":{"type":"number","description":"Temperature in °C (Acurite -204.8..204.7; LaCrosse -50.0..359.5)."},
			"humidity_percent":{"type":"integer","description":"Relative humidity 0-100."},
			"battery_low":{"type":"boolean","description":"Battery-low flag (default false)."},
			"channel":{"type":"integer","description":"LaCrosse channel 0-3 (ignored for Acurite)."},
			"test_button":{"type":"boolean","description":"LaCrosse test-button flag (ignored for Acurite)."}
		},
		"required":["protocol","sensor_id","temperature_c","humidity_percent"]
	}`),
	Required:  []string{"protocol", "sensor_id", "temperature_c", "humidity_percent"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   weatherSynthHandler,
}

func weatherSynthHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	proto := strings.TrimSpace(str(p, "protocol"))
	if proto == "" {
		return "", fmt.Errorf("subghz_weather_synth: 'protocol' is required")
	}
	id, ok := intArg(p["sensor_id"])
	if !ok {
		return "", fmt.Errorf("subghz_weather_synth: 'sensor_id' is required and must be an integer")
	}
	hum, ok := intArg(p["humidity_percent"])
	if !ok {
		return "", fmt.Errorf("subghz_weather_synth: 'humidity_percent' is required and must be an integer")
	}
	tempC, ok := p["temperature_c"].(float64)
	if !ok {
		return "", fmt.Errorf("subghz_weather_synth: 'temperature_c' is required and must be a number")
	}

	in := weather.SynthInput{
		Protocol:     proto,
		SensorID:     id,
		TemperatureC: tempC,
		Humidity:     hum,
	}
	if v, ok := p["battery_low"].(bool); ok {
		in.BatteryLow = v
	}
	if v, ok := intArg(p["channel"]); ok {
		in.Channel = v
	}
	if v, ok := p["test_button"].(bool); ok {
		in.TestButton = v
	}

	frame, err := weather.Synth(in)
	if err != nil {
		return "", fmt.Errorf("subghz_weather_synth: %w", err)
	}
	back, _ := weather.DecodeBytes(frame)
	out, _ := json.MarshalIndent(struct {
		Bytes string          `json:"bytes_hex"`
		Bits  string          `json:"bits"`
		Frame *weather.Result `json:"decoded_back"`
	}{
		Bytes: strings.ToUpper(hex.EncodeToString(frame)),
		Bits:  bytesToBitString(frame),
		Frame: back,
	}, "", "  ")
	return string(out), nil
}

// bytesToBitString renders bytes as an MSB-first '0'/'1' string.
func bytesToBitString(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b) * 8)
	for _, by := range b {
		for i := 7; i >= 0; i-- {
			if by&(1<<uint(i)) != 0 {
				sb.WriteByte('1')
			} else {
				sb.WriteByte('0')
			}
		}
	}
	return sb.String()
}
