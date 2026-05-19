package tools

import (
	"context"
	"strings"
	"testing"
)

// TestAPRSPacketDecodeHandler_TNC2 pins a canonical TNC2 line
// through the Spec handler to JSON.
func TestAPRSPacketDecodeHandler_TNC2(t *testing.T) {
	out, err := aprsPacketDecodeHandler(context.Background(), nil, map[string]any{
		"packet": "K1ABC-9>APRS,WIDE2-1:!4903.50N/07201.75W>South of Ottawa",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"callsign": "K1ABC"`) {
		t.Errorf("expected source callsign K1ABC:\n%s", out)
	}
	if !strings.Contains(out, `"ssid": 9`) {
		t.Errorf("expected SSID 9:\n%s", out)
	}
	if !strings.Contains(out, `"info_type": "!"`) {
		t.Errorf("expected info_type '!':\n%s", out)
	}
	if !strings.Contains(out, `"symbol_name": "Car"`) {
		t.Errorf("expected symbol_name 'Car':\n%s", out)
	}
}

func TestAPRSPacketDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := aprsPacketDecodeHandler(context.Background(), nil, map[string]any{"packet": ""})
	if err == nil {
		t.Fatal("want error for empty packet")
	}
}

func TestAPRSPacketDecodeHandler_RejectsMalformed(t *testing.T) {
	_, err := aprsPacketDecodeHandler(context.Background(), nil, map[string]any{"packet": "garbage"})
	if err == nil {
		t.Fatal("want error for malformed packet")
	}
}
