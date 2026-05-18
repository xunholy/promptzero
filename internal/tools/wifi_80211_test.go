package tools

import (
	"context"
	"strings"
	"testing"
)

// TestWifi80211DecodeHandler_BeaconHappyPath confirms the
// handler decodes a minimal beacon frame through to JSON.
func TestWifi80211DecodeHandler_BeaconHappyPath(t *testing.T) {
	hex := "80 00 00 00 " +
		"FF FF FF FF FF FF " +
		"00 11 22 33 44 55 " +
		"00 11 22 33 44 55 " +
		"00 00 " +
		"00 00 00 00 00 00 00 00 " +
		"64 00 01 00 " +
		"00 03 41 50 31 " +
		"03 01 06"
	out, err := wifi80211DecodeHandler(context.Background(), nil, map[string]any{"hex": hex})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"subtype_name": "Beacon"`) {
		t.Errorf("expected Beacon in output:\n%s", out)
	}
	if !strings.Contains(out, `"ssid": "AP1"`) {
		t.Errorf("expected SSID AP1:\n%s", out)
	}
	if !strings.Contains(out, `"channel": 6`) {
		t.Errorf("expected channel 6:\n%s", out)
	}
}

// TestWifi80211DecodeHandler_DeauthReason confirms a deauth
// frame surfaces the reason-code documented name.
func TestWifi80211DecodeHandler_DeauthReason(t *testing.T) {
	hex := "C0 00 00 00 " +
		"AA BB CC DD EE FF " +
		"00 11 22 33 44 55 " +
		"00 11 22 33 44 55 " +
		"00 00 " +
		"04 00"
	out, err := wifi80211DecodeHandler(context.Background(), nil, map[string]any{"hex": hex})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, "inactivity") {
		t.Errorf("expected 'inactivity' wording in output:\n%s", out)
	}
}

func TestWifi80211DecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := wifi80211DecodeHandler(context.Background(), nil, map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
