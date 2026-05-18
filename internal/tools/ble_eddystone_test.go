package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestBLEEddystoneDecodeHandler_URLHappyPath sends the canonical
// "https://www.google.com" URL frame from the Eddystone spec and
// confirms the Spec handler returns the documented top-level
// shape with the URL field decoded.
func TestBLEEddystoneDecodeHandler_URLHappyPath(t *testing.T) {
	out, err := bleEddystoneDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "10 20 01 67 6F 6F 67 6C 65 07",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	var got struct {
		FrameType    int            `json:"frame_type"`
		FrameTypeHex string         `json:"frame_type_hex"`
		FrameName    string         `json:"frame_name"`
		Fields       map[string]any `json:"fields"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output not valid JSON: %v\n%s", err, out)
	}
	if got.FrameName != "URL" {
		t.Errorf("FrameName = %q; want 'URL'", got.FrameName)
	}
	if got.Fields["url"] != "https://www.google.com" {
		t.Errorf("url = %v", got.Fields["url"])
	}
}

func TestBLEEddystoneDecodeHandler_RejectsEmpty(t *testing.T) {
	for _, in := range []string{"", "   "} {
		_, err := bleEddystoneDecodeHandler(context.Background(), nil, map[string]any{"hex": in})
		if err == nil {
			t.Errorf("handler(hex=%q) = nil; want error", in)
		}
	}
}

// TestBLEEddystoneDecodeHandler_TLM confirms a TLM frame
// round-trips through the JSON Spec handler with its numeric
// fields intact.
func TestBLEEddystoneDecodeHandler_TLM(t *testing.T) {
	out, err := bleEddystoneDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "20 00 0B B8 19 80 00 01 00 00 00 00 00 64",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"frame_name": "TLM"`) {
		t.Errorf("frame_name TLM missing:\n%s", out)
	}
	if !strings.Contains(out, `"battery_mv": 3000`) {
		t.Errorf("battery_mv 3000 missing:\n%s", out)
	}
}
