package tools

import (
	"context"
	"strings"
	"testing"
)

// TestHTTP2FrameDecodeHandler_Settings pins a canonical SETTINGS
// frame with 2 parameters through the Spec handler.
func TestHTTP2FrameDecodeHandler_Settings(t *testing.T) {
	in := "00000C 04 00 00000000 0003 00000064 0005 00004000"
	out, err := http2FrameDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"type_name": "SETTINGS"`) {
		t.Errorf("expected SETTINGS:\n%s", out)
	}
	if !strings.Contains(out, `"identifier_name": "MAX_CONCURRENT_STREAMS"`) {
		t.Errorf("expected MAX_CONCURRENT_STREAMS:\n%s", out)
	}
	if !strings.Contains(out, `"identifier_name": "MAX_FRAME_SIZE"`) {
		t.Errorf("expected MAX_FRAME_SIZE:\n%s", out)
	}
}

// TestHTTP2FrameDecodeHandler_GoAway pins a GOAWAY with
// PROTOCOL_ERROR.
func TestHTTP2FrameDecodeHandler_GoAway(t *testing.T) {
	in := "000008 07 00 00000000 00000005 00000001"
	out, err := http2FrameDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"type_name": "GOAWAY"`) {
		t.Errorf("expected GOAWAY:\n%s", out)
	}
	if !strings.Contains(out, `"error_code_name": "PROTOCOL_ERROR"`) {
		t.Errorf("expected PROTOCOL_ERROR:\n%s", out)
	}
	if !strings.Contains(out, `"last_stream_id": 5`) {
		t.Errorf("expected last_stream_id 5:\n%s", out)
	}
}

// TestHTTP2FrameDecodeHandler_PrefacePlusSettings pins the
// preface detection path.
func TestHTTP2FrameDecodeHandler_PrefacePlusSettings(t *testing.T) {
	preface := "505249202A20485454502F322E300D0A0D0A534D0D0A0D0A"
	in := preface + "000000 04 00 00000000"
	out, err := http2FrameDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"has_preface": true`) {
		t.Errorf("expected has_preface true:\n%s", out)
	}
	if !strings.Contains(out, "Connection Preface") {
		t.Errorf("expected preface frame:\n%s", out)
	}
}

func TestHTTP2FrameDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := http2FrameDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
