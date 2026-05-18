package tools

import (
	"context"
	"strings"
	"testing"
)

// TestIButtonDecodeHandler_RoundTrip pins a Dallas DS1990A ROM ID
// through the Spec handler to JSON.
func TestIButtonDecodeHandler_RoundTrip(t *testing.T) {
	out, err := ibuttonDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "01 02 03 04 05 06 07 0F",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"family_code": 1`) {
		t.Errorf("expected family_code 1 in JSON:\n%s", out)
	}
	if !strings.Contains(out, `"family_hex": "0x01"`) {
		t.Errorf("expected family_hex 0x01:\n%s", out)
	}
	if !strings.Contains(out, "DS1990A") {
		t.Errorf("expected DS1990A in family_name:\n%s", out)
	}
	if !strings.Contains(out, `"crc_valid": true`) {
		t.Errorf("expected crc_valid true:\n%s", out)
	}
	if !strings.Contains(out, `"serial_hex": "020304050607"`) {
		t.Errorf("expected serial_hex 020304050607:\n%s", out)
	}
}

func TestIButtonDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := ibuttonDecodeHandler(context.Background(), nil, map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}

func TestIButtonDecodeHandler_RejectsBadLength(t *testing.T) {
	_, err := ibuttonDecodeHandler(context.Background(), nil, map[string]any{"hex": "01 02 03"})
	if err == nil {
		t.Fatal("want error for short hex")
	}
}
