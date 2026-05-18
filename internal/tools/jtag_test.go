package tools

import (
	"context"
	"strings"
	"testing"
)

// TestJTAGIDCodeDecodeHandler_ARMHappyPath sends the canonical
// ARM Cortex-M JTAG-DP IDCODE and confirms the Spec handler
// decodes it through to JSON.
func TestJTAGIDCodeDecodeHandler_ARMHappyPath(t *testing.T) {
	out, err := jtagIDCodeDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "4BA00477",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"manufacturer_name": "ARM"`) {
		t.Errorf("expected ARM manufacturer:\n%s", out)
	}
	if !strings.Contains(out, `"part_name": "ARM Cortex-M JTAG-DP"`) {
		t.Errorf("expected ARM Cortex-M JTAG-DP part:\n%s", out)
	}
}

// TestJTAGIDCodeDecodeHandler_STMHappyPath verifies STM32F411
// chip identification.
func TestJTAGIDCodeDecodeHandler_STMHappyPath(t *testing.T) {
	out, err := jtagIDCodeDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "0x16431041",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"part_name": "STM32F411xx"`) {
		t.Errorf("expected STM32F411xx:\n%s", out)
	}
}

func TestJTAGIDCodeDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := jtagIDCodeDecodeHandler(context.Background(), nil, map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
