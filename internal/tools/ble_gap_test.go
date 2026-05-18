package tools

import (
	"context"
	"strings"
	"testing"
)

// TestBLEGAPDecodeHandler_HappyPath sends a typical real-world
// advertisement (Flags + Local Name) and confirms the Spec
// handler decodes both records.
func TestBLEGAPDecodeHandler_HappyPath(t *testing.T) {
	out, err := bleGAPDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "02 01 06 07 09 42 4C 45 64 65 76",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"name": "Flags"`) {
		t.Errorf("expected Flags name in output:\n%s", out)
	}
	if !strings.Contains(out, `"name": "Complete Local Name"`) {
		t.Errorf("expected Complete Local Name:\n%s", out)
	}
	if !strings.Contains(out, `"name": "BLEdev"`) {
		t.Errorf("expected decoded name BLEdev:\n%s", out)
	}
}

// TestBLEGAPDecodeHandler_AppleManufacturer confirms the
// manufacturer-data company lookup picks up Apple's company ID.
func TestBLEGAPDecodeHandler_AppleManufacturer(t *testing.T) {
	out, err := bleGAPDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "08 FF 4C 00 10 05 1B 00 AA",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"company": "Apple, Inc."`) {
		t.Errorf("expected Apple company in output:\n%s", out)
	}
}

func TestBLEGAPDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := bleGAPDecodeHandler(context.Background(), nil, map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
