package tools

import (
	"context"
	"strings"
	"testing"
)

// TestNFCDesfireAIDDecodeHandler_MIFAREClassic confirms the
// Spec handler decodes the canonical 0xF40000 MIFARE Classic
// emulation AID through to JSON.
func TestNFCDesfireAIDDecodeHandler_MIFAREClassic(t *testing.T) {
	out, err := nfcDesfireAIDDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "F40000",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"special": "mifare_classic"`) {
		t.Errorf("expected mifare_classic special:\n%s", out)
	}
	if !strings.Contains(out, `"application_name": "MIFARE Classic emulation"`) {
		t.Errorf("expected MIFARE Classic emulation:\n%s", out)
	}
}

// TestNFCDesfireAIDDecodeHandler_TransitMAD confirms a transit
// MAD AID surfaces with the right category.
func TestNFCDesfireAIDDecodeHandler_TransitMAD(t *testing.T) {
	out, err := nfcDesfireAIDDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "0xF48484",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"category": "Transit applications"`) {
		t.Errorf("expected Transit category:\n%s", out)
	}
	if !strings.Contains(out, `"mad_formatted": true`) {
		t.Errorf("expected mad_formatted true:\n%s", out)
	}
}

func TestNFCDesfireAIDDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := nfcDesfireAIDDecodeHandler(context.Background(), nil, map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
