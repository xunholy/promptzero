package tools

import (
	"context"
	"strings"
	"testing"
)

// TestNDEFDecodeHandler_URIHappyPath confirms the Spec handler
// returns JSON with the decoded URI for the canonical
// "https://example.com" NDEF URI record.
func TestNDEFDecodeHandler_URIHappyPath(t *testing.T) {
	out, err := ndefDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "D1 01 0C 55 04 6578616D706C652E636F6D",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"uri": "https://example.com"`) {
		t.Errorf("expected https://example.com in output:\n%s", out)
	}
	if !strings.Contains(out, `"tnf_name": "Well-Known"`) {
		t.Errorf("tnf_name Well-Known missing:\n%s", out)
	}
}

// TestNDEFDecodeHandler_TextRecord confirms the Text record
// decode path round-trips through the handler.
func TestNDEFDecodeHandler_TextRecord(t *testing.T) {
	out, err := ndefDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "D1 01 08 54 02 65 6E 68 65 6C 6C 6F",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"text": "hello"`) {
		t.Errorf("expected text hello in output:\n%s", out)
	}
	if !strings.Contains(out, `"language": "en"`) {
		t.Errorf("expected language en in output:\n%s", out)
	}
}

func TestNDEFDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := ndefDecodeHandler(context.Background(), nil, map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
