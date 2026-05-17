package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestEmvDecodeHandler_RoundTrip pins the Spec→handler→JSON path
// end-to-end. Parser correctness is covered by internal/emv tests;
// this just verifies the handler wires up cleanly.
func TestEmvDecodeHandler_RoundTrip(t *testing.T) {
	out, err := emvDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "5A084012001037141112",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	var resp struct {
		Count int `json:"count"`
		TLVs  []struct {
			TagHex   string `json:"tag_hex"`
			Name     string `json:"name"`
			ValueHex string `json:"value_hex"`
		} `json:"tlvs"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("output not valid JSON: %v\n%s", err, out)
	}
	if resp.Count != 1 || len(resp.TLVs) != 1 {
		t.Fatalf("unexpected response shape: %+v", resp)
	}
	if resp.TLVs[0].TagHex != "5A" {
		t.Errorf("TagHex = %q; want '5A'", resp.TLVs[0].TagHex)
	}
	if resp.TLVs[0].Name == "" {
		t.Error("PAN tag should have a recognised name")
	}
	if resp.TLVs[0].ValueHex != "4012001037141112" {
		t.Errorf("ValueHex = %q", resp.TLVs[0].ValueHex)
	}
}

func TestEmvDecodeHandler_RejectsEmpty(t *testing.T) {
	for _, in := range []string{"", "   ", "\t\n"} {
		_, err := emvDecodeHandler(context.Background(), nil, map[string]any{"hex": in})
		if err == nil {
			t.Errorf("hex=%q: nil error; want 'hex is required'", in)
			continue
		}
		if !strings.Contains(err.Error(), "hex") {
			t.Errorf("err = %v; want mention of hex field", err)
		}
	}
}

func TestEmvDecodeHandler_BubblesUpParserErrors(t *testing.T) {
	_, err := emvDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "5A05010203", // length 5 but only 3 bytes follow
	})
	if err == nil {
		t.Fatal("expected error on truncated TLV")
	}
	if !strings.Contains(err.Error(), "exceeds remaining buffer") {
		t.Errorf("err = %v; want parser error to bubble up", err)
	}
}
