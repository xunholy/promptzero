package tools

import (
	"context"
	"strings"
	"testing"
)

// TestNFCIdentifyHandler_MifareClassic1K confirms the Spec
// handler returns JSON with the canonical Mifare Classic 1K
// identification.
func TestNFCIdentifyHandler_MifareClassic1K(t *testing.T) {
	out, err := nfcISO14443AIdentifyHandler(context.Background(), nil, map[string]any{
		"atqa": "0004",
		"sak":  "08",
		"uid":  "04 5A 3B FF",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"tag_type": "Mifare Classic 1K"`) {
		t.Errorf("expected Mifare Classic 1K in output:\n%s", out)
	}
	if !strings.Contains(out, `"manufacturer_name": "NXP Semiconductors"`) {
		t.Errorf("expected NXP manufacturer in output:\n%s", out)
	}
}

// TestNFCIdentifyHandler_DESFireWithATS exercises the optional
// ATS path through the handler.
func TestNFCIdentifyHandler_DESFireWithATS(t *testing.T) {
	out, err := nfcISO14443AIdentifyHandler(context.Background(), nil, map[string]any{
		"atqa": "0344",
		"sak":  "20",
		"uid":  "04 65 8A B2 11 22 33",
		"ats":  "05 75 77 81 02",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"tag_type": "Mifare DESFire EV1/EV2/EV3"`) {
		t.Errorf("expected DESFire in output:\n%s", out)
	}
	if !strings.Contains(out, `"fsc": 64`) {
		t.Errorf("expected fsc 64 in output:\n%s", out)
	}
}

func TestNFCIdentifyHandler_RejectsMissingFields(t *testing.T) {
	cases := []map[string]any{
		{"atqa": "", "sak": "08", "uid": "04 5A 3B FF"},
		{"atqa": "0004", "sak": "", "uid": "04 5A 3B FF"},
		{"atqa": "0004", "sak": "08", "uid": ""},
	}
	for _, c := range cases {
		_, err := nfcISO14443AIdentifyHandler(context.Background(), nil, c)
		if err == nil {
			t.Errorf("handler(%+v) = nil; want error", c)
		}
	}
}
