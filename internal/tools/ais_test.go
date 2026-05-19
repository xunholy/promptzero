package tools

import (
	"context"
	"strings"
	"testing"
)

// TestAISNMEADecodeHandler_Type1 pins the famous AIS Type 1
// vector through the Spec handler.
func TestAISNMEADecodeHandler_Type1(t *testing.T) {
	out, err := aisNMEADecodeHandler(context.Background(), nil, map[string]any{
		"sentence": "!AIVDM,1,1,,A,15M67FC000G?ufbE`FepT@3n00Sa,0*5F",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"message_type": 1`) {
		t.Errorf("expected message_type 1:\n%s", out)
	}
	if !strings.Contains(out, `"mmsi": 366053209`) {
		t.Errorf("expected MMSI 366053209:\n%s", out)
	}
	if !strings.Contains(out, `"nav_status_name": "Restricted manoeuvrability"`) {
		t.Errorf("expected nav status:\n%s", out)
	}
}

func TestAISNMEADecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := aisNMEADecodeHandler(context.Background(), nil, map[string]any{"sentence": ""})
	if err == nil {
		t.Fatal("want error for empty sentence")
	}
}

func TestAISNMEADecodeHandler_RejectsBadPrefix(t *testing.T) {
	_, err := aisNMEADecodeHandler(context.Background(), nil, map[string]any{
		"sentence": "$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9*47",
	})
	if err == nil {
		t.Fatal("want error for non-AIS sentence")
	}
}
