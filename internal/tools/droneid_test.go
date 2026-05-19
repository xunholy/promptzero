package tools

import (
	"context"
	"strings"
	"testing"
)

// TestDroneRemoteIDDecodeHandler_BasicID pins a Basic ID frame
// through the Spec handler to JSON.
func TestDroneRemoteIDDecodeHandler_BasicID(t *testing.T) {
	out, err := droneRemoteIDDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "0212313538314634444B453030303030303030300000000000",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"type": 0`) {
		t.Errorf("expected type 0:\n%s", out)
	}
	if !strings.Contains(out, `"type_name": "Basic ID"`) {
		t.Errorf("expected Basic ID type_name:\n%s", out)
	}
	if !strings.Contains(out, `"uas_id": "1581F4DKE000000000"`) {
		t.Errorf("expected UAS ID:\n%s", out)
	}
}

func TestDroneRemoteIDDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := droneRemoteIDDecodeHandler(context.Background(), nil, map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}

func TestDroneRemoteIDDecodeHandler_RejectsBadLength(t *testing.T) {
	_, err := droneRemoteIDDecodeHandler(context.Background(), nil, map[string]any{"hex": "0212"})
	if err == nil {
		t.Fatal("want error for short hex")
	}
}
