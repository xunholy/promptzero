package tools

import (
	"context"
	"strings"
	"testing"
)

// TestMQTTPacketDecodeHandler_CONNECT confirms the handler
// decodes a CONNECT packet through to JSON.
func TestMQTTPacketDecodeHandler_CONNECT(t *testing.T) {
	hex := "10 16 00 04 4D 51 54 54 04 02 00 3C 00 0A 74 65 73 74 43 6C 69 65 6E 74"
	out, err := mqttPacketDecodeHandler(context.Background(), nil, map[string]any{
		"hex": hex,
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"packet_type_name": "CONNECT"`) {
		t.Errorf("expected CONNECT in output:\n%s", out)
	}
	if !strings.Contains(out, `"client_id": "testClient"`) {
		t.Errorf("expected client_id testClient:\n%s", out)
	}
}

// TestMQTTPacketDecodeHandler_PUBLISH confirms a PUBLISH packet
// round-trips with topic + payload extraction.
func TestMQTTPacketDecodeHandler_PUBLISH(t *testing.T) {
	hex := "30 19 00 13 73 65 6E 73 6F 72 73 2F 74 65 6D 70 65 72 61 74 75 72 65 32 33 2E 35"
	out, err := mqttPacketDecodeHandler(context.Background(), nil, map[string]any{
		"hex": hex,
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"topic_name": "sensors/temperature"`) {
		t.Errorf("expected topic_name in output:\n%s", out)
	}
	if !strings.Contains(out, `"payload_string": "23.5"`) {
		t.Errorf("expected payload_string 23.5:\n%s", out)
	}
}

func TestMQTTPacketDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := mqttPacketDecodeHandler(context.Background(), nil, map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
