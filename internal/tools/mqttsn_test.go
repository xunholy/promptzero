package tools

import (
	"context"
	"strings"
	"testing"
)

// TestMQTTSNDecodeHandler_Connect pins a canonical CONNECT with
// ClientId.
func TestMQTTSNDecodeHandler_Connect(t *testing.T) {
	in := "0E 04 04 01 003C 73 65 6E 73 6F 72 30 31"
	out, err := mqttsnDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"msg_type_name": "CONNECT"`,
		`"clean_session": true`,
		`"protocol_id": 1`,
		`"duration": 60`,
		`"client_id": "sensor01"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestMQTTSNDecodeHandler_PublishQoSMinus1 pins the MQTT-SN-
// specific fire-and-forget QoS = -1 decode.
func TestMQTTSNDecodeHandler_PublishQoSMinus1(t *testing.T) {
	in := "0B 0C 60 0001 0000 DEADBEEF"
	out, err := mqttsnDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"msg_type_name": "PUBLISH"`,
		`"qos": -1`,
		`"data_hex": "DEADBEEF"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestMQTTSNDecodeHandler_Register pins topic registration.
func TestMQTTSNDecodeHandler_Register(t *testing.T) {
	in := "12 0A 0001 0002 74 65 6D 70 2F 63 65 6C 73 69 75 73"
	out, err := mqttsnDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"msg_type_name": "REGISTER"`,
		`"topic_id": 1`,
		`"msg_id": 2`,
		`"topic_name": "temp/celsius"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestMQTTSNDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := mqttsnDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
