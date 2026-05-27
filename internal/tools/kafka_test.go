package tools

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

func kfRequest(apiKey, apiVersion uint16, correlationID uint32, clientID string, body []byte) []byte {
	var msg []byte
	msg = binary.BigEndian.AppendUint16(msg, apiKey)
	msg = binary.BigEndian.AppendUint16(msg, apiVersion)
	msg = binary.BigEndian.AppendUint32(msg, correlationID)
	if clientID == "" {
		msg = binary.BigEndian.AppendUint16(msg, uint16(0xFFFF))
	} else {
		msg = binary.BigEndian.AppendUint16(msg, uint16(len(clientID)))
		msg = append(msg, []byte(clientID)...)
	}
	msg = append(msg, body...)
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, uint32(len(msg)))
	return append(out, msg...)
}

func kfString(s string) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(len(s)))
	return append(b, []byte(s)...)
}

// TestKafkaDecodeHandler_ApiVersions pins the canonical version
// fingerprint probe shape.
func TestKafkaDecodeHandler_ApiVersions(t *testing.T) {
	req := kfRequest(18, 3, 1, "kafka-python-2.0.2", nil)
	out, err := kafkaDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(req)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"api_key_name": "ApiVersions"`,
		`"is_version_probe": true`,
		`"client_id": "kafka-python-2.0.2"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestKafkaDecodeHandler_SaslHandshakePLAIN pins the cleartext
// credential exposure classification.
func TestKafkaDecodeHandler_SaslHandshakePLAIN(t *testing.T) {
	body := kfString("PLAIN")
	req := kfRequest(17, 1, 4, "admin-client", body)
	out, err := kafkaDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(req)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"sasl_mechanism": "PLAIN"`,
		`"is_cleartext_sasl": true`,
		`cleartext`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestKafkaDecodeHandler_Metadata pins the cluster topology
// recon shape.
func TestKafkaDecodeHandler_Metadata(t *testing.T) {
	var body []byte
	body = binary.BigEndian.AppendUint32(body, 1)
	body = append(body, kfString("orders")...)

	req := kfRequest(3, 12, 2, "consumer-1", body)
	out, err := kafkaDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(req)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"is_metadata_request": true`,
		`"topic_name": "orders"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestKafkaDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := kafkaDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
