package kafka

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func kafkaRequest(apiKey, apiVersion uint16, correlationID uint32, clientID string, body []byte) []byte {
	var msg []byte
	msg = binary.BigEndian.AppendUint16(msg, apiKey)
	msg = binary.BigEndian.AppendUint16(msg, apiVersion)
	msg = binary.BigEndian.AppendUint32(msg, correlationID)
	if clientID == "" {
		msg = binary.BigEndian.AppendUint16(msg, uint16(0xFFFF)) // null
	} else {
		msg = binary.BigEndian.AppendUint16(msg, uint16(len(clientID)))
		msg = append(msg, []byte(clientID)...)
	}
	msg = append(msg, body...)

	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, uint32(len(msg)))
	return append(out, msg...)
}

func kafkaString(s string) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(len(s)))
	return append(b, []byte(s)...)
}

func TestDecode_ApiVersions(t *testing.T) {
	req := kafkaRequest(18, 3, 1, "kafka-python-2.0.2", nil)
	r, err := Decode(hex.EncodeToString(req))
	if err != nil {
		t.Fatal(err)
	}
	if r.APIKeyName != "ApiVersions" {
		t.Errorf("api=%q, want ApiVersions", r.APIKeyName)
	}
	if !r.IsVersionProbe {
		t.Error("expected IsVersionProbe=true")
	}
	if r.ClientID != "kafka-python-2.0.2" {
		t.Errorf("client_id=%q, want kafka-python-2.0.2", r.ClientID)
	}
	if r.APIVersion != 3 {
		t.Errorf("version=%d, want 3", r.APIVersion)
	}
}

func TestDecode_Metadata(t *testing.T) {
	var body []byte
	body = binary.BigEndian.AppendUint32(body, 1) // topic count
	body = append(body, kafkaString("orders")...)

	req := kafkaRequest(3, 12, 2, "consumer-1", body)
	r, err := Decode(hex.EncodeToString(req))
	if err != nil {
		t.Fatal(err)
	}
	if !r.IsMetadataReq {
		t.Error("expected IsMetadataReq=true")
	}
	if r.TopicName != "orders" {
		t.Errorf("topic=%q, want orders", r.TopicName)
	}
	if r.TopicCount != 1 {
		t.Errorf("count=%d, want 1", r.TopicCount)
	}
}

func TestDecode_Produce(t *testing.T) {
	var body []byte
	// transactional_id = null (v3+)
	body = binary.BigEndian.AppendUint16(body, uint16(0xFFFF))
	// acks
	body = binary.BigEndian.AppendUint16(body, uint16(0xFFFF)) // -1 = all
	// timeout
	body = binary.BigEndian.AppendUint32(body, 30000)
	// topic count
	body = binary.BigEndian.AppendUint32(body, 1)
	body = append(body, kafkaString("events")...)

	req := kafkaRequest(0, 7, 3, "producer-1", body)
	r, err := Decode(hex.EncodeToString(req))
	if err != nil {
		t.Fatal(err)
	}
	if r.APIKeyName != "Produce" {
		t.Errorf("api=%q, want Produce", r.APIKeyName)
	}
	if r.Acks != -1 {
		t.Errorf("acks=%d, want -1", r.Acks)
	}
	if r.TimeoutMs != 30000 {
		t.Errorf("timeout=%d, want 30000", r.TimeoutMs)
	}
	if r.TopicName != "events" {
		t.Errorf("topic=%q, want events", r.TopicName)
	}
}

func TestDecode_SaslHandshake_PLAIN(t *testing.T) {
	body := kafkaString("PLAIN")
	req := kafkaRequest(17, 1, 4, "admin-client", body)
	r, err := Decode(hex.EncodeToString(req))
	if err != nil {
		t.Fatal(err)
	}
	if !r.IsSASLHandshake {
		t.Error("expected IsSASLHandshake=true")
	}
	if r.SASLMechanism != "PLAIN" {
		t.Errorf("mechanism=%q, want PLAIN", r.SASLMechanism)
	}
	if !r.IsCleartextSASL {
		t.Error("expected IsCleartextSASL=true for PLAIN")
	}
}

func TestDecode_SaslHandshake_SCRAM(t *testing.T) {
	body := kafkaString("SCRAM-SHA-256")
	req := kafkaRequest(17, 1, 5, "secure-client", body)
	r, err := Decode(hex.EncodeToString(req))
	if err != nil {
		t.Fatal(err)
	}
	if r.SASLMechanism != "SCRAM-SHA-256" {
		t.Errorf("mechanism=%q, want SCRAM-SHA-256", r.SASLMechanism)
	}
	if r.IsCleartextSASL {
		t.Error("SCRAM should not flag cleartext")
	}
}

func TestDecode_SaslAuthenticate(t *testing.T) {
	auth := []byte("\x00admin\x00secret")
	var body []byte
	body = binary.BigEndian.AppendUint32(body, uint32(len(auth)))
	body = append(body, auth...)

	req := kafkaRequest(36, 2, 6, "admin-client", body)
	r, err := Decode(hex.EncodeToString(req))
	if err != nil {
		t.Fatal(err)
	}
	if !r.IsSASLAuth {
		t.Error("expected IsSASLAuth=true")
	}
	if r.AuthBytes != len(auth) {
		t.Errorf("auth_bytes=%d, want %d", r.AuthBytes, len(auth))
	}
}

func TestDecode_FindCoordinator(t *testing.T) {
	body := kafkaString("my-consumer-group")
	req := kafkaRequest(10, 4, 7, "client-1", body)
	r, err := Decode(hex.EncodeToString(req))
	if err != nil {
		t.Fatal(err)
	}
	if !r.IsGroupOperation {
		t.Error("expected IsGroupOperation=true")
	}
	if r.CoordinatorKey != "my-consumer-group" {
		t.Errorf("key=%q, want my-consumer-group", r.CoordinatorKey)
	}
}

func TestDecode_JoinGroup(t *testing.T) {
	var body []byte
	body = append(body, kafkaString("order-processors")...) // group_id
	body = binary.BigEndian.AppendUint32(body, 30000)       // session_timeout
	body = binary.BigEndian.AppendUint32(body, 300000)      // rebalance_timeout (v1+)
	body = append(body, kafkaString("")...)                 // member_id
	body = append(body, kafkaString("consumer")...)         // protocol_type

	req := kafkaRequest(11, 5, 8, "client-1", body)
	r, err := Decode(hex.EncodeToString(req))
	if err != nil {
		t.Fatal(err)
	}
	if r.GroupID != "order-processors" {
		t.Errorf("group=%q, want order-processors", r.GroupID)
	}
	if r.ProtocolType != "consumer" {
		t.Errorf("protocol_type=%q, want consumer", r.ProtocolType)
	}
}

func TestDecode_CreateTopics(t *testing.T) {
	req := kafkaRequest(19, 7, 9, "admin-client", nil)
	r, err := Decode(hex.EncodeToString(req))
	if err != nil {
		t.Fatal(err)
	}
	if !r.IsTopicAdmin {
		t.Error("expected IsTopicAdmin=true")
	}
}

func TestDecode_DescribeAcls(t *testing.T) {
	req := kafkaRequest(29, 3, 10, "admin-client", nil)
	r, err := Decode(hex.EncodeToString(req))
	if err != nil {
		t.Fatal(err)
	}
	if !r.IsACLOperation {
		t.Error("expected IsACLOperation=true")
	}
}

func TestDecode_RejectsEmpty(t *testing.T) {
	_, err := Decode("")
	if err == nil {
		t.Fatal("want error for empty input")
	}
}

func TestDecode_RejectsTruncated(t *testing.T) {
	_, err := Decode("0102")
	if err == nil {
		t.Fatal("want error for truncated input")
	}
}
