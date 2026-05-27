package amqp091

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func amqpShortString(s string) []byte {
	return append([]byte{byte(len(s))}, []byte(s)...)
}

func amqpLongString(s string) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(len(s)))
	return append(b, []byte(s)...)
}

func amqpTable(entries map[string]string) []byte {
	var body []byte
	for k, v := range entries {
		body = append(body, amqpShortString(k)...)
		body = append(body, 'S')
		body = append(body, amqpLongString(v)...)
	}
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(body)))
	return append(hdr, body...)
}

func amqpFrame(frameType byte, channel uint16, payload []byte) []byte {
	hdr := make([]byte, 7)
	hdr[0] = frameType
	binary.BigEndian.PutUint16(hdr[1:3], channel)
	binary.BigEndian.PutUint32(hdr[3:7], uint32(len(payload)))
	out := append(hdr, payload...)
	return append(out, 0xCE)
}

func amqpMethodPayload(classID, methodID uint16, args []byte) []byte {
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint16(hdr[0:2], classID)
	binary.BigEndian.PutUint16(hdr[2:4], methodID)
	return append(hdr, args...)
}

func TestDecode_ProtocolHeader(t *testing.T) {
	header := []byte("AMQP\x00\x00\x09\x01")
	r, err := Decode(hex.EncodeToString(header))
	if err != nil {
		t.Fatal(err)
	}
	if !r.IsProtocolHeader {
		t.Error("expected IsProtocolHeader=true")
	}
	if r.ProtocolMajor != 0 || r.ProtocolMinor != 9 || r.ProtocolRevision != 1 {
		t.Errorf("version=%d.%d.%d, want 0.9.1",
			r.ProtocolMajor, r.ProtocolMinor, r.ProtocolRevision)
	}
}

func TestDecode_ConnectionStart(t *testing.T) {
	props := amqpTable(map[string]string{
		"product":  "RabbitMQ",
		"version":  "3.13.0",
		"platform": "Erlang/OTP 26.2.1",
	})
	var args []byte
	args = append(args, 0, 9) // version-major=0, version-minor=9
	args = append(args, props...)
	args = append(args, amqpLongString("PLAIN AMQPLAIN")...)
	args = append(args, amqpLongString("en_US")...)

	payload := amqpMethodPayload(10, 10, args)
	frame := amqpFrame(1, 0, payload)

	r, err := Decode(hex.EncodeToString(frame))
	if err != nil {
		t.Fatal(err)
	}
	if r.MethodName != "Connection.Start" {
		t.Errorf("method=%q, want Connection.Start", r.MethodName)
	}
	if r.ServerProduct != "RabbitMQ" {
		t.Errorf("product=%q, want RabbitMQ", r.ServerProduct)
	}
	if r.ServerVersion != "3.13.0" {
		t.Errorf("version=%q, want 3.13.0", r.ServerVersion)
	}
	if r.ServerPlatform != "Erlang/OTP 26.2.1" {
		t.Errorf("platform=%q, want Erlang/OTP 26.2.1", r.ServerPlatform)
	}
	if r.Mechanisms != "PLAIN AMQPLAIN" {
		t.Errorf("mechanisms=%q, want 'PLAIN AMQPLAIN'", r.Mechanisms)
	}
	if !r.IsVersionDisclosure {
		t.Error("expected IsVersionDisclosure=true")
	}
	if !r.FrameEndValid {
		t.Error("expected FrameEndValid=true")
	}
}

func TestDecode_ConnectionStartOk_PLAIN(t *testing.T) {
	props := amqpTable(map[string]string{
		"product": "py-amqp",
		"version": "5.2.0",
	})
	response := "\x00guest\x00guest"
	var args []byte
	args = append(args, props...)
	args = append(args, amqpShortString("PLAIN")...)
	args = append(args, amqpLongString(response)...)
	args = append(args, amqpShortString("en_US")...)

	payload := amqpMethodPayload(10, 11, args)
	frame := amqpFrame(1, 0, payload)

	r, err := Decode(hex.EncodeToString(frame))
	if err != nil {
		t.Fatal(err)
	}
	if r.MethodName != "Connection.StartOk" {
		t.Errorf("method=%q, want Connection.StartOk", r.MethodName)
	}
	if r.SASLMechanism != "PLAIN" {
		t.Errorf("mechanism=%q, want PLAIN", r.SASLMechanism)
	}
	if !r.IsCleartextAuth {
		t.Error("expected IsCleartextAuth=true for PLAIN mechanism")
	}
	if r.ResponseBytes != len(response) {
		t.Errorf("response_bytes=%d, want %d", r.ResponseBytes, len(response))
	}
	if r.ClientProduct != "py-amqp" {
		t.Errorf("client_product=%q, want py-amqp", r.ClientProduct)
	}
	if r.Locale != "en_US" {
		t.Errorf("locale=%q, want en_US", r.Locale)
	}
}

func TestDecode_ConnectionTune(t *testing.T) {
	var args []byte
	args = binary.BigEndian.AppendUint16(args, 2047)   // channel-max
	args = binary.BigEndian.AppendUint32(args, 131072) // frame-max
	args = binary.BigEndian.AppendUint16(args, 60)     // heartbeat

	payload := amqpMethodPayload(10, 30, args)
	frame := amqpFrame(1, 0, payload)

	r, err := Decode(hex.EncodeToString(frame))
	if err != nil {
		t.Fatal(err)
	}
	if r.MethodName != "Connection.Tune" {
		t.Errorf("method=%q, want Connection.Tune", r.MethodName)
	}
	if r.ChannelMax != 2047 {
		t.Errorf("channel_max=%d, want 2047", r.ChannelMax)
	}
	if r.FrameMax != 131072 {
		t.Errorf("frame_max=%d, want 131072", r.FrameMax)
	}
	if r.Heartbeat != 60 {
		t.Errorf("heartbeat=%d, want 60", r.Heartbeat)
	}
}

func TestDecode_ConnectionOpen(t *testing.T) {
	args := amqpShortString("/production")
	payload := amqpMethodPayload(10, 40, args)
	frame := amqpFrame(1, 0, payload)

	r, err := Decode(hex.EncodeToString(frame))
	if err != nil {
		t.Fatal(err)
	}
	if r.MethodName != "Connection.Open" {
		t.Errorf("method=%q, want Connection.Open", r.MethodName)
	}
	if r.VirtualHost != "/production" {
		t.Errorf("vhost=%q, want /production", r.VirtualHost)
	}
}

func TestDecode_ConnectionClose(t *testing.T) {
	var args []byte
	args = binary.BigEndian.AppendUint16(args, 320) // reply-code
	args = append(args, amqpShortString("CONNECTION_FORCED")...)
	args = binary.BigEndian.AppendUint16(args, 0) // class-id
	args = binary.BigEndian.AppendUint16(args, 0) // method-id

	payload := amqpMethodPayload(10, 50, args)
	frame := amqpFrame(1, 0, payload)

	r, err := Decode(hex.EncodeToString(frame))
	if err != nil {
		t.Fatal(err)
	}
	if r.MethodName != "Connection.Close" {
		t.Errorf("method=%q, want Connection.Close", r.MethodName)
	}
	if r.ReplyCode != 320 {
		t.Errorf("reply_code=%d, want 320", r.ReplyCode)
	}
	if r.ReplyText != "CONNECTION_FORCED" {
		t.Errorf("reply_text=%q, want CONNECTION_FORCED", r.ReplyText)
	}
}

func TestDecode_BasicPublish(t *testing.T) {
	var args []byte
	args = binary.BigEndian.AppendUint16(args, 0) // ticket
	args = append(args, amqpShortString("orders.exchange")...)
	args = append(args, amqpShortString("order.created")...)

	payload := amqpMethodPayload(60, 40, args)
	frame := amqpFrame(1, 1, payload)

	r, err := Decode(hex.EncodeToString(frame))
	if err != nil {
		t.Fatal(err)
	}
	if r.MethodName != "Basic.Publish" {
		t.Errorf("method=%q, want Basic.Publish", r.MethodName)
	}
	if r.ExchangeName != "orders.exchange" {
		t.Errorf("exchange=%q, want orders.exchange", r.ExchangeName)
	}
	if r.RoutingKey != "order.created" {
		t.Errorf("routing_key=%q, want order.created", r.RoutingKey)
	}
	if r.Channel != 1 {
		t.Errorf("channel=%d, want 1", r.Channel)
	}
}

func TestDecode_QueueDeclare(t *testing.T) {
	var args []byte
	args = binary.BigEndian.AppendUint16(args, 0) // ticket
	args = append(args, amqpShortString("task_queue")...)

	payload := amqpMethodPayload(50, 10, args)
	frame := amqpFrame(1, 1, payload)

	r, err := Decode(hex.EncodeToString(frame))
	if err != nil {
		t.Fatal(err)
	}
	if r.MethodName != "Queue.Declare" {
		t.Errorf("method=%q, want Queue.Declare", r.MethodName)
	}
	if r.QueueName != "task_queue" {
		t.Errorf("queue=%q, want task_queue", r.QueueName)
	}
}

func TestDecode_QueueBind(t *testing.T) {
	var args []byte
	args = binary.BigEndian.AppendUint16(args, 0) // ticket
	args = append(args, amqpShortString("events_queue")...)
	args = append(args, amqpShortString("events")...)
	args = append(args, amqpShortString("event.user.#")...)

	payload := amqpMethodPayload(50, 20, args)
	frame := amqpFrame(1, 1, payload)

	r, err := Decode(hex.EncodeToString(frame))
	if err != nil {
		t.Fatal(err)
	}
	if r.MethodName != "Queue.Bind" {
		t.Errorf("method=%q, want Queue.Bind", r.MethodName)
	}
	if r.QueueName != "events_queue" {
		t.Errorf("queue=%q, want events_queue", r.QueueName)
	}
	if r.ExchangeName != "events" {
		t.Errorf("exchange=%q, want events", r.ExchangeName)
	}
	if r.RoutingKey != "event.user.#" {
		t.Errorf("routing_key=%q, want event.user.#", r.RoutingKey)
	}
}

func TestDecode_ExchangeDeclare(t *testing.T) {
	var args []byte
	args = binary.BigEndian.AppendUint16(args, 0) // ticket
	args = append(args, amqpShortString("logs")...)
	args = append(args, amqpShortString("fanout")...)

	payload := amqpMethodPayload(40, 10, args)
	frame := amqpFrame(1, 1, payload)

	r, err := Decode(hex.EncodeToString(frame))
	if err != nil {
		t.Fatal(err)
	}
	if r.MethodName != "Exchange.Declare" {
		t.Errorf("method=%q, want Exchange.Declare", r.MethodName)
	}
	if r.ExchangeName != "logs" {
		t.Errorf("exchange=%q, want logs", r.ExchangeName)
	}
	if r.ExchangeType != "fanout" {
		t.Errorf("type=%q, want fanout", r.ExchangeType)
	}
}

func TestDecode_Heartbeat(t *testing.T) {
	frame := amqpFrame(4, 0, nil)
	r, err := Decode(hex.EncodeToString(frame))
	if err != nil {
		t.Fatal(err)
	}
	if r.FrameTypeName != "Heartbeat" {
		t.Errorf("type=%q, want Heartbeat", r.FrameTypeName)
	}
	if !r.FrameEndValid {
		t.Error("expected FrameEndValid=true")
	}
}

func TestDecode_BasicConsume(t *testing.T) {
	var args []byte
	args = binary.BigEndian.AppendUint16(args, 0) // ticket
	args = append(args, amqpShortString("worker_queue")...)

	payload := amqpMethodPayload(60, 20, args)
	frame := amqpFrame(1, 1, payload)

	r, err := Decode(hex.EncodeToString(frame))
	if err != nil {
		t.Fatal(err)
	}
	if r.MethodName != "Basic.Consume" {
		t.Errorf("method=%q, want Basic.Consume", r.MethodName)
	}
	if r.QueueName != "worker_queue" {
		t.Errorf("queue=%q, want worker_queue", r.QueueName)
	}
}

func TestDecode_BasicDeliver(t *testing.T) {
	var args []byte
	args = append(args, amqpShortString("ctag1")...) // consumer-tag
	args = append(args, make([]byte, 8)...)          // delivery-tag
	args = append(args, 0)                           // redelivered
	args = append(args, amqpShortString("amq.direct")...)
	args = append(args, amqpShortString("order.new")...)

	payload := amqpMethodPayload(60, 60, args)
	frame := amqpFrame(1, 1, payload)

	r, err := Decode(hex.EncodeToString(frame))
	if err != nil {
		t.Fatal(err)
	}
	if r.MethodName != "Basic.Deliver" {
		t.Errorf("method=%q, want Basic.Deliver", r.MethodName)
	}
	if r.ExchangeName != "amq.direct" {
		t.Errorf("exchange=%q, want amq.direct", r.ExchangeName)
	}
	if r.RoutingKey != "order.new" {
		t.Errorf("routing_key=%q, want order.new", r.RoutingKey)
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
		t.Fatal("want error for truncated frame")
	}
}
