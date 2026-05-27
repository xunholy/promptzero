package tools

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

func amqpShortStr(s string) []byte {
	return append([]byte{byte(len(s))}, []byte(s)...)
}

func amqpLongStr(s string) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(len(s)))
	return append(b, []byte(s)...)
}

func amqpTbl(entries map[string]string) []byte {
	var body []byte
	for k, v := range entries {
		body = append(body, amqpShortStr(k)...)
		body = append(body, 'S')
		body = append(body, amqpLongStr(v)...)
	}
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(body)))
	return append(hdr, body...)
}

func amqpFrm(fType byte, ch uint16, payload []byte) []byte {
	hdr := make([]byte, 7)
	hdr[0] = fType
	binary.BigEndian.PutUint16(hdr[1:3], ch)
	binary.BigEndian.PutUint32(hdr[3:7], uint32(len(payload)))
	out := append(hdr, payload...)
	return append(out, 0xCE)
}

func amqpMethodPld(classID, methodID uint16, args []byte) []byte {
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint16(hdr[0:2], classID)
	binary.BigEndian.PutUint16(hdr[2:4], methodID)
	return append(hdr, args...)
}

// TestAMQP091DecodeHandler_ConnectionStart pins the version +
// auth-mechanism enumeration probe shape.
func TestAMQP091DecodeHandler_ConnectionStart(t *testing.T) {
	props := amqpTbl(map[string]string{
		"product":  "RabbitMQ",
		"version":  "3.13.0",
		"platform": "Erlang/OTP 26.2.1",
	})
	var args []byte
	args = append(args, 0, 9)
	args = append(args, props...)
	args = append(args, amqpLongStr("PLAIN AMQPLAIN")...)
	args = append(args, amqpLongStr("en_US")...)

	payload := amqpMethodPld(10, 10, args)
	frame := amqpFrm(1, 0, payload)

	out, err := amqp091DecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(frame)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"method_name": "Connection.Start"`,
		`"server_product": "RabbitMQ"`,
		`"server_version": "3.13.0"`,
		`"is_version_disclosure": true`,
		`"mechanisms": "PLAIN AMQPLAIN"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestAMQP091DecodeHandler_StartOkPLAIN pins the cleartext
// credential exposure classification.
func TestAMQP091DecodeHandler_StartOkPLAIN(t *testing.T) {
	props := amqpTbl(map[string]string{"product": "py-amqp"})
	var args []byte
	args = append(args, props...)
	args = append(args, amqpShortStr("PLAIN")...)
	args = append(args, amqpLongStr("\x00guest\x00guest")...)
	args = append(args, amqpShortStr("en_US")...)

	payload := amqpMethodPld(10, 11, args)
	frame := amqpFrm(1, 0, payload)

	out, err := amqp091DecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(frame)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"sasl_mechanism": "PLAIN"`,
		`"is_cleartext_auth": true`,
		`cleartext`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestAMQP091DecodeHandler_BasicPublish pins the exchange + routing-key
// topology disclosure.
func TestAMQP091DecodeHandler_BasicPublish(t *testing.T) {
	var args []byte
	args = binary.BigEndian.AppendUint16(args, 0)
	args = append(args, amqpShortStr("orders.exchange")...)
	args = append(args, amqpShortStr("order.created")...)

	payload := amqpMethodPld(60, 40, args)
	frame := amqpFrm(1, 1, payload)

	out, err := amqp091DecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(frame)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"method_name": "Basic.Publish"`,
		`"exchange_name": "orders.exchange"`,
		`"routing_key": "order.created"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestAMQP091DecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := amqp091DecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
