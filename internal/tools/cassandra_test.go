package tools

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// cassandraFrame builds a minimal CQL v4 request frame.
func cassandraFrame(opcode byte, body []byte) []byte {
	var b []byte
	b = append(b, 0x04)                          // version: request, protocol v4
	b = append(b, 0x00)                          // flags: none
	b = binary.BigEndian.AppendUint16(b, 0x0001) // stream: 1
	b = append(b, opcode)
	b = binary.BigEndian.AppendUint32(b, uint32(len(body)))
	b = append(b, body...)
	return b
}

// cassandraString encodes a CQL short string (int16 BE length + UTF-8).
func cassandraString(s string) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(len(s)))
	return append(b, []byte(s)...)
}

// cassandraStringMap encodes a CQL string map (int16 BE count + k/v pairs).
func cassandraStringMap(pairs ...string) []byte {
	if len(pairs)%2 != 0 {
		panic("cassandraStringMap: odd number of arguments")
	}
	var b []byte
	b = binary.BigEndian.AppendUint16(b, uint16(len(pairs)/2))
	for i := 0; i < len(pairs); i += 2 {
		b = append(b, cassandraString(pairs[i])...)
		b = append(b, cassandraString(pairs[i+1])...)
	}
	return b
}

// cassandraLongString encodes a CQL long string (int32 BE length + UTF-8).
func cassandraLongString(s string) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(len(s)))
	return append(b, []byte(s)...)
}

// TestCassandraDecodeHandler_STARTUP pins the CQL version fingerprint shape.
func TestCassandraDecodeHandler_STARTUP(t *testing.T) {
	body := cassandraStringMap("CQL_VERSION", "3.0.0", "COMPRESSION", "lz4")
	frame := cassandraFrame(0x01, body)
	out, err := cassandraDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(frame)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"opcode_name": "STARTUP"`,
		`"is_startup": true`,
		`"cql_version": "3.0.0"`,
		`"compression": "lz4"`,
		`"protocol_version": 4`,
		`"is_request": true`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestCassandraDecodeHandler_QUERY pins the query text extraction shape.
func TestCassandraDecodeHandler_QUERY(t *testing.T) {
	qText := "SELECT keyspace_name, table_name FROM system_schema.tables"
	body := cassandraLongString(qText)
	frame := cassandraFrame(0x07, body)
	out, err := cassandraDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(frame)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"opcode_name": "QUERY"`,
		`"is_query": true`,
		`"query_text": "SELECT keyspace_name, table_name FROM system_schema.tables"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestCassandraDecodeHandler_RejectsEmpty pins the empty-input error path.
func TestCassandraDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := cassandraDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
