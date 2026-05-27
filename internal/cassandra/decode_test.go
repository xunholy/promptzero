package cassandra

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// cqlFrame builds a minimal CQL v4 request frame (version byte 0x04).
func cqlFrame(opcode byte, body []byte) []byte {
	var b []byte
	b = append(b, 0x04)                          // version: request, protocol v4
	b = append(b, 0x00)                          // flags: none
	b = binary.BigEndian.AppendUint16(b, 0x0001) // stream: 1
	b = append(b, opcode)
	b = binary.BigEndian.AppendUint32(b, uint32(len(body)))
	b = append(b, body...)
	return b
}

// cqlString encodes a CQL short string (int16 BE length + UTF-8).
func cqlString(s string) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(len(s)))
	return append(b, []byte(s)...)
}

// cqlStringMap encodes a CQL string map (int16 BE count + k/v pairs).
func cqlStringMap(pairs ...string) []byte {
	if len(pairs)%2 != 0 {
		panic("cqlStringMap: odd number of arguments")
	}
	var b []byte
	b = binary.BigEndian.AppendUint16(b, uint16(len(pairs)/2))
	for i := 0; i < len(pairs); i += 2 {
		b = append(b, cqlString(pairs[i])...)
		b = append(b, cqlString(pairs[i+1])...)
	}
	return b
}

// cqlLongString encodes a CQL long string (int32 BE length + UTF-8).
func cqlLongString(s string) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(len(s)))
	return append(b, []byte(s)...)
}

func TestDecode_STARTUP(t *testing.T) {
	body := cqlStringMap("CQL_VERSION", "3.0.0", "COMPRESSION", "lz4")
	frame := cqlFrame(0x01, body)
	r, err := Decode(hex.EncodeToString(frame))
	if err != nil {
		t.Fatal(err)
	}
	if r.OpcodeName != "STARTUP" {
		t.Errorf("opcode=%q, want STARTUP", r.OpcodeName)
	}
	if !r.IsStartup {
		t.Error("expected IsStartup=true")
	}
	if !r.IsRequest {
		t.Error("expected IsRequest=true")
	}
	if r.IsResponse {
		t.Error("expected IsResponse=false")
	}
	if r.ProtocolVersion != 4 {
		t.Errorf("protocol_version=%d, want 4", r.ProtocolVersion)
	}
	if r.CQLVersion != "3.0.0" {
		t.Errorf("cql_version=%q, want 3.0.0", r.CQLVersion)
	}
	if r.Compression != "lz4" {
		t.Errorf("compression=%q, want lz4", r.Compression)
	}
	if r.StreamID != 1 {
		t.Errorf("stream_id=%d, want 1", r.StreamID)
	}
}

func TestDecode_STARTUP_NoCOMPRESSION(t *testing.T) {
	body := cqlStringMap("CQL_VERSION", "3.0.0")
	frame := cqlFrame(0x01, body)
	r, err := Decode(hex.EncodeToString(frame))
	if err != nil {
		t.Fatal(err)
	}
	if r.CQLVersion != "3.0.0" {
		t.Errorf("cql_version=%q, want 3.0.0", r.CQLVersion)
	}
	if r.Compression != "" {
		t.Errorf("compression=%q, want empty", r.Compression)
	}
}

func TestDecode_QUERY_SELECT(t *testing.T) {
	qText := "SELECT * FROM keyspace1.users WHERE user_id = 'alice'"
	body := cqlLongString(qText)
	// append minimal consistency + flags (2 bytes: consistency + query flags)
	body = binary.BigEndian.AppendUint16(body, 0x0001) // consistency = ONE
	body = append(body, 0x00)                          // query flags = none
	frame := cqlFrame(0x07, body)
	r, err := Decode(hex.EncodeToString(frame))
	if err != nil {
		t.Fatal(err)
	}
	if r.OpcodeName != "QUERY" {
		t.Errorf("opcode=%q, want QUERY", r.OpcodeName)
	}
	if !r.IsQuery {
		t.Error("expected IsQuery=true")
	}
	if r.QueryText != qText {
		t.Errorf("query_text=%q, want %q", r.QueryText, qText)
	}
	if r.QueryTruncated {
		t.Error("expected QueryTruncated=false for short query")
	}
}

func TestDecode_QUERY_Truncation(t *testing.T) {
	// Build a query longer than 200 chars.
	qText := strings.Repeat("SELECT * FROM t WHERE x = 'y'; ", 20)
	body := cqlLongString(qText)
	frame := cqlFrame(0x07, body)
	r, err := Decode(hex.EncodeToString(frame))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.QueryText) > maxQueryPreview {
		t.Errorf("query_text len=%d, want <= %d", len(r.QueryText), maxQueryPreview)
	}
	if !r.QueryTruncated {
		t.Error("expected QueryTruncated=true for long query")
	}
}

func TestDecode_AUTHENTICATE(t *testing.T) {
	authClass := "org.apache.cassandra.auth.PasswordAuthenticator"
	body := cqlString(authClass)
	// AUTHENTICATE is a response (version byte 0x84 = response + v4)
	var frame []byte
	frame = append(frame, 0x84)                          // response, protocol v4
	frame = append(frame, 0x00)                          // flags
	frame = binary.BigEndian.AppendUint16(frame, 0x0001) // stream
	frame = append(frame, 0x03)                          // opcode AUTHENTICATE
	frame = binary.BigEndian.AppendUint32(frame, uint32(len(body)))
	frame = append(frame, body...)

	r, err := Decode(hex.EncodeToString(frame))
	if err != nil {
		t.Fatal(err)
	}
	if r.OpcodeName != "AUTHENTICATE" {
		t.Errorf("opcode=%q, want AUTHENTICATE", r.OpcodeName)
	}
	if !r.IsResponse {
		t.Error("expected IsResponse=true")
	}
	if r.IsRequest {
		t.Error("expected IsRequest=false")
	}
	if !r.IsAuthExchange {
		t.Error("expected IsAuthExchange=true")
	}
	if r.AuthenticatorClass != authClass {
		t.Errorf("authenticator_class=%q, want %q", r.AuthenticatorClass, authClass)
	}
}

func TestDecode_AUTH_RESPONSE(t *testing.T) {
	// SASL PLAIN: \x00<username>\x00<password>
	sasl := []byte("\x00alice\x00s3cr3t")
	var body []byte
	body = binary.BigEndian.AppendUint32(body, uint32(len(sasl)))
	body = append(body, sasl...)
	frame := cqlFrame(0x0F, body)
	r, err := Decode(hex.EncodeToString(frame))
	if err != nil {
		t.Fatal(err)
	}
	if r.OpcodeName != "AUTH_RESPONSE" {
		t.Errorf("opcode=%q, want AUTH_RESPONSE", r.OpcodeName)
	}
	if !r.IsAuthExchange {
		t.Error("expected IsAuthExchange=true")
	}
	if r.AuthBytes != len(sasl) {
		t.Errorf("auth_bytes=%d, want %d", r.AuthBytes, len(sasl))
	}
}

func TestDecode_ERROR(t *testing.T) {
	errCode := uint32(0x2200) // INVALID_QUERY
	errMsg := "Unknown identifier user_id in selection clause"
	var body []byte
	body = binary.BigEndian.AppendUint32(body, errCode)
	body = append(body, cqlString(errMsg)...)

	// ERROR is a response
	var frame []byte
	frame = append(frame, 0x84)
	frame = append(frame, 0x00)
	frame = binary.BigEndian.AppendUint16(frame, 0x0001)
	frame = append(frame, 0x00) // opcode ERROR
	frame = binary.BigEndian.AppendUint32(frame, uint32(len(body)))
	frame = append(frame, body...)

	r, err := Decode(hex.EncodeToString(frame))
	if err != nil {
		t.Fatal(err)
	}
	if r.OpcodeName != "ERROR" {
		t.Errorf("opcode=%q, want ERROR", r.OpcodeName)
	}
	if r.ErrorCode != int(errCode) {
		t.Errorf("error_code=0x%04x, want 0x%04x", r.ErrorCode, errCode)
	}
	if r.ErrorMessage != errMsg {
		t.Errorf("error_message=%q, want %q", r.ErrorMessage, errMsg)
	}
}

func TestDecode_FlagDecoding(t *testing.T) {
	// Build a frame with compression + tracing flags set.
	var frame []byte
	frame = append(frame, 0x04)                          // request v4
	frame = append(frame, 0x03)                          // flags: compression(0x01) + tracing(0x02)
	frame = binary.BigEndian.AppendUint16(frame, 0x0002) // stream 2
	frame = append(frame, 0x05)                          // OPTIONS opcode
	frame = binary.BigEndian.AppendUint32(frame, 0)      // empty body

	r, err := Decode(hex.EncodeToString(frame))
	if err != nil {
		t.Fatal(err)
	}
	if !r.FlagCompression {
		t.Error("expected FlagCompression=true")
	}
	if !r.FlagTracing {
		t.Error("expected FlagTracing=true")
	}
	if r.FlagWarning {
		t.Error("expected FlagWarning=false")
	}
}

func TestDecode_ProtocolVersions(t *testing.T) {
	tests := []struct {
		versionByte   byte
		wantProtoVer  int
		wantIsRequest bool
	}{
		{0x03, 3, true},
		{0x04, 4, true},
		{0x05, 5, true},
		{0x83, 3, false},
		{0x84, 4, false},
	}
	for _, tc := range tests {
		var frame []byte
		frame = append(frame, tc.versionByte)
		frame = append(frame, 0x00)
		frame = binary.BigEndian.AppendUint16(frame, 0x0000)
		frame = append(frame, 0x05) // OPTIONS
		frame = binary.BigEndian.AppendUint32(frame, 0)

		r, err := Decode(hex.EncodeToString(frame))
		if err != nil {
			t.Fatalf("version byte 0x%02x: %v", tc.versionByte, err)
		}
		if r.ProtocolVersion != tc.wantProtoVer {
			t.Errorf("version byte 0x%02x: proto_ver=%d, want %d",
				tc.versionByte, r.ProtocolVersion, tc.wantProtoVer)
		}
		if r.IsRequest != tc.wantIsRequest {
			t.Errorf("version byte 0x%02x: is_request=%v, want %v",
				tc.versionByte, r.IsRequest, tc.wantIsRequest)
		}
	}
}

func TestDecode_RejectsEmpty(t *testing.T) {
	_, err := Decode("")
	if err == nil {
		t.Fatal("want error for empty input")
	}
}

func TestDecode_RejectsTruncated(t *testing.T) {
	_, err := Decode("04000001")
	if err == nil {
		t.Fatal("want error for truncated input (only 4 bytes)")
	}
}

func TestDecode_OpcodeNameTable(t *testing.T) {
	tests := []struct {
		opcode byte
		want   string
	}{
		{0x00, "ERROR"},
		{0x01, "STARTUP"},
		{0x02, "READY"},
		{0x03, "AUTHENTICATE"},
		{0x05, "OPTIONS"},
		{0x06, "SUPPORTED"},
		{0x07, "QUERY"},
		{0x08, "RESULT"},
		{0x09, "PREPARE"},
		{0x0A, "EXECUTE"},
		{0x0B, "REGISTER"},
		{0x0C, "EVENT"},
		{0x0D, "BATCH"},
		{0x0E, "AUTH_CHALLENGE"},
		{0x0F, "AUTH_RESPONSE"},
		{0x10, "AUTH_SUCCESS"},
	}
	for _, tc := range tests {
		frame := cqlFrame(tc.opcode, nil)
		r, err := Decode(hex.EncodeToString(frame))
		if err != nil {
			t.Fatalf("opcode 0x%02x: %v", tc.opcode, err)
		}
		if r.OpcodeName != tc.want {
			t.Errorf("opcode 0x%02x: name=%q, want %q", tc.opcode, r.OpcodeName, tc.want)
		}
	}
}
