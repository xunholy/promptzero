package tools

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

func myPktHdr(payloadLen int, seq byte) []byte {
	return []byte{
		byte(payloadLen),
		byte(payloadLen >> 8),
		byte(payloadLen >> 16),
		seq,
	}
}

func myHandshakeV10(serverVer, pluginName string,
	caps uint32) []byte {
	payload := []byte{0x0A}
	payload = append(payload, []byte(serverVer)...)
	payload = append(payload, 0x00)
	cid := make([]byte, 4)
	binary.LittleEndian.PutUint32(cid, 1234)
	payload = append(payload, cid...)
	payload = append(payload, make([]byte, 8)...)
	payload = append(payload, 0x00)
	capLow := make([]byte, 2)
	binary.LittleEndian.PutUint16(capLow, uint16(caps&0xFFFF))
	payload = append(payload, capLow...)
	payload = append(payload, 0x21)
	statFlags := make([]byte, 2)
	binary.LittleEndian.PutUint16(statFlags, 0x0002)
	payload = append(payload, statFlags...)
	capHigh := make([]byte, 2)
	binary.LittleEndian.PutUint16(capHigh, uint16(caps>>16))
	payload = append(payload, capHigh...)
	payload = append(payload, 21)
	payload = append(payload, make([]byte, 10)...)
	payload = append(payload, make([]byte, 13)...)
	payload = append(payload, []byte(pluginName)...)
	payload = append(payload, 0x00)
	return append(myPktHdr(len(payload), 0), payload...)
}

func myHandshakeResp(user, db, plugin string, caps uint32,
	authLen byte) []byte {
	payload := make([]byte, 32)
	binary.LittleEndian.PutUint32(payload[0:4], caps)
	binary.LittleEndian.PutUint32(payload[4:8], 16777216)
	payload[8] = 0x21
	payload = append(payload, []byte(user)...)
	payload = append(payload, 0x00)
	payload = append(payload, authLen)
	payload = append(payload, make([]byte, int(authLen))...)
	if caps&0x00000008 != 0 {
		payload = append(payload, []byte(db)...)
		payload = append(payload, 0x00)
	}
	if caps&0x00080000 != 0 {
		payload = append(payload, []byte(plugin)...)
		payload = append(payload, 0x00)
	}
	return append(myPktHdr(len(payload), 1), payload...)
}

func myERR(code uint16, sqlState, message string) []byte {
	payload := []byte{0xFF}
	codeBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(codeBytes, code)
	payload = append(payload, codeBytes...)
	payload = append(payload, '#')
	payload = append(payload, []byte(sqlState)...)
	payload = append(payload, []byte(message)...)
	return append(myPktHdr(len(payload), 1), payload...)
}

func TestMySQLDecodeHandler_HandshakeV10(t *testing.T) {
	pkt := myHandshakeV10("8.0.35-0ubuntu0.22.04.1",
		"caching_sha2_password",
		0x00000800|0x00080000)
	out, err := mysqlDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(pkt)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"is_handshake": true`,
		`"server_version": "8.0.35-0ubuntu0.22.04.1"`,
		`"auth_plugin_name": "caching_sha2_password"`,
		`MySQL 8 default`,
		`"ssl_supported": true`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestMySQLDecodeHandler_NativePasswordWeak(t *testing.T) {
	pkt := myHandshakeV10("5.7.42",
		"mysql_native_password",
		0x00080000)
	out, err := mysqlDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(pkt)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, "offline-crackable") {
		t.Errorf("expected offline-crackable flag in output:\n%s", out)
	}
}

func TestMySQLDecodeHandler_HandshakeResponse(t *testing.T) {
	pkt := myHandshakeResp("admin", "production",
		"mysql_native_password",
		0x00000008|0x00008000|0x00080000,
		20)
	out, err := mysqlDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(pkt)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"is_handshake_response": true`,
		`"user_name": "admin"`,
		`"database": "production"`,
		`"client_plugin_name": "mysql_native_password"`,
		`"auth_data_bytes": 20`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestMySQLDecodeHandler_AccessDeniedError(t *testing.T) {
	pkt := myERR(1045, "28000",
		"Access denied for user 'admin'@'10.0.0.5'")
	out, err := mysqlDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(pkt)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"is_err_packet": true`,
		`"error_code": 1045`,
		`ER_ACCESS_DENIED_ERROR`,
		`brute-force feedback`,
		`"sql_state": "28000"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestMySQLDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := mysqlDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
