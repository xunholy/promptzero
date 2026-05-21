package tools

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"unicode/utf16"
)

func tdsHdr(t byte, status byte, length uint16) []byte {
	h := make([]byte, 8)
	h[0] = t
	h[1] = status
	binary.BigEndian.PutUint16(h[2:4], length)
	h[6] = 1
	return h
}

func tdsUTF16LE(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	out := make([]byte, len(u16)*2)
	for i, c := range u16 {
		binary.LittleEndian.PutUint16(out[i*2:i*2+2], c)
	}
	return out
}

// TestTDSDecodeHandler_PreLoginEncryptionNotSupported pins the
// TLS-downgrade-vulnerable shape.
func TestTDSDecodeHandler_PreLoginEncryptionNotSupported(t *testing.T) {
	body := make([]byte, 7)
	body[0] = 0x01                           // ENCRYPTION
	binary.BigEndian.PutUint16(body[1:3], 6) // offset
	binary.BigEndian.PutUint16(body[3:5], 1) // length
	body[5] = 0xFF
	body[6] = 0x02 // ENCRYPT_NOT_SUP
	msg := append(tdsHdr(0x12, 0x01, uint16(8+len(body))), body...)
	out, err := tdsDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(msg)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"type_name": "PRE_LOGIN"`,
		`"encryption_mode": 2`,
		`TLS-downgrade vulnerable`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestTDSDecodeHandler_Login7CleartextCreds pins the canonical
// SQL-Server credential disclosure shape.
func TestTDSDecodeHandler_Login7CleartextCreds(t *testing.T) {
	host := tdsUTF16LE("workstation01")
	user := tdsUTF16LE("sa")
	pass := tdsUTF16LE("hunter2")
	app := tdsUTF16LE(".Net SqlClient Data Provider")
	srv := tdsUTF16LE("sqlserver.corp.example.com")
	db := tdsUTF16LE("master")
	body := make([]byte, 94)
	binary.LittleEndian.PutUint32(body[4:8], 0x74000004)
	binary.LittleEndian.PutUint32(body[8:12], 4096)
	varStart := 94
	addVar := func(idx int, data []byte) {
		base := 36 + idx*4
		body[base] = byte(varStart)
		body[base+1] = byte(varStart >> 8)
		body[base+2] = byte(len(data) / 2)
		body[base+3] = byte((len(data) / 2) >> 8)
		body = append(body, data...)
		varStart += len(data)
	}
	addVar(0, host)
	addVar(1, user)
	addVar(2, pass)
	addVar(3, app)
	addVar(4, srv)
	addVar(5, nil)
	addVar(6, nil)
	addVar(7, nil)
	addVar(8, db)
	addVar(9, nil)
	msg := append(tdsHdr(0x10, 0x01, uint16(8+len(body))), body...)
	out, err := tdsDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(msg)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"type_name": "TDS7_LOGIN"`,
		`"tds_version_name": "SQL Server 2012/2014/2016/2017/2019/2022"`,
		`"user_name": "sa"`,
		`"password_bytes": 14`,
		`"app_name": ".Net SqlClient Data Provider"`,
		`"database": "master"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestTDSDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := tdsDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
