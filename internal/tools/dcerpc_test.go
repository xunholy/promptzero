package tools

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

func dcerpcHdr(ptype, pfc byte, fragLen uint16, callID uint32) []byte {
	h := make([]byte, 16)
	h[0] = 5
	h[1] = 0
	h[2] = ptype
	h[3] = pfc
	h[4] = 0x10
	binary.LittleEndian.PutUint16(h[8:10], fragLen)
	binary.LittleEndian.PutUint32(h[12:16], callID)
	return h
}

func dcerpcUUID(d1 uint32, d2, d3 uint16, last8 [8]byte) []byte {
	b := make([]byte, 16)
	binary.LittleEndian.PutUint32(b[0:4], d1)
	binary.LittleEndian.PutUint16(b[4:6], d2)
	binary.LittleEndian.PutUint16(b[6:8], d3)
	copy(b[8:16], last8[:])
	return b
}

func dcerpcBindBody(uuid []byte, vMaj, vMin uint16) []byte {
	body := make([]byte, 36)
	binary.LittleEndian.PutUint16(body[0:2], 4280)
	binary.LittleEndian.PutUint16(body[2:4], 4280)
	body[8] = 1
	body[14] = 1
	copy(body[16:32], uuid)
	binary.LittleEndian.PutUint16(body[32:34], vMaj)
	binary.LittleEndian.PutUint16(body[34:36], vMin)
	return body
}

// TestDCERPCDecodeHandler_BindNetlogon pins the ZeroLogon
// attack signature.
func TestDCERPCDecodeHandler_BindNetlogon(t *testing.T) {
	uuid := dcerpcUUID(0x12345678, 0x1234, 0xabcd,
		[8]byte{0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0xcf, 0xfb})
	body := dcerpcBindBody(uuid, 1, 0)
	msg := append(dcerpcHdr(11, 0x03, 0, 1), body...)
	out, err := dcerpcDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(msg)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"ptype_name": "BIND"`,
		`"interface_uuid": "12345678-1234-abcd-ef00-01234567cffb"`,
		`netlogon`,
		`ZeroLogon`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestDCERPCDecodeHandler_BindDrsuapi pins the DCSync attack
// signature.
func TestDCERPCDecodeHandler_BindDrsuapi(t *testing.T) {
	uuid := dcerpcUUID(0xe3514235, 0x4b06, 0x11d1,
		[8]byte{0xab, 0x04, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2})
	body := dcerpcBindBody(uuid, 4, 0)
	msg := append(dcerpcHdr(11, 0x03, 0, 2), body...)
	out, err := dcerpcDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(msg)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, "DCSync") {
		t.Errorf("expected DCSync flag in output:\n%s", out)
	}
}

// TestDCERPCDecodeHandler_RequestOpnum30 pins the ZeroLogon
// REQUEST shape (opnum 30 = NetrServerAuthenticate3).
func TestDCERPCDecodeHandler_RequestOpnum30(t *testing.T) {
	body := make([]byte, 8)
	binary.LittleEndian.PutUint32(body[0:4], 256)
	binary.LittleEndian.PutUint16(body[6:8], 30)
	msg := append(dcerpcHdr(0, 0x03, 24, 5), body...)
	out, err := dcerpcDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(msg)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"ptype_name": "REQUEST"`,
		`"opnum": 30`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestDCERPCDecodeHandler_Fault pins the FAULT status decode.
func TestDCERPCDecodeHandler_Fault(t *testing.T) {
	body := make([]byte, 12)
	binary.LittleEndian.PutUint32(body[8:12], 0x00000005)
	msg := append(dcerpcHdr(3, 0x03, 28, 6), body...)
	out, err := dcerpcDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(msg)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"ptype_name": "FAULT"`,
		`"fault_status_name": "nca_s_fault_access_denied"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestDCERPCDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := dcerpcDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
