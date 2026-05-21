package tools

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"unicode/utf16"
)

func smb2Header(command uint16, flags uint32, status uint32,
	messageID uint64, sessionID uint64, treeID uint32) []byte {
	h := make([]byte, 64)
	h[0] = 0xFE
	h[1] = 'S'
	h[2] = 'M'
	h[3] = 'B'
	binary.LittleEndian.PutUint16(h[4:6], 64)
	binary.LittleEndian.PutUint32(h[8:12], status)
	binary.LittleEndian.PutUint16(h[12:14], command)
	binary.LittleEndian.PutUint32(h[16:20], flags)
	binary.LittleEndian.PutUint64(h[24:32], messageID)
	binary.LittleEndian.PutUint32(h[36:40], treeID)
	binary.LittleEndian.PutUint64(h[40:48], sessionID)
	return h
}

func smb2UTF16LE(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	out := make([]byte, len(u16)*2)
	for i, c := range u16 {
		binary.LittleEndian.PutUint16(out[i*2:i*2+2], c)
	}
	return out
}

// TestSMB2DecodeHandler_NegotiateRequest pins the dialect-list
// + SMB1-wildcard shape (EternalBlue candidate).
func TestSMB2DecodeHandler_NegotiateRequest(t *testing.T) {
	dialects := []uint16{0x0202, 0x0210, 0x0300, 0x02FF}
	body := make([]byte, 36+len(dialects)*2)
	binary.LittleEndian.PutUint16(body[0:2], 36)
	binary.LittleEndian.PutUint16(body[2:4],
		uint16(len(dialects)))
	binary.LittleEndian.PutUint16(body[4:6], 0x01)
	for i, d := range dialects {
		binary.LittleEndian.PutUint16(body[36+i*2:38+i*2], d)
	}
	msg := append(smb2Header(0x00, 0x00, 0x00, 1, 0, 0), body...)
	out, err := smb2DecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(msg)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"command_name": "NEGOTIATE"`,
		`"smb1_offered": true`,
		`"signing_enabled": true`,
		`"signing_required": false`,
		`"SMB 2.0.2"`,
		`"SMB 3.0"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestSMB2DecodeHandler_TreeConnectAdminShare pins ADMIN$ access.
func TestSMB2DecodeHandler_TreeConnectAdminShare(t *testing.T) {
	path := `\\dc01\ADMIN$`
	pathBytes := smb2UTF16LE(path)
	body := make([]byte, 8+len(pathBytes))
	binary.LittleEndian.PutUint16(body[0:2], 9)
	binary.LittleEndian.PutUint16(body[4:6], uint16(64+8))
	binary.LittleEndian.PutUint16(body[6:8],
		uint16(len(pathBytes)))
	copy(body[8:], pathBytes)
	msg := append(smb2Header(0x03, 0x00, 0x00, 5, 1, 0), body...)
	out, err := smb2DecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(msg)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"command_name": "TREE_CONNECT"`,
		`"tree_connect_path": "\\\\dc01\\ADMIN$"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestSMB2DecodeHandler_CreateSpoolssPipe pins the
// PrintNightmare named-pipe access shape.
func TestSMB2DecodeHandler_CreateSpoolssPipe(t *testing.T) {
	name := `spoolss`
	nameBytes := smb2UTF16LE(name)
	body := make([]byte, 56+len(nameBytes))
	binary.LittleEndian.PutUint16(body[0:2], 57)
	binary.LittleEndian.PutUint16(body[44:46],
		uint16(64+56))
	binary.LittleEndian.PutUint16(body[46:48],
		uint16(len(nameBytes)))
	copy(body[56:], nameBytes)
	msg := append(smb2Header(0x05, 0x00, 0x00, 6, 1, 1), body...)
	out, err := smb2DecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(msg)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"command_name": "CREATE"`,
		`"create_name": "spoolss"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestSMB2DecodeHandler_SessionSetupLogonFailure pins the
// password-spray feedback signal.
func TestSMB2DecodeHandler_SessionSetupLogonFailure(t *testing.T) {
	msg := smb2Header(0x01, 0x01, 0xC000006D, 2, 0xDEADBEEF, 0)
	body := make([]byte, 9)
	binary.LittleEndian.PutUint16(body[0:2], 9)
	msg = append(msg, body...)
	out, err := smb2DecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(msg)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"command_name": "SESSION_SETUP"`,
		`"status_name": "STATUS_LOGON_FAILURE"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestSMB2DecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := smb2DecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
