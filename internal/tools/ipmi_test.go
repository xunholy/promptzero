package tools

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// ipmiRMCPHeader returns the 4-byte RMCP header with version=0x06 and class=0x07 (IPMI).
func ipmiRMCPHeader(seq byte) []byte {
	return []byte{0x06, 0x00, seq, 0x07}
}

// ipmiSession15 returns an IPMI 1.5 session header (auth_type=None)
// followed by the IPMI message.
func ipmiSession15(sessionSeq, sessionID uint32, msg []byte) []byte {
	var b []byte
	b = append(b, 0x00) // auth_type = None
	b = binary.LittleEndian.AppendUint32(b, sessionSeq)
	b = binary.LittleEndian.AppendUint32(b, sessionID)
	b = append(b, byte(len(msg))) // message_length
	b = append(b, msg...)
	return b
}

// ipmiMsg builds a minimal IPMI LAN message.
func ipmiMsg(rsAddr, netFnLUN, rqAddr, rqSeqLUN, cmd byte) []byte {
	cksum1 := byte(-(int(rsAddr) + int(netFnLUN)))
	cksum2 := byte(-(int(rqAddr) + int(rqSeqLUN) + int(cmd)))
	return []byte{rsAddr, netFnLUN, cksum1, rqAddr, rqSeqLUN, cmd, cksum2}
}

// TestIPMIDecodeHandler_GetChannelAuthCapabilities tests the auth probe
// command (Get Channel Auth Capabilities, NetFn=0x06 cmd=0x38).
func TestIPMIDecodeHandler_GetChannelAuthCapabilities(t *testing.T) {
	// NetFn=0x06 request → netFnLUN = (0x06 << 2) | 0 = 0x18, cmd=0x38
	msg := ipmiMsg(0x20, 0x18, 0x81, 0x04, 0x38)
	session := ipmiSession15(0, 0, msg)
	pkt := append(ipmiRMCPHeader(0xFF), session...)

	out, err := ipmiDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(pkt)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"rmcp_class_name": "IPMI"`,
		`"auth_type_name": "None"`,
		`"net_fn_name": "App"`,
		`"command_name": "Get Channel Auth Capabilities"`,
		`"is_auth_probe": true`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestIPMIDecodeHandler_GetDeviceID tests the firmware version fingerprint
// command (Get Device ID, NetFn=0x06 cmd=0x01).
func TestIPMIDecodeHandler_GetDeviceID(t *testing.T) {
	// NetFn=0x06 request → netFnLUN=0x18, cmd=0x01
	msg := ipmiMsg(0x20, 0x18, 0x81, 0x08, 0x01)
	session := ipmiSession15(0, 0, msg)
	pkt := append(ipmiRMCPHeader(0x01), session...)

	out, err := ipmiDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(pkt)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"command_name": "Get Device ID"`,
		`"is_version_probe": true`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestIPMIDecodeHandler_RejectsEmpty tests that an empty hex string returns an error.
func TestIPMIDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := ipmiDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
