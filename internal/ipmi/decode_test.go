package ipmi

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// rmcpHeader builds the 4-byte RMCP header.
func rmcpHeader(seq byte, class byte) []byte {
	return []byte{0x06, 0x00, seq, class}
}

// ipmi15Session builds an IPMI 1.5 session header (no auth_code) followed by
// the given IPMI message bytes.
func ipmi15Session(authType byte, sessionSeq, sessionID uint32, msgLen byte, msg []byte) []byte {
	var b []byte
	b = append(b, authType)
	b = binary.LittleEndian.AppendUint32(b, sessionSeq)
	b = binary.LittleEndian.AppendUint32(b, sessionID)
	b = append(b, msgLen)
	b = append(b, msg...)
	return b
}

// ipmiMessage builds a minimal IPMI LAN message payload.
// rsAddr: target address (0x20 = BMC)
// netFnLUN: (netFn << 2) | rsLUN
// rqAddr: source address (0x81 = remote console)
// rqSeqLUN: (rqSeq << 2) | rqLUN
// cmd: command byte
func ipmiMessage(rsAddr, netFnLUN, rqAddr, rqSeqLUN, cmd byte, data []byte) []byte {
	cksum1 := byte(-(int(rsAddr) + int(netFnLUN)))
	cksum2Acc := int(rqAddr) + int(rqSeqLUN) + int(cmd)
	for _, d := range data {
		cksum2Acc += int(d)
	}
	cksum2 := byte(-cksum2Acc)

	var b []byte
	b = append(b, rsAddr)
	b = append(b, netFnLUN)
	b = append(b, cksum1)
	b = append(b, rqAddr)
	b = append(b, rqSeqLUN)
	b = append(b, cmd)
	b = append(b, data...)
	b = append(b, cksum2)
	return b
}

// rmcpPlusSession builds an IPMI 2.0 / RMCP+ session header.
func rmcpPlusSession(payloadTypeByte byte, sessionID, sessionSeq uint32, payload []byte) []byte {
	var b []byte
	b = append(b, 0x06) // auth_type = RMCP+
	b = append(b, payloadTypeByte)
	b = binary.LittleEndian.AppendUint32(b, sessionID)
	b = binary.LittleEndian.AppendUint32(b, sessionSeq)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(payload)))
	b = append(b, payload...)
	return b
}

// TestDecode_GetChannelAuthCapabilities tests the key IPMI auth probe.
// RMCP + IPMI 1.5 (auth_type=0) + Get Channel Auth Capabilities.
func TestDecode_GetChannelAuthCapabilities(t *testing.T) {
	// NetFn=0x06 (App) request → netFnLUN = (0x06 << 2) | 0 = 0x18
	// cmd = 0x38
	msg := ipmiMessage(0x20, 0x18, 0x81, 0x04, 0x38, []byte{0x0E, 0x04})
	session := ipmi15Session(0x00, 0, 0, byte(len(msg)), msg)
	pkt := append(rmcpHeader(0xFF, 0x07), session...)
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.RMCPClass != 0x07 {
		t.Errorf("rmcp_class=%d, want 7 (IPMI)", r.RMCPClass)
	}
	if r.RMCPClassName != "IPMI" {
		t.Errorf("rmcp_class_name=%q, want IPMI", r.RMCPClassName)
	}
	if r.AuthType != 0x00 {
		t.Errorf("auth_type=%d, want 0 (None)", r.AuthType)
	}
	if r.AuthTypeName != "None" {
		t.Errorf("auth_type_name=%q, want None", r.AuthTypeName)
	}
	if r.IsRMCPPlus {
		t.Error("is_rmcp_plus=true, want false")
	}
	if r.NetFn != 0x06 {
		t.Errorf("net_fn=0x%02x, want 0x06", r.NetFn)
	}
	if r.NetFnName != "App" {
		t.Errorf("net_fn_name=%q, want App", r.NetFnName)
	}
	if r.Command != 0x38 {
		t.Errorf("command=0x%02x, want 0x38", r.Command)
	}
	if r.CommandName != "Get Channel Auth Capabilities" {
		t.Errorf("command_name=%q, want Get Channel Auth Capabilities", r.CommandName)
	}
	if !r.IsAuthProbe {
		t.Error("expected is_auth_probe=true")
	}
	if r.IsVersionProbe {
		t.Error("is_version_probe=true, want false")
	}
	if r.RsAddr != 0x20 {
		t.Errorf("rs_addr=0x%02x, want 0x20 (BMC)", r.RsAddr)
	}
}

// TestDecode_GetDeviceID tests the IPMI version fingerprint command.
// RMCP + IPMI 1.5 (auth_type=0) + Get Device ID.
func TestDecode_GetDeviceID(t *testing.T) {
	// NetFn=0x06 (App) → netFnLUN = 0x18, cmd=0x01
	msg := ipmiMessage(0x20, 0x18, 0x81, 0x08, 0x01, nil)
	session := ipmi15Session(0x00, 0, 0, byte(len(msg)), msg)
	pkt := append(rmcpHeader(0x01, 0x07), session...)
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Command != 0x01 {
		t.Errorf("command=0x%02x, want 0x01", r.Command)
	}
	if r.CommandName != "Get Device ID" {
		t.Errorf("command_name=%q, want Get Device ID", r.CommandName)
	}
	if !r.IsVersionProbe {
		t.Error("expected is_version_probe=true")
	}
	if r.IsAuthProbe {
		t.Error("is_auth_probe=true, want false")
	}
}

// TestDecode_RMCPPlus_OpenSessionRequest tests RMCP+ Open Session Request
// (payload_type=0x10).
func TestDecode_RMCPPlus_OpenSessionRequest(t *testing.T) {
	// Minimal Open Session Request payload (16 bytes per spec)
	payload := make([]byte, 16)
	binary.LittleEndian.PutUint32(payload[0:4], 0xDEADBEEF) // remote session ID
	// payload_type=0x10 (Open Session Request), not encrypted or authenticated
	session := rmcpPlusSession(0x10, 0, 1, payload)
	pkt := append(rmcpHeader(0x02, 0x07), session...)
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.IsRMCPPlus {
		t.Error("expected is_rmcp_plus=true")
	}
	if r.PayloadType != 0x10 {
		t.Errorf("payload_type=0x%02x, want 0x10", r.PayloadType)
	}
	if r.PayloadTypeName != "Open Session Request" {
		t.Errorf("payload_type_name=%q, want Open Session Request", r.PayloadTypeName)
	}
	if r.PayloadEncrypted {
		t.Error("payload_encrypted=true, want false")
	}
	if r.PayloadAuthenticated {
		t.Error("payload_authenticated=true, want false")
	}
	if r.IsRAKPExchange {
		t.Error("is_rakp_exchange=true for Open Session Request, want false")
	}
	if r.SessionSeq != 1 {
		t.Errorf("session_seq=%d, want 1", r.SessionSeq)
	}
}

// TestDecode_RMCPPlus_RAKPMessage2 tests RMCP+ RAKP Message 2 (payload_type=0x13).
// This is the message that leaks the HMAC-SHA1 hash for offline cracking (hashcat mode 7300).
func TestDecode_RMCPPlus_RAKPMessage2(t *testing.T) {
	// Minimal RAKP Message 2 payload (36+ bytes per spec, but we can use a short stub)
	// to test classification; actual hash extraction is out of scope.
	payload := make([]byte, 36)
	payload[0] = 0x00                                       // message tag
	payload[1] = 0x00                                       // RAKP return code (success)
	binary.LittleEndian.PutUint32(payload[4:8], 0xCAFEBABE) // managed system session ID
	// payload_type = 0x13 (RAKP Message 2)
	session := rmcpPlusSession(0x13, 0xCAFEBABE, 0, payload)
	pkt := append(rmcpHeader(0x03, 0x07), session...)
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.IsRMCPPlus {
		t.Error("expected is_rmcp_plus=true")
	}
	if r.PayloadType != 0x13 {
		t.Errorf("payload_type=0x%02x, want 0x13", r.PayloadType)
	}
	if r.PayloadTypeName != "RAKP Message 2" {
		t.Errorf("payload_type_name=%q, want RAKP Message 2", r.PayloadTypeName)
	}
	if !r.IsRAKPExchange {
		t.Error("expected is_rakp_exchange=true for RAKP Message 2")
	}
	if r.SessionID != 0xCAFEBABE {
		t.Errorf("session_id=0x%08x, want 0xcafebabe", r.SessionID)
	}
}

// TestDecode_RejectsEmpty verifies empty input returns an error.
func TestDecode_RejectsEmpty(t *testing.T) {
	_, err := Decode("")
	if err == nil {
		t.Fatal("want error for empty input")
	}
}

// TestDecode_RejectsTruncated verifies a 2-byte input (shorter than the 4-byte
// RMCP header) returns an error.
func TestDecode_RejectsTruncated(t *testing.T) {
	b := []byte{0x06, 0x00}
	_, err := Decode(hex.EncodeToString(b))
	if err == nil {
		t.Fatal("want error for truncated input")
	}
}
