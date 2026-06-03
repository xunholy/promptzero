// SPDX-License-Identifier: AGPL-3.0-or-later

package smb2

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// ntlmType2 is a minimal NTLMSSP CHALLENGE (Type 2) message: signature +
// type 2 + empty target-name fields + flags + 8-byte server challenge +
// reserved + empty target-info fields.
func ntlmType2() []byte {
	b, _ := hex.DecodeString(
		"4E544C4D53535000" + // "NTLMSSP\0"
			"02000000" + //         MessageType = 2 (CHALLENGE)
			"0000000000000000" + // TargetName len/maxlen/offset
			"00000000" + //         NegotiateFlags
			"1122334455667788" + // ServerChallenge
			"0000000000000000" + // Reserved
			"0000000000000000") //  TargetInfo len/maxlen/offset
	return b
}

// sessionSetupResponse builds a SESSION_SETUP response carrying the given
// security buffer (StructureSize 9; offset/length at body[4:8]).
func sessionSetupResponse(secBuf []byte) []byte {
	body := make([]byte, 8)
	binary.LittleEndian.PutUint16(body[0:2], 9)                    // StructureSize
	binary.LittleEndian.PutUint16(body[4:6], uint16(headerSize+8)) // SecurityBufferOffset
	binary.LittleEndian.PutUint16(body[6:8], uint16(len(secBuf)))  // SecurityBufferLength
	body = append(body, secBuf...)
	return append(header(0x01, 0x01, 0x00, 2, 0xCAFE, 0), body...)
}

// sessionSetupRequest builds a SESSION_SETUP request (StructureSize 25;
// offset/length at body[12:16]).
func sessionSetupRequest(secBuf []byte) []byte {
	body := make([]byte, 24)
	binary.LittleEndian.PutUint16(body[0:2], 25)                      // StructureSize
	binary.LittleEndian.PutUint16(body[12:14], uint16(headerSize+24)) // SecurityBufferOffset
	binary.LittleEndian.PutUint16(body[14:16], uint16(len(secBuf)))   // SecurityBufferLength
	body = append(body, secBuf...)
	return append(header(0x01, 0x00, 0x00, 2, 0, 0), body...)
}

func TestDecodeSessionSetup_NTLMChallenge(t *testing.T) {
	msg := sessionSetupResponse(ntlmType2())
	r, err := Decode(hex.EncodeToString(msg))
	if err != nil {
		t.Fatal(err)
	}
	if r.CommandName != "SESSION_SETUP" {
		t.Fatalf("command = %s", r.CommandName)
	}
	if r.NTLMMessage == nil {
		t.Fatal("NTLMSSP message not decoded from the security buffer")
	}
	// The decoded NTLM message should be a CHALLENGE (type 2).
	if r.NTLMMessage.MessageType != 2 {
		t.Errorf("NTLM message type = %d, want 2", r.NTLMMessage.MessageType)
	}
}

func TestDecodeSessionSetup_SPNEGOWrappedNTLM(t *testing.T) {
	// NTLMSSP not at offset 0 — preceded by SPNEGO/GSS-API wrapper bytes.
	// The 8-byte signature scan finds it regardless.
	spnego := append([]byte{0xA1, 0x82, 0x01, 0x00, 0x30, 0x82}, ntlmType2()...)
	r, err := Decode(hex.EncodeToString(sessionSetupResponse(spnego)))
	if err != nil {
		t.Fatal(err)
	}
	if r.NTLMMessage == nil || r.NTLMMessage.MessageType != 2 {
		t.Fatalf("SPNEGO-wrapped NTLMSSP not decoded: %+v", r.NTLMMessage)
	}
}

func TestDecodeSessionSetup_Request(t *testing.T) {
	// NTLMSSP NEGOTIATE (type 1) in a request.
	t1, _ := hex.DecodeString("4E544C4D53535000" + "01000000" + "0000000000000000000000000000000000000000")
	r, err := Decode(hex.EncodeToString(sessionSetupRequest(t1)))
	if err != nil {
		t.Fatal(err)
	}
	if r.NTLMMessage == nil || r.NTLMMessage.MessageType != 1 {
		t.Fatalf("request NTLMSSP not decoded: %+v", r.NTLMMessage)
	}
}

func TestDecodeSessionSetup_KerberosNotDecoded(t *testing.T) {
	// A GSS-API/Kerberos token (no NTLMSSP signature) — left for the operator.
	kerb := []byte{0x60, 0x82, 0x02, 0x00, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12}
	r, err := Decode(hex.EncodeToString(sessionSetupResponse(kerb)))
	if err != nil {
		t.Fatal(err)
	}
	if r.NTLMMessage != nil {
		t.Errorf("a Kerberos token should not decode as NTLM")
	}
	if r.SecurityBufferBytes != len(kerb) {
		t.Errorf("security buffer length = %d, want %d", r.SecurityBufferBytes, len(kerb))
	}
}
