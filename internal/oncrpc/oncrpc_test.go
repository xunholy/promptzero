// SPDX-License-Identifier: AGPL-3.0-or-later

package oncrpc

import (
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseCall(t *testing.T) {
	// A portmap GETPORT call: xid 0x11223344, prog 100000, v2, proc 3,
	// null auth; body is the 16-byte GETPORT args.
	const v = "112233440000000000000002000186a0000000020000000300000000000000000000000000000000000186a3000000030000001100000000"
	m, err := Parse(mustHex(t, v))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !m.IsCall() || m.XID != 0x11223344 {
		t.Fatalf("xid/type = %#x/%d", m.XID, m.Type)
	}
	if m.Program != 100000 || m.ProgramVersion != 2 || m.Procedure != 3 {
		t.Errorf("prog/ver/proc = %d/%d/%d", m.Program, m.ProgramVersion, m.Procedure)
	}
	if m.AuthFlavor != 0 {
		t.Errorf("auth flavor = %d", m.AuthFlavor)
	}
	if len(m.Body) != 16 {
		t.Errorf("body len = %d, want 16 (GETPORT args)", len(m.Body))
	}
}

func TestParseAcceptedReply(t *testing.T) {
	// A GETPORT reply: accepted, success, body is the 4-byte port (2049).
	const v = "11223344000000010000000000000000000000000000000000000801"
	m, err := Parse(mustHex(t, v))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !m.IsReply() || !m.Accepted || m.AcceptStat != 0 {
		t.Fatalf("reply/accepted/stat = %v/%v/%d", m.IsReply(), m.Accepted, m.AcceptStat)
	}
	if len(m.Body) != 4 {
		t.Errorf("body len = %d, want 4", len(m.Body))
	}
}

func TestParseDeniedReply(t *testing.T) {
	const v = "11223344000000010000000100000001"
	m, err := Parse(mustHex(t, v))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if m.ReplyStat != 1 || m.Accepted {
		t.Errorf("denied reply: stat=%d accepted=%v", m.ReplyStat, m.Accepted)
	}
}

func TestParseAuthBody(t *testing.T) {
	// CALL with an AUTH_SYS body (flavor 1, length 4) — Body must start
	// after the auth + null verifier.
	const v = "00000001" + "00000000" + // xid, CALL
		"00000002000186a500000003000000010000000100000004aabbccdd00000000" + // ver/prog/pver/proc, auth flavor 1 len 4 + 4 bytes, verf flavor 0
		"00000000" + // verifier length 0
		"deadbeef" // 4-byte body
	m, err := Parse(mustHex(t, v))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if m.AuthFlavor != 1 {
		t.Errorf("auth flavor = %d, want 1", m.AuthFlavor)
	}
	if hex.EncodeToString(m.Body) != "deadbeef" {
		t.Errorf("body = %x, want deadbeef", m.Body)
	}
}

func TestParseRejects(t *testing.T) {
	if _, err := Parse(mustHex(t, "112233")); err == nil {
		t.Error("expected error on short header")
	}
	if _, err := Parse(mustHex(t, "0000000100000002")); err == nil {
		t.Error("expected error on message type 2")
	}
	if _, err := Parse(mustHex(t, "0000000100000000")); err == nil {
		t.Error("expected error on truncated CALL header")
	}
}

func TestAcceptStatName(t *testing.T) {
	if AcceptStatName(0) != "SUCCESS" || AcceptStatName(2) != "PROG_MISMATCH" {
		t.Error("accept stat names wrong")
	}
}
