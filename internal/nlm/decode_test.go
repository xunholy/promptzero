// SPDX-License-Identifier: AGPL-3.0-or-later

package nlm

import "testing"

// Vectors produced with scapy's NLM + ONC RPC layers (scapy.contrib.nlm /
// oncrpc) and verified field-for-field.

func TestDecodeLock(t *testing.T) {
	// LOCK call: exclusive, caller "client01", fh AABBCCDD, owner "owner-xyz",
	// svid 1234, offset 4096, len 8192.
	const v = "112233440000000000000002000186b50000000400000002000000000000000000000000000000000000000401020304000000000000000100000008636c69656e74303100000004aabbccdd000000096f776e65722d78797a000000000004d2000000000000100000000000000020000000000000000007"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MessageName != "CALL" || r.ProcName != "LOCK" {
		t.Fatalf("msg/proc = %q/%q", r.MessageName, r.ProcName)
	}
	if r.Program == nil || *r.Program != 100021 {
		t.Errorf("program = %v", r.Program)
	}
	if r.Caller != "client01" {
		t.Errorf("caller = %q, want client01", r.Caller)
	}
	if r.FileHandle != "AABBCCDD" {
		t.Errorf("fh = %q", r.FileHandle)
	}
	if r.Owner != "owner-xyz" {
		t.Errorf("owner = %q, want owner-xyz", r.Owner)
	}
	if r.SVID == nil || *r.SVID != 1234 {
		t.Errorf("svid = %v", r.SVID)
	}
	if r.Offset == nil || *r.Offset != 4096 || r.Length == nil || *r.Length != 8192 {
		t.Errorf("offset/len = %v/%v", r.Offset, r.Length)
	}
	if r.Exclusive == nil || !*r.Exclusive {
		t.Errorf("exclusive = %v, want true", r.Exclusive)
	}
}

func TestDecodeTest(t *testing.T) {
	// TEST call (no block field): caller "host2", fh 11223344, owner "own2".
	const v = "000000010000000000000002000186b500000004000000010000000000000000000000000000000000000004010203040000000100000005686f7374320000000000000411223344000000046f776e320000000500000000000000000000000000000064"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.ProcName != "TEST" {
		t.Fatalf("proc = %q", r.ProcName)
	}
	if r.Caller != "host2" || r.FileHandle != "11223344" || r.Owner != "own2" {
		t.Errorf("caller/fh/owner = %q/%q/%q", r.Caller, r.FileHandle, r.Owner)
	}
	if r.Length == nil || *r.Length != 100 {
		t.Errorf("len = %v, want 100", r.Length)
	}
}

func TestDecodeUnlock(t *testing.T) {
	// UNLOCK call (no block, no exclusive): caller "h3", owner "o3".
	const v = "000000010000000000000002000186b5000000040000000400000000000000000000000000000000000000040102030400000002683300000000000455667788000000026f33000000000009000000000000000a0000000000000014"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.ProcName != "UNLOCK" {
		t.Fatalf("proc = %q", r.ProcName)
	}
	if r.Caller != "h3" || r.Owner != "o3" {
		t.Errorf("caller/owner = %q/%q", r.Caller, r.Owner)
	}
	if r.Exclusive != nil {
		t.Error("UNLOCK has no exclusive flag")
	}
	if r.Offset == nil || *r.Offset != 10 || r.Length == nil || *r.Length != 20 {
		t.Errorf("offset/len = %v/%v", r.Offset, r.Length)
	}
}

func TestDecodeReply(t *testing.T) {
	// LOCK reply: cookie 01020304, status 4 (NLM4_DENIED_GRACE_PERIOD).
	const v = "112233440000000100000000000000000000000000000000000000040102030400000004"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MessageName != "REPLY" {
		t.Fatalf("msg = %q", r.MessageName)
	}
	if r.Status == nil || *r.Status != 4 || r.StatusName != "NLM4_DENIED_GRACE_PERIOD" {
		t.Errorf("status = %v/%q", r.Status, r.StatusName)
	}
}

func TestDecodeTruncated(t *testing.T) {
	if _, err := Decode("112233"); err == nil {
		t.Fatal("expected error on short input")
	}
}
