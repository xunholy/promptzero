// SPDX-License-Identifier: AGPL-3.0-or-later

package nfs

import "testing"

// Vectors produced with scapy's NFS + ONC RPC layers (scapy.contrib.nfs /
// oncrpc) and verified field-for-field.

func TestDecodeLookup(t *testing.T) {
	// LOOKUP call: dir handle 01020304, filename "passwd".
	const v = "112233440000000000000002000186a30000000300000003000000000000000000000000000000000000000401020304000000067061737377640000"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MessageName != "CALL" || r.ProcName != "LOOKUP" {
		t.Fatalf("msg/proc = %q/%q", r.MessageName, r.ProcName)
	}
	if r.Program == nil || *r.Program != 100003 {
		t.Errorf("program = %v", r.Program)
	}
	if r.FileHandle != "01020304" {
		t.Errorf("dir handle = %q", r.FileHandle)
	}
	if r.Filename != "passwd" {
		t.Errorf("filename = %q, want passwd", r.Filename)
	}
}

func TestDecodeRead(t *testing.T) {
	// READ call: handle aabbccdd, offset 4096, count 8192.
	const v = "000000010000000000000002000186a300000003000000060000000000000000000000000000000000000004aabbccdd000000000000100000002000"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.ProcName != "READ" {
		t.Fatalf("proc = %q", r.ProcName)
	}
	if r.FileHandle != "AABBCCDD" {
		t.Errorf("handle = %q", r.FileHandle)
	}
	if r.Offset == nil || *r.Offset != 4096 {
		t.Errorf("offset = %v, want 4096", r.Offset)
	}
	if r.Count == nil || *r.Count != 8192 {
		t.Errorf("count = %v, want 8192", r.Count)
	}
}

func TestDecodeRemove(t *testing.T) {
	// REMOVE call: dir handle 01020304, filename "secret.txt".
	const v = "000000010000000000000002000186a3000000030000000c0000000000000000000000000000000000000004010203040000000a7365637265742e7478740000"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.ProcName != "REMOVE" || r.Filename != "secret.txt" {
		t.Errorf("proc/filename = %q/%q", r.ProcName, r.Filename)
	}
}

func TestDecodeRename(t *testing.T) {
	// RENAME call: from "a" to "bb".
	const v = "000000010000000000000002000186a3000000030000000e000000000000000000000000000000000000000401020304000000016100000000000004050607080000000262620000"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.ProcName != "RENAME" {
		t.Fatalf("proc = %q", r.ProcName)
	}
	if r.Filename != "a" || r.Filename2 != "bb" {
		t.Errorf("names = %q -> %q, want a -> bb", r.Filename, r.Filename2)
	}
	if r.FileHandle != "01020304" || r.FileHandle2 != "05060708" {
		t.Errorf("handles = %q / %q", r.FileHandle, r.FileHandle2)
	}
}

func TestDecodeGetattr(t *testing.T) {
	// GETATTR call: handle 01020304.
	const v = "000000010000000000000002000186a30000000300000001000000000000000000000000000000000000000401020304"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.ProcName != "GETATTR" || r.FileHandle != "01020304" {
		t.Errorf("proc/handle = %q/%q", r.ProcName, r.FileHandle)
	}
	if r.Filename != "" {
		t.Error("GETATTR carries no filename")
	}
}

func TestDecodeTruncated(t *testing.T) {
	if _, err := Decode("112233"); err == nil {
		t.Fatal("expected error on short input")
	}
}
