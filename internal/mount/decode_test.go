// SPDX-License-Identifier: AGPL-3.0-or-later

package mount

import "testing"

// Vectors produced with scapy's NFS-MOUNT + ONC RPC layers
// (scapy.contrib.mount / oncrpc) and verified field-for-field.

func TestDecodeMountCall(t *testing.T) {
	// RPC(CALL)/RPC_Call(prog=100005, v3, proc=1 MNT)/MOUNT_Call("/export/home")
	const v = "112233440000000000000002000186a50000000300000001000000000000000000000000000000000000000c2f6578706f72742f686f6d65"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MessageName != "CALL" || r.ProcName != "MNT" {
		t.Fatalf("msg/proc = %q/%q", r.MessageName, r.ProcName)
	}
	if r.Program == nil || *r.Program != 100005 {
		t.Errorf("program = %v", r.Program)
	}
	if r.Path != "/export/home" {
		t.Errorf("path = %q, want /export/home", r.Path)
	}
}

func TestDecodeMountReplyOK(t *testing.T) {
	// MOUNT reply OK: filehandle aabbccdd01020304, 1 flavor AUTH_SYS.
	const v = "1122334400000001000000000000000000000000000000000000000000000008aabbccdd010203040000000100000001"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Status == nil || *r.Status != 0 || r.StatusName != "MNT3_OK" {
		t.Fatalf("status = %v/%q", r.Status, r.StatusName)
	}
	if r.FileHandle != "AABBCCDD01020304" {
		t.Errorf("fh = %q", r.FileHandle)
	}
	if len(r.AuthFlavors) != 1 || r.AuthFlavors[0] != "AUTH_SYS (AUTH_UNIX)" {
		t.Errorf("flavors = %v", r.AuthFlavors)
	}
}

func TestDecodeMountReplyDenied(t *testing.T) {
	// MOUNT reply: status 13 (MNT3ERR_ACCES).
	const v = "1122334400000001000000000000000000000000000000000000000d"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Status == nil || *r.Status != 13 || r.StatusName != "MNT3ERR_ACCES" {
		t.Errorf("status = %v/%q, want 13/MNT3ERR_ACCES", r.Status, r.StatusName)
	}
	if r.FileHandle != "" {
		t.Error("denied mount must not carry a file handle")
	}
}

func TestDecodeReplyNotMount(t *testing.T) {
	// Accepted reply whose first word is not a mountstat3 code -> raw.
	const v = "11223344000000010000000000000000000000000000000000abcdef12"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Status != nil {
		t.Error("non-mountstat3 first word must not be typed as a MOUNT status")
	}
	if r.BodyHex == "" {
		t.Error("expected raw body for unrecognised reply")
	}
}

func TestDecodeTruncated(t *testing.T) {
	if _, err := Decode("112233"); err == nil {
		t.Fatal("expected error on short input")
	}
}
