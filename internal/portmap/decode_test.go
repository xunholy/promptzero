// SPDX-License-Identifier: AGPL-3.0-or-later

package portmap

import "testing"

// Vectors produced with scapy's ONC RPC + portmap layers
// (scapy.contrib.oncrpc / portmap) and verified field-for-field.

func TestDecodeGetportCall(t *testing.T) {
	// RPC(xid=0x11223344, CALL)/RPC_Call(prog=100000, v2, proc=3 GETPORT,
	//   null auth)/GETPORT_Call(prog=100003 nfs, vers=3, prot=17 udp, port=0)
	const v = "112233440000000000000002000186a0000000020000000300000000000000000000000000000000000186a3000000030000001100000000"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MessageName != "CALL" {
		t.Fatalf("mtype = %q", r.MessageName)
	}
	if r.Program == nil || *r.Program != 100000 || r.ProgramName != "portmapper/rpcbind" {
		t.Errorf("program = %v/%q", r.Program, r.ProgramName)
	}
	if r.ProcName != "GETPORT" {
		t.Errorf("proc = %q", r.ProcName)
	}
	if r.Query == nil || r.Query.Program != 100003 || r.Query.ProgramName != "nfs" || r.Query.ProtocolStr != "udp" {
		t.Errorf("query = %+v", r.Query)
	}
}

func TestDecodeGetportReply(t *testing.T) {
	// RPC(REPLY, accepted, success)/GETPORT_Reply(port=2049)
	const v = "11223344000000010000000000000000000000000000000000000801"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MessageName != "REPLY" || r.AcceptName != "SUCCESS" {
		t.Fatalf("reply = %q/%q", r.MessageName, r.AcceptName)
	}
	if r.Port == nil || *r.Port != 2049 {
		t.Errorf("port = %v, want 2049", r.Port)
	}
}

func TestDecodeDumpReply(t *testing.T) {
	// DUMP reply listing portmapper/111, nfs/2049, mountd/635.
	const v = "aabbccdd000000010000000000000000000000000000000000000001" +
		"000186a000000002000000110000006f00000001" +
		"000186a300000003000000110000080100000001" +
		"000186a500000003000000060000027b00000000"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.Mappings) != 3 {
		t.Fatalf("mappings = %d, want 3", len(r.Mappings))
	}
	want := []struct {
		prog uint32
		name string
		prot string
		port uint32
	}{
		{100000, "portmapper/rpcbind", "udp", 111},
		{100003, "nfs", "udp", 2049},
		{100005, "mountd", "tcp", 635},
	}
	for i, w := range want {
		m := r.Mappings[i]
		if m.Program != w.prog || m.ProgramName != w.name || m.ProtocolStr != w.prot || m.Port != w.port {
			t.Errorf("mapping %d = %+v, want %+v", i, m, w)
		}
	}
}

func TestDecodeEmptyDumpIsAmbiguousWithPortZero(t *testing.T) {
	// A 4-byte all-zero accepted body is byte-identical as a GETPORT port-0
	// (service not registered) and an empty DUMP reply; the decoder reports
	// the common GETPORT interpretation (port 0) with a note on the ambiguity.
	const v = "00000001000000010000000000000000000000000000000000000000"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Port == nil || *r.Port != 0 {
		t.Errorf("expected port 0, got %v", r.Port)
	}
}

func TestDecodeDeniedReply(t *testing.T) {
	const v = "11223344000000010000000100000001" // MSG_DENIED
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.ReplyName != "MSG_DENIED" {
		t.Errorf("reply stat = %q", r.ReplyName)
	}
}

func TestDecodeRejectsBadType(t *testing.T) {
	if _, err := Decode("00000000000000020000"); err == nil {
		t.Fatal("expected rejection of message type 2")
	}
}

func TestDecodeTruncated(t *testing.T) {
	if _, err := Decode("112233"); err == nil {
		t.Fatal("expected error on short input")
	}
}
