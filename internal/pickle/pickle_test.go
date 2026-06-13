package pickle

import (
	"encoding/base64"
	"strings"
	"testing"
)

// Vectors and their opcode sequences are produced by Python's stdlib
// pickletools.genops — the canonical disassembler this package mirrors.
//
//	pickle.dumps({"user":"admin","id":7,"ok":True}, 4)   → benignDict
//	pickle.dumps([1,2,"three"], 0)                        → benignListP0
//	pickle.dumps(Evil(), 4)  # __reduce__ → (os.system,("id",))  → maliciousP4
//	pickle.dumps(Evil(), 2)                               → maliciousP2
const (
	benignDict   = "gASVIQAAAAAAAAB9lCiMBHVzZXKUjAVhZG1pbpSMAmlklEsHjAJva5SIdS4="
	benignListP0 = "KGxwMApJMQphSTIKYVZ0aHJlZQpwMQphLg=="
	maliciousP4  = "gASVHQAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAJpZJSFlFKULg=="
	maliciousP2  = "gAJjcG9zaXgKc3lzdGVtCnEAWAIAAABpZHEBhXECUnEDLg=="
)

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	return b
}

func opSeq(r *Result) string {
	names := make([]string, len(r.Opcodes))
	for i, o := range r.Opcodes {
		names[i] = o.Opcode
	}
	return strings.Join(names, ",")
}

func TestDecode_OpcodeSequences(t *testing.T) {
	cases := []struct {
		name, b64, ops string
		proto          int
	}{
		{"benign_dict", benignDict,
			"PROTO,FRAME,EMPTY_DICT,MEMOIZE,MARK,SHORT_BINUNICODE,MEMOIZE,SHORT_BINUNICODE,MEMOIZE," +
				"SHORT_BINUNICODE,MEMOIZE,BININT1,SHORT_BINUNICODE,MEMOIZE,NEWTRUE,SETITEMS,STOP", 4},
		{"benign_list_p0", benignListP0,
			"MARK,LIST,PUT,INT,APPEND,INT,APPEND,UNICODE,PUT,APPEND,STOP", 0},
		{"malicious_p4", maliciousP4,
			"PROTO,FRAME,SHORT_BINUNICODE,MEMOIZE,SHORT_BINUNICODE,MEMOIZE,STACK_GLOBAL,MEMOIZE," +
				"SHORT_BINUNICODE,MEMOIZE,TUPLE1,MEMOIZE,REDUCE,MEMOIZE,STOP", 4},
		{"malicious_p2", maliciousP2,
			"PROTO,GLOBAL,BINPUT,BINUNICODE,BINPUT,TUPLE1,BINPUT,REDUCE,BINPUT,STOP", 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := Decode(mustB64(t, c.b64))
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if got := opSeq(r); got != c.ops {
				t.Errorf("opcodes =\n %s\nwant\n %s", got, c.ops)
			}
			if r.Protocol != c.proto {
				t.Errorf("protocol = %d, want %d", r.Protocol, c.proto)
			}
			if r.Truncated {
				t.Errorf("unexpected truncation")
			}
		})
	}
}

func TestDecode_MaliciousFlagged(t *testing.T) {
	for _, b64 := range []string{maliciousP4, maliciousP2} {
		r, err := Decode(mustB64(t, b64))
		if err != nil {
			t.Fatalf("Decode: %v", err)
		}
		if len(r.DangerousImports) != 1 || r.DangerousImports[0] != "posix.system" {
			t.Errorf("dangerous_imports = %v, want [posix.system]", r.DangerousImports)
		}
		if !r.ExecutesCode {
			t.Errorf("ExecutesCode = false, want true")
		}
		if !contains(r.CodeExecOpcodes, "REDUCE") {
			t.Errorf("code_exec_opcodes = %v, want REDUCE", r.CodeExecOpcodes)
		}
		if !strings.Contains(r.Note, "DANGEROUS") {
			t.Errorf("note should warn DANGEROUS: %q", r.Note)
		}
	}
}

func TestDecode_BenignClean(t *testing.T) {
	for _, b64 := range []string{benignDict, benignListP0} {
		r, err := Decode(mustB64(t, b64))
		if err != nil {
			t.Fatalf("Decode: %v", err)
		}
		if len(r.DangerousImports) != 0 || r.ExecutesCode || len(r.CodeExecOpcodes) != 0 {
			t.Errorf("benign pickle flagged: danger=%v exec=%v ops=%v", r.DangerousImports, r.ExecutesCode, r.CodeExecOpcodes)
		}
		if len(r.Imports) != 0 {
			t.Errorf("benign pickle has imports: %v", r.Imports)
		}
	}
}

func TestDecode_Errors(t *testing.T) {
	if _, err := Decode(nil); err == nil {
		t.Error("empty input should error")
	}
}

func TestDecode_UnknownOpcodeTruncates(t *testing.T) {
	// 0x80 0x04 (PROTO 4) then 0xFF — not a valid opcode.
	r, err := Decode([]byte{0x80, 0x04, 0xFF})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.Truncated {
		t.Errorf("expected Truncated on an unknown opcode")
	}
	last := r.Opcodes[len(r.Opcodes)-1]
	if !strings.HasPrefix(last.Opcode, "UNKNOWN") {
		t.Errorf("last opcode = %q, want UNKNOWN(...)", last.Opcode)
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func FuzzDecode(f *testing.F) {
	for _, s := range []string{benignDict, benignListP0, maliciousP4, maliciousP2} {
		if b, err := base64.StdEncoding.DecodeString(s); err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte{0x80, 0x05})
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, in []byte) {
		_, _ = Decode(in)
	})
}
