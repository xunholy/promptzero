// Package pickle disassembles a Python pickle byte stream into its opcode
// sequence and flags the code-execution opcodes that make a pickle dangerous —
// without ever unpickling it.
//
// Python pickle is a stack-machine bytecode (PEP 307 / CPython Lib/pickle.py),
// and a malicious pickle is a top supply-chain RCE vector: PyTorch / TensorFlow
// / scikit-learn / HuggingFace model files, joblib caches, and Redis values are
// all pickles, and merely *loading* one with pickle.load runs whatever the
// GLOBAL + REDUCE opcodes encode (the classic gadget is GLOBAL os system /
// STACK_GLOBAL + REDUCE). This walks the opcode stream — the safe operation that
// pickletools.dis performs, never pickle.load — and reports the protocol
// version, every opcode, the imported callables (module.name from GLOBAL /
// STACK_GLOBAL / INST), and whether the pickle can execute code (an import
// opcode plus an invocation opcode), with the known-dangerous imports
// (os / subprocess / builtins.eval / …) called out.
//
// No confidently-wrong output: the opcode and argument encodings are transcribed
// verbatim from CPython's pickletools.opcodes; an unknown opcode stops the walk
// (the argument length is then unknown) and is reported as such rather than
// guessed; every length field is bounds-checked against the remaining input; and
// the stream is never executed. STACK_GLOBAL's target is resolved heuristically
// from the two preceding string pushes (how the pickler emits it) and labelled
// as such.
//
// Wrap-vs-native: native — a byte-cursor walk of the documented opcode set;
// stdlib only, no new go.mod dependency. Verified opcode-for-opcode against
// Python's stdlib pickletools (see the package test).
package pickle

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

// argKind identifies how an opcode's inline argument is encoded.
type argKind int

const (
	argNone argKind = iota
	argUint1
	argUint2
	argUint4
	argUint8
	argInt4
	argLong1                // 1-byte length + LE two's-complement bytes
	argLong4                // 4-byte length + LE two's-complement bytes
	argFloat8               // 8-byte big-endian double
	argFloatNL              // newline-terminated float text
	argDecimalNL            // newline-terminated decimal int text
	argDecimalNLLong        // newline-terminated decimal long (optional trailing L)
	argStringNL             // newline-terminated quoted string
	argStringNLNoEscape     // newline-terminated, unquoted
	argStringNLNoEscapePair // two newline-terminated unquoted (module, name)
	argString1              // 1-byte length + bytes
	argString4              // 4-byte length + bytes
	argBytes1               // 1-byte length + bytes
	argBytes4               // 4-byte length + bytes
	argBytes8               // 8-byte length + bytes
	argByteArray8           // 8-byte length + bytes
	argUnicodeNL            // newline-terminated unicode
	argUnicode1             // 1-byte length + UTF-8
	argUnicode4             // 4-byte length + UTF-8
	argUnicode8             // 8-byte length + UTF-8
)

type opcode struct {
	name string
	arg  argKind
}

// opcodes maps each pickle opcode byte to its name + argument kind, transcribed
// from CPython pickletools.opcodes (68 opcodes, protocols 0–5).
var opcodes = map[byte]opcode{ //nolint:gochecknoglobals
	'I': {"INT", argDecimalNL}, 'J': {"BININT", argInt4}, 'K': {"BININT1", argUint1},
	'M': {"BININT2", argUint2}, 'L': {"LONG", argDecimalNLLong}, 0x8a: {"LONG1", argLong1},
	0x8b: {"LONG4", argLong4}, 'S': {"STRING", argStringNL}, 'T': {"BINSTRING", argString4},
	'U': {"SHORT_BINSTRING", argString1}, 'B': {"BINBYTES", argBytes4}, 'C': {"SHORT_BINBYTES", argBytes1},
	0x8e: {"BINBYTES8", argBytes8}, 0x96: {"BYTEARRAY8", argByteArray8}, 0x97: {"NEXT_BUFFER", argNone},
	0x98: {"READONLY_BUFFER", argNone}, 'N': {"NONE", argNone}, 0x88: {"NEWTRUE", argNone},
	0x89: {"NEWFALSE", argNone}, 'V': {"UNICODE", argUnicodeNL}, 0x8c: {"SHORT_BINUNICODE", argUnicode1},
	'X': {"BINUNICODE", argUnicode4}, 0x8d: {"BINUNICODE8", argUnicode8}, 'F': {"FLOAT", argFloatNL},
	'G': {"BINFLOAT", argFloat8}, ']': {"EMPTY_LIST", argNone}, 'a': {"APPEND", argNone},
	'e': {"APPENDS", argNone}, 'l': {"LIST", argNone}, ')': {"EMPTY_TUPLE", argNone},
	't': {"TUPLE", argNone}, 0x85: {"TUPLE1", argNone}, 0x86: {"TUPLE2", argNone},
	0x87: {"TUPLE3", argNone}, '}': {"EMPTY_DICT", argNone}, 'd': {"DICT", argNone},
	's': {"SETITEM", argNone}, 'u': {"SETITEMS", argNone}, 0x8f: {"EMPTY_SET", argNone},
	0x90: {"ADDITEMS", argNone}, 0x91: {"FROZENSET", argNone}, '0': {"POP", argNone},
	'2': {"DUP", argNone}, '(': {"MARK", argNone}, '1': {"POP_MARK", argNone},
	'g': {"GET", argDecimalNL}, 'h': {"BINGET", argUint1}, 'j': {"LONG_BINGET", argUint4},
	'p': {"PUT", argDecimalNL}, 'q': {"BINPUT", argUint1}, 'r': {"LONG_BINPUT", argUint4},
	0x94: {"MEMOIZE", argNone}, 0x82: {"EXT1", argUint1}, 0x83: {"EXT2", argUint2},
	0x84: {"EXT4", argInt4}, 'c': {"GLOBAL", argStringNLNoEscapePair}, 0x93: {"STACK_GLOBAL", argNone},
	'R': {"REDUCE", argNone}, 'b': {"BUILD", argNone}, 'i': {"INST", argStringNLNoEscapePair},
	'o': {"OBJ", argNone}, 0x81: {"NEWOBJ", argNone}, 0x92: {"NEWOBJ_EX", argNone},
	0x80: {"PROTO", argUint1}, '.': {"STOP", argNone}, 0x95: {"FRAME", argUint8},
	'P': {"PERSID", argStringNLNoEscape}, 'Q': {"BINPERSID", argNone},
}

// Op is one disassembled opcode.
type Op struct {
	Pos    int    `json:"pos"`
	Opcode string `json:"opcode"`
	Arg    string `json:"arg,omitempty"`
}

// Result is the disassembled pickle.
type Result struct {
	Format   string `json:"format"`
	Protocol int    `json:"protocol"`
	Opcodes  []Op   `json:"opcodes"`
	OpCount  int    `json:"opcode_count"`
	// Imports are the module.name callables referenced by GLOBAL / STACK_GLOBAL /
	// INST (STACK_GLOBAL resolved heuristically — see DangerousImports note).
	Imports []string `json:"imports,omitempty"`
	// DangerousImports is the subset of Imports matching a known RCE sink.
	DangerousImports []string `json:"dangerous_imports,omitempty"`
	// CodeExecOpcodes are the invocation opcodes present (REDUCE / OBJ / NEWOBJ /
	// NEWOBJ_EX / INST / BUILD) — a pickle carrying these runs code on load.
	CodeExecOpcodes []string `json:"code_exec_opcodes,omitempty"`
	// ExecutesCode is true when both an import and an invocation opcode are present.
	ExecutesCode bool `json:"executes_code"`
	// Truncated is true when the walk stopped before STOP (unknown opcode or a
	// short/over-long argument).
	Truncated bool   `json:"truncated,omitempty"`
	Note      string `json:"note"`
}

// maxOpcodes caps the disassembly listing; the counts/flags still reflect the
// full walk.
const maxOpcodes = 5000

// Decode disassembles a pickle byte stream.
func Decode(data []byte) (*Result, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("pickle: empty input")
	}
	res := &Result{Format: "python-pickle", Protocol: 0}
	c := &cursor{b: data}

	importsSet := map[string]bool{}
	codeExecSet := map[string]bool{}
	var recentStrings []string // for STACK_GLOBAL resolution
	hasImportOp := false

	for c.pos < len(c.b) {
		pos := c.pos
		code := c.b[c.pos]
		c.pos++
		op, ok := opcodes[code]
		if !ok {
			res.Truncated = true
			res.Opcodes = append(res.Opcodes, Op{Pos: pos, Opcode: fmt.Sprintf("UNKNOWN(0x%02x)", code)})
			break
		}
		arg, sval, err := c.readArg(op.arg)
		if err != nil {
			res.Truncated = true
			res.Opcodes = append(res.Opcodes, Op{Pos: pos, Opcode: op.name, Arg: "<" + err.Error() + ">"})
			break
		}
		res.OpCount++
		if len(res.Opcodes) < maxOpcodes {
			res.Opcodes = append(res.Opcodes, Op{Pos: pos, Opcode: op.name, Arg: arg})
		}

		switch op.name {
		case "PROTO":
			if len(sval) > 0 {
				res.Protocol = int(sval[0])
			}
		case "GLOBAL", "INST":
			hasImportOp = true
			if mn := strings.Replace(strings.TrimRight(arg, "\n"), "\n", ".", 1); mn != "" {
				importsSet[mn] = true
			}
		case "STACK_GLOBAL":
			hasImportOp = true
			if n := len(recentStrings); n >= 2 {
				importsSet[recentStrings[n-2]+"."+recentStrings[n-1]] = true
			}
		case "REDUCE", "OBJ", "NEWOBJ", "NEWOBJ_EX", "BUILD":
			codeExecSet[op.name] = true
		}
		if isStringPush(op.name) {
			recentStrings = append(recentStrings, string(sval))
		}
		if op.name == "STOP" {
			break
		}
	}

	res.Imports = sortedKeys(importsSet)
	for _, imp := range res.Imports {
		if isDangerousImport(imp) {
			res.DangerousImports = append(res.DangerousImports, imp)
		}
	}
	res.CodeExecOpcodes = sortedKeys(codeExecSet)
	res.ExecutesCode = hasImportOp && len(codeExecSet) > 0
	res.Note = noteFor(res)
	return res, nil
}

// isStringPush reports whether an opcode pushes a string literal (tracked for
// STACK_GLOBAL resolution).
func isStringPush(name string) bool {
	switch name {
	case "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
		"SHORT_BINSTRING", "BINSTRING", "STRING":
		return true
	}
	return false
}

// dangerousModules / dangerousNames flag a GLOBAL/STACK_GLOBAL import as a likely
// RCE sink. posix/nt are the os.system targets on Linux/Windows.
var dangerousModules = map[string]bool{ //nolint:gochecknoglobals
	"os": true, "posix": true, "nt": true, "subprocess": true, "sys": true,
	"builtins": true, "__builtin__": true, "pty": true, "socket": true,
	"shutil": true, "ctypes": true, "importlib": true, "runpy": true,
	"multiprocessing": true, "commands": true, "platform": true, "pickle": true,
}

var dangerousNames = map[string]bool{ //nolint:gochecknoglobals
	"system": true, "popen": true, "exec": true, "eval": true, "execfile": true,
	"compile": true, "__import__": true, "spawn": true, "spawnl": true, "spawnv": true,
	"call": true, "check_call": true, "check_output": true, "run": true, "Popen": true,
	"getoutput": true, "getstatusoutput": true, "load": true, "loads": true,
}

func isDangerousImport(mn string) bool {
	parts := strings.SplitN(mn, ".", 2)
	if dangerousModules[parts[0]] {
		return true
	}
	if len(parts) == 2 && dangerousNames[parts[1]] {
		return true
	}
	return false
}

func noteFor(res *Result) string {
	switch {
	case len(res.DangerousImports) > 0:
		return "DANGEROUS: this pickle imports a known code-execution sink and runs code when loaded with " +
			"pickle.load — do NOT unpickle from an untrusted source. Disassembly only; the stream was not executed."
	case res.ExecutesCode:
		return "This pickle executes code on load (an import opcode plus an invocation opcode are present); " +
			"the imported callables may still be benign — review them. Disassembly only; not executed."
	default:
		return "No code-execution opcodes found — this appears to be a pure-data pickle. Disassembly only; " +
			"absence of these opcodes is not a guarantee of safety. Not executed."
	}
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// --- cursor ---------------------------------------------------------------

type cursor struct {
	b   []byte
	pos int
}

func (c *cursor) remaining() int { return len(c.b) - c.pos }

func (c *cursor) take(n int) ([]byte, error) {
	if n < 0 || n > c.remaining() {
		return nil, fmt.Errorf("truncated: want %d bytes, %d left", n, c.remaining())
	}
	b := c.b[c.pos : c.pos+n]
	c.pos += n
	return b, nil
}

// line reads up to and including the next '\n', returning the content without it.
func (c *cursor) line() ([]byte, error) {
	for i := c.pos; i < len(c.b); i++ {
		if c.b[i] == '\n' {
			s := c.b[c.pos:i]
			c.pos = i + 1
			return s, nil
		}
	}
	return nil, fmt.Errorf("truncated: unterminated line")
}

// readArg reads an opcode's argument, returning a display string and, for
// length-prefixed/string args, the raw value bytes (used for STACK_GLOBAL).
func (c *cursor) readArg(kind argKind) (string, []byte, error) {
	switch kind {
	case argNone:
		return "", nil, nil
	case argUint1:
		b, err := c.take(1)
		if err != nil {
			return "", nil, err
		}
		return fmt.Sprintf("%d", b[0]), b, nil
	case argUint2:
		b, err := c.take(2)
		if err != nil {
			return "", nil, err
		}
		return fmt.Sprintf("%d", binary.LittleEndian.Uint16(b)), b, nil
	case argUint4:
		b, err := c.take(4)
		if err != nil {
			return "", nil, err
		}
		return fmt.Sprintf("%d", binary.LittleEndian.Uint32(b)), b, nil
	case argUint8:
		b, err := c.take(8)
		if err != nil {
			return "", nil, err
		}
		return fmt.Sprintf("%d", binary.LittleEndian.Uint64(b)), b, nil
	case argInt4:
		b, err := c.take(4)
		if err != nil {
			return "", nil, err
		}
		return fmt.Sprintf("%d", int32(binary.LittleEndian.Uint32(b))), b, nil
	case argFloat8:
		b, err := c.take(8)
		if err != nil {
			return "", nil, err
		}
		return fmt.Sprintf("0x%x", b), b, nil
	case argLong1:
		return c.lengthPrefixed(1, "long")
	case argLong4:
		return c.lengthPrefixed(4, "long")
	case argString1, argBytes1, argUnicode1:
		return c.lengthPrefixed(1, "")
	case argString4, argBytes4, argUnicode4:
		return c.lengthPrefixed(4, "")
	case argBytes8, argByteArray8, argUnicode8:
		return c.lengthPrefixed(8, "")
	case argDecimalNL, argDecimalNLLong, argFloatNL, argStringNL, argStringNLNoEscape, argUnicodeNL:
		s, err := c.line()
		if err != nil {
			return "", nil, err
		}
		return string(s), s, nil
	case argStringNLNoEscapePair:
		mod, err := c.line()
		if err != nil {
			return "", nil, err
		}
		name, err := c.line()
		if err != nil {
			return "", nil, err
		}
		return string(mod) + "\n" + string(name), append(append([]byte{}, mod...), name...), nil
	default:
		return "", nil, fmt.Errorf("unhandled arg kind")
	}
}

// lengthPrefixed reads an n-byte little-endian length then that many bytes.
func (c *cursor) lengthPrefixed(lenBytes int, kind string) (string, []byte, error) {
	lb, err := c.take(lenBytes)
	if err != nil {
		return "", nil, err
	}
	var n uint64
	for i := lenBytes - 1; i >= 0; i-- {
		n = n<<8 | uint64(lb[i])
	}
	body, err := c.take(int(n))
	if err != nil {
		return "", nil, err
	}
	if kind == "long" {
		return fmt.Sprintf("<%d-byte int>", n), body, nil
	}
	const show = 64
	disp := body
	suffix := ""
	if len(disp) > show {
		disp = disp[:show]
		suffix = "…"
	}
	return string(disp) + suffix, body, nil
}
