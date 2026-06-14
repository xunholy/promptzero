// Package elftriage triages an ELF binary for Linux / IoT malware indicators.
//
// ELF is the executable format of Linux and the embedded / IoT world — routers,
// IP cameras, NAS boxes, and the Mirai-class botnets that infest them, plus
// Linux backdoors and droppers. After the delivery formats (email / .lnk / PDF)
// the payload is an ELF, and the analyst question is "what is this binary and
// does it look hostile?". This parses the ELF with the Go stdlib (debug/elf) and
// layers the triage: the class / endianness / type / CPU architecture (IoT
// malware is cross-compiled for MIPS / ARM / etc.), the entry point, the dynamic
// linker (or static), whether it is stripped, the NEEDED shared libraries and
// RPATH / RUNPATH, the imported symbols with the suspicious libc / syscall
// wrappers (system / execve / ptrace / socket …) flagged, and per-section
// Shannon entropy to spot a packed / encrypted section (UPX and friends).
//
// No confidently-wrong output: parsing uses stdlib debug/elf; fields absent from
// the binary are left empty, never guessed; the suspicious verdict is a labelled
// heuristic (a known dangerous import, a high-entropy executable section, or an
// RPATH/RUNPATH) — a clean result is not a guarantee of safety; section data is
// sampled under a byte cap for entropy; it never executes the binary.
//
// Wrap-vs-native: native — Go stdlib debug/elf + the analysis layer, no new
// go.mod dependency. Anchored to real gcc-built ELF binaries (see the test).
package elftriage

import (
	"bytes"
	"debug/elf"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
)

// entropySampleCap bounds how many bytes of a section are read for entropy.
const entropySampleCap = 256 << 10

// Section is one section's triage facts.
type Section struct {
	Name        string  `json:"name"`
	Type        string  `json:"type"`
	Size        uint64  `json:"size"`
	Executable  bool    `json:"executable,omitempty"`
	Entropy     float64 `json:"entropy,omitempty"`
	HighEntropy bool    `json:"high_entropy,omitempty"`
}

// Result is the ELF triage.
type Result struct {
	Format      string `json:"format"`
	Class       string `json:"class"`
	Endianness  string `json:"endianness"`
	Type        string `json:"type"`
	Machine     string `json:"machine"`
	EntryPoint  string `json:"entry_point"`
	Interpreter string `json:"interpreter,omitempty"`
	Static      bool   `json:"static"`
	Stripped    bool   `json:"stripped"`
	RunPath     string `json:"run_path,omitempty"`

	NeededLibraries   []string  `json:"needed_libraries,omitempty"`
	ImportedSymbols   []string  `json:"imported_symbols,omitempty"`
	SuspiciousSymbols []string  `json:"suspicious_symbols,omitempty"`
	Sections          []Section `json:"sections,omitempty"`

	Suspicious        bool     `json:"suspicious"`
	SuspiciousReasons []string `json:"suspicious_reasons,omitempty"`
	Note              string   `json:"note"`
}

// Decode triages an ELF byte stream. It never panics: the stdlib debug/elf
// parser slice-panics on some malformed inputs (a crafted section/dynamic table
// — and a hostile ELF is exactly this tool's input), so a recover converts any
// such panic into a graceful error rather than crashing the host.
func Decode(data []byte) (res *Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			res, err = nil, fmt.Errorf("elftriage: malformed ELF (recovered: %v)", r)
		}
	}()

	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("elftriage: not an ELF: %w", err)
	}
	defer f.Close()

	res = &Result{
		Format:     "elf",
		Class:      f.Class.String(),
		Endianness: endianName(f.Data),
		Type:       elfType(f.Type),
		Machine:    machineName(f.Machine),
		EntryPoint: fmt.Sprintf("0x%x", f.Entry),
	}

	// Interpreter / static.
	if interp := f.Section(".interp"); interp != nil {
		if b, err := interp.Data(); err == nil {
			res.Interpreter = strings.TrimRight(string(b), "\x00")
		}
	}
	res.Static = res.Interpreter == "" && f.Type != elf.ET_REL

	// Stripped: no .symtab (the dynamic table .dynsym is separate and remains).
	res.Stripped = f.Section(".symtab") == nil

	res.NeededLibraries, _ = f.ImportedLibraries()
	if rp := dynString(f, elf.DT_RUNPATH); rp != "" {
		res.RunPath = rp
	} else {
		res.RunPath = dynString(f, elf.DT_RPATH)
	}

	res.collectSymbols(f)
	res.collectSections(f)
	res.evaluate()
	return res, nil
}

// collectSymbols records the undefined (imported) dynamic symbols.
func (res *Result) collectSymbols(f *elf.File) {
	syms, err := f.DynamicSymbols()
	if err != nil {
		return
	}
	seen := map[string]bool{}
	for _, s := range syms {
		if s.Section != elf.SHN_UNDEF || s.Name == "" {
			continue
		}
		name := s.Name
		if i := strings.IndexByte(name, '@'); i >= 0 { // strip @GLIBC_x.y
			name = name[:i]
		}
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		res.ImportedSymbols = append(res.ImportedSymbols, name)
		if suspiciousSyms[name] {
			res.SuspiciousSymbols = append(res.SuspiciousSymbols, name)
		}
	}
	sort.Strings(res.ImportedSymbols)
	sort.Strings(res.SuspiciousSymbols)
}

// collectSections records section facts and per-section entropy.
func (res *Result) collectSections(f *elf.File) {
	for _, s := range f.Sections {
		if s.Type == elf.SHT_NULL {
			continue
		}
		sec := Section{
			Name:       s.Name,
			Type:       strings.TrimPrefix(s.Type.String(), "SHT_"),
			Size:       s.Size,
			Executable: s.Flags&elf.SHF_EXECINSTR != 0,
		}
		if s.Type == elf.SHT_PROGBITS && s.Size > 0 {
			if e, ok := sectionEntropy(s); ok {
				sec.Entropy = round2(e)
				sec.HighEntropy = e >= 7.0 && sec.Executable
			}
		}
		res.Sections = append(res.Sections, sec)
	}
}

// evaluate fills the suspicious verdict.
func (res *Result) evaluate() {
	var reasons []string
	if len(res.SuspiciousSymbols) > 0 {
		reasons = append(reasons, "dangerous imports: "+strings.Join(res.SuspiciousSymbols, ", "))
	}
	for _, s := range res.Sections {
		if s.HighEntropy {
			reasons = append(reasons, fmt.Sprintf("high-entropy executable section %q (entropy %.2f) — possibly packed", s.Name, s.Entropy))
		}
	}
	if res.RunPath != "" {
		reasons = append(reasons, "RPATH/RUNPATH set ("+res.RunPath+") — library-hijack surface")
	}
	if len(reasons) > 0 {
		res.Suspicious = true
		res.SuspiciousReasons = reasons
	}
	res.Note = noteFor(res)
}

func noteFor(res *Result) string {
	base := "Static analysis only — the binary was not executed. "
	if res.Suspicious {
		return base + "SUSPICIOUS: " + strings.Join(res.SuspiciousReasons, "; ") +
			". Review before trusting this ELF."
	}
	return base + "No strong malware indicator found — not a guarantee of safety (a stripped, statically-linked, " +
		"cross-architecture ELF is a common IoT-malware shape worth scrutiny regardless)."
}

// --- helpers --------------------------------------------------------------

// suspiciousSyms are libc / syscall wrappers commonly abused by Linux/IoT malware.
var suspiciousSyms = map[string]bool{ //nolint:gochecknoglobals
	"system": true, "popen": true, "execl": true, "execle": true, "execlp": true,
	"execv": true, "execve": true, "execvp": true, "execvpe": true, "fexecve": true,
	"posix_spawn": true, "fork": true, "vfork": true, "clone": true, "daemon": true,
	"setsid": true, "ptrace": true, "prctl": true, "mprotect": true, "dlopen": true,
	"dlsym": true, "socket": true, "connect": true, "bind": true, "listen": true,
	"accept": true, "recv": true, "send": true, "inet_addr": true, "gethostbyname": true,
	"getaddrinfo": true, "chmod": true, "unlink": true, "kill": true, "syscall": true,
}

func endianName(d elf.Data) string {
	switch d {
	case elf.ELFDATA2LSB:
		return "little-endian"
	case elf.ELFDATA2MSB:
		return "big-endian"
	default:
		return "unknown"
	}
}

func elfType(t elf.Type) string {
	switch t {
	case elf.ET_REL:
		return "REL (relocatable)"
	case elf.ET_EXEC:
		return "EXEC (executable)"
	case elf.ET_DYN:
		return "DYN (shared object / PIE)"
	case elf.ET_CORE:
		return "CORE"
	default:
		return t.String()
	}
}

// machineName maps the common architectures (IoT malware spans many) to a
// friendly name, falling back to the stdlib name.
func machineName(m elf.Machine) string {
	switch m {
	case elf.EM_X86_64:
		return "x86-64"
	case elf.EM_386:
		return "x86"
	case elf.EM_AARCH64:
		return "AArch64 (ARM64)"
	case elf.EM_ARM:
		return "ARM"
	case elf.EM_MIPS:
		return "MIPS"
	case elf.EM_MIPS_RS3_LE:
		return "MIPS-RS3 (little-endian)"
	case elf.EM_PPC:
		return "PowerPC"
	case elf.EM_PPC64:
		return "PowerPC64"
	case elf.EM_RISCV:
		return "RISC-V"
	case elf.EM_SPARC:
		return "SPARC"
	case elf.EM_SH:
		return "SuperH"
	case elf.EM_S390:
		return "S/390"
	default:
		return strings.TrimPrefix(m.String(), "EM_")
	}
}

func dynString(f *elf.File, tag elf.DynTag) string {
	vals, err := f.DynString(tag)
	if err != nil || len(vals) == 0 {
		return ""
	}
	return strings.Join(vals, ":")
}

// sectionEntropy computes the Shannon entropy of a section's data, sampled under
// a byte cap.
func sectionEntropy(s *elf.Section) (float64, bool) {
	r := s.Open()
	data, err := io.ReadAll(io.LimitReader(r, entropySampleCap))
	if err != nil || len(data) == 0 {
		return 0, false
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	n := float64(len(data))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h, true
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }
