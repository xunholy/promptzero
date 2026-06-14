// Package machotriage triages a Mach-O binary for macOS / iOS malware
// indicators.
//
// Mach-O is the executable format of macOS and iOS (and their malware) — the
// third member of the executable-payload triad alongside ELF (Linux / IoT) and
// PE (Windows). After the delivery formats (email / .lnk / PDF) the payload on
// an Apple host is a Mach-O, and the analyst question is "what is this binary
// and does it look hostile?". This parses the Mach-O with the Go stdlib
// (debug/macho) and layers the triage: the bitness / CPU architecture (x86-64 /
// arm64 — Apple-Silicon malware), the file type (EXECUTE / DYLIB / BUNDLE — a
// dlopen-loaded bundle is a classic injection vector), the security-relevant
// header flags (PIE; MH_ALLOW_STACK_EXECUTION — a W^X red flag), whether the
// binary is code-signed and whether a segment is encrypted (FairPlay / packer),
// the imported dylibs / frameworks and the LC_RPATH search paths (dylib-hijack
// surface), the imported symbols with the suspicious ones flagged (process
// injection — task_for_pid / mach_vm_write / NSCreateObjectFileImageFromMemory;
// anti-debug — ptrace(PT_DENY_ATTACH) / sysctl / csops; exec — system / popen /
// posix_spawn; keylogging — CGEventTapCreate / AXIsProcessTrusted; keychain
// theft, ransomware-crypto, screen capture), and per-section Shannon entropy to
// spot a packed section. Universal (fat) binaries are triaged per-architecture.
//
// No confidently-wrong output: parsing uses stdlib debug/macho; fields absent
// from the binary are left empty, never guessed; the suspicious verdict is a
// labelled heuristic (a known-abused import, an RPATH, a high-entropy
// executable section, an encrypted segment, or a stack-execution flag) — a
// clean result is not a guarantee of safety, and a flagged import is not proof
// of malice (many flagged APIs appear in benign software); section data is
// sampled under a byte cap for entropy; it never executes the binary.
//
// Wrap-vs-native: native — Go stdlib debug/macho + the analysis layer, no new
// go.mod dependency. Anchored to real clang/gcc-built Mach-O binaries (see the
// test): the Go toolchain's own debug/macho corpus, thin and fat.
package machotriage

import (
	"bytes"
	"debug/macho"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
)

// entropySampleCap bounds how many bytes of a section are read for entropy.
const entropySampleCap = 256 << 10

// Mach-O header flags (mach-o/loader.h) — debug/macho does not export these.
const (
	mhTwoLevel            = 0x80
	mhAllowStackExecution = 0x20000
	mhPIE                 = 0x200000
	mhNoHeapExecution     = 0x1000000
	mhRootSafe            = 0x40000
)

// Load-command codes not given a typed accessor by debug/macho.
const (
	lcCodeSignature    = 0x1d
	lcEncryptionInfo   = 0x21
	lcEncryptionInfo64 = 0x2c
)

// Mach-O section attribute flags (low byte is the section type; high bits are
// attributes).
const (
	sAttrPureInstructions = 0x80000000
	sAttrSomeInstructions = 0x00000400
	sectionTypeMask       = 0x000000ff
	sZerofill             = 0x1
	sGBZerofill           = 0xc
	sThreadLocalZerofill  = 0x11
)

// Section is one section's triage facts.
type Section struct {
	Segment     string  `json:"segment"`
	Name        string  `json:"name"`
	Size        uint64  `json:"size"`
	Executable  bool    `json:"executable,omitempty"`
	Entropy     float64 `json:"entropy,omitempty"`
	HighEntropy bool    `json:"high_entropy,omitempty"`
}

// Arch is the triage of a single Mach-O image (a thin binary, or one slice of a
// universal binary).
type Arch struct {
	Bits        int      `json:"bits"`
	CPU         string   `json:"cpu"`
	Type        string   `json:"type"`
	PIE         bool     `json:"pie"`
	CodeSigned  bool     `json:"code_signed"`
	Encrypted   bool     `json:"encrypted,omitempty"`
	HeaderFlags []string `json:"header_flags,omitempty"`

	ImportedDylibs    []string  `json:"imported_dylibs,omitempty"`
	RPaths            []string  `json:"rpaths,omitempty"`
	ImportedSymbols   []string  `json:"imported_symbols,omitempty"`
	SuspiciousSymbols []string  `json:"suspicious_symbols,omitempty"`
	Sections          []Section `json:"sections,omitempty"`

	Suspicious        bool     `json:"suspicious"`
	SuspiciousReasons []string `json:"suspicious_reasons,omitempty"`
}

// Result is the Mach-O triage; Architectures holds one entry for a thin binary
// or N for a universal (fat) binary.
type Result struct {
	Format        string  `json:"format"`
	Universal     bool    `json:"universal,omitempty"`
	Architectures []*Arch `json:"architectures"`

	Suspicious        bool     `json:"suspicious"`
	SuspiciousReasons []string `json:"suspicious_reasons,omitempty"`
	Note              string   `json:"note"`
}

// Decode triages a Mach-O byte stream (thin or universal). It never panics: a
// recover converts any debug/macho parser panic on a hostile / corrupt binary
// into a graceful error rather than crashing the host.
func Decode(data []byte) (res *Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			res, err = nil, fmt.Errorf("machotriage: malformed Mach-O (recovered: %v)", r)
		}
	}()

	res = &Result{Format: "macho"}

	if fat, ferr := macho.NewFatFile(bytes.NewReader(data)); ferr == nil {
		defer fat.Close()
		res.Universal = true
		for i := range fat.Arches {
			res.Architectures = append(res.Architectures, triageImage(fat.Arches[i].File))
		}
	} else {
		f, oerr := macho.NewFile(bytes.NewReader(data))
		if oerr != nil {
			return nil, fmt.Errorf("machotriage: not a Mach-O: %w", oerr)
		}
		defer f.Close()
		res.Architectures = append(res.Architectures, triageImage(f))
	}

	res.aggregate()
	return res, nil
}

// triageImage triages a single Mach-O image.
func triageImage(f *macho.File) *Arch {
	a := &Arch{
		Bits: machoBits(f.Magic),
		CPU:  cpuName(f.Cpu),
		Type: typeName(f.Type),
		PIE:  f.Flags&mhPIE != 0,
	}
	a.HeaderFlags = headerFlags(f.Flags)
	a.scanLoads(f)
	a.collectSymbols(f)
	a.collectSections(f)
	a.evaluate()
	return a
}

// scanLoads records imported dylibs, LC_RPATH paths, code-signature presence,
// and an encrypted segment, walking the load commands by raw cmd code.
func (a *Arch) scanLoads(f *macho.File) {
	a.ImportedDylibs, _ = f.ImportedLibraries()
	sort.Strings(a.ImportedDylibs)
	for _, l := range f.Loads {
		if rp, ok := l.(*macho.Rpath); ok {
			a.RPaths = append(a.RPaths, rp.Path)
		}
		raw := l.Raw()
		if len(raw) < 4 {
			continue
		}
		switch f.ByteOrder.Uint32(raw[0:4]) {
		case lcCodeSignature:
			a.CodeSigned = true
		case lcEncryptionInfo, lcEncryptionInfo64:
			// struct: cmd, cmdsize, cryptoff, cryptsize, cryptid — cryptid != 0
			// means the segment is actually encrypted (a 0 placeholder is not).
			if len(raw) >= 20 && f.ByteOrder.Uint32(raw[16:20]) != 0 {
				a.Encrypted = true
			}
		}
	}
}

// collectSymbols records the imported (undefined) symbols, flagging the
// macOS-malware-relevant ones. Mach-O C symbols carry a leading underscore,
// stripped before the suspicious lookup.
func (a *Arch) collectSymbols(f *macho.File) {
	syms, err := f.ImportedSymbols()
	if err != nil {
		return
	}
	seen := map[string]bool{}
	for _, s := range syms {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		a.ImportedSymbols = append(a.ImportedSymbols, s)
		if suspiciousAPIs[strings.ToLower(strings.TrimPrefix(s, "_"))] {
			a.SuspiciousSymbols = append(a.SuspiciousSymbols, s)
		}
	}
	sort.Strings(a.ImportedSymbols)
	sort.Strings(a.SuspiciousSymbols)
}

// collectSections records section facts and per-section entropy (skipping
// zero-fill sections, which have no file data).
func (a *Arch) collectSections(f *macho.File) {
	for _, s := range f.Sections {
		exec := s.Flags&sAttrPureInstructions != 0 || s.Flags&sAttrSomeInstructions != 0
		sec := Section{
			Segment:    s.Seg,
			Name:       s.Name,
			Size:       s.Size,
			Executable: exec,
		}
		if st := s.Flags & sectionTypeMask; s.Size > 0 && st != sZerofill && st != sGBZerofill && st != sThreadLocalZerofill {
			if e, ok := sectionEntropy(s); ok {
				sec.Entropy = round2(e)
				sec.HighEntropy = e >= 7.0 && exec
			}
		}
		a.Sections = append(a.Sections, sec)
	}
}

// evaluate fills this image's suspicious verdict.
func (a *Arch) evaluate() {
	var reasons []string
	if len(a.SuspiciousSymbols) > 0 {
		reasons = append(reasons, "abused APIs: "+strings.Join(a.SuspiciousSymbols, ", "))
	}
	for _, r := range a.RPaths {
		reasons = append(reasons, fmt.Sprintf("LC_RPATH %q — dylib-hijack surface", r))
	}
	if a.Encrypted {
		reasons = append(reasons, "encrypted segment (LC_ENCRYPTION_INFO, cryptid set) — packed / FairPlay")
	}
	if a.containsFlag(mhAllowStackExecution) {
		reasons = append(reasons, "MH_ALLOW_STACK_EXECUTION — executable stack (W^X violation)")
	}
	for _, s := range a.Sections {
		if s.HighEntropy {
			reasons = append(reasons, fmt.Sprintf("high-entropy executable section %s,%s (entropy %.2f) — possibly packed", s.Segment, s.Name, s.Entropy))
		}
	}
	if len(reasons) > 0 {
		a.Suspicious = true
		a.SuspiciousReasons = reasons
	}
}

func (a *Arch) containsFlag(name uint32) bool {
	for _, f := range a.HeaderFlags {
		if f == flagName(name) {
			return true
		}
	}
	return false
}

// aggregate rolls the per-architecture verdicts up to the top level.
func (res *Result) aggregate() {
	for i, a := range res.Architectures {
		if !a.Suspicious {
			continue
		}
		res.Suspicious = true
		for _, r := range a.SuspiciousReasons {
			if res.Universal {
				res.SuspiciousReasons = append(res.SuspiciousReasons, fmt.Sprintf("[%s] %s", a.CPU, r))
			} else {
				res.SuspiciousReasons = append(res.SuspiciousReasons, r)
			}
		}
		_ = i
	}
	res.Note = noteFor(res)
}

func noteFor(res *Result) string {
	base := "Static analysis only — the binary was not executed. "
	if res.Universal {
		base += fmt.Sprintf("Universal (fat) binary with %d architectures. ", len(res.Architectures))
	}
	if res.Suspicious {
		return base + "SUSPICIOUS: " + strings.Join(res.SuspiciousReasons, "; ") +
			". A flagged import is a labelled heuristic, not proof of malice — review before trusting this Mach-O."
	}
	return base + "No strong malware indicator found — not a guarantee of safety (an unsigned, import-light, or " +
		"non-PIE Mach-O can still be hostile)."
}

// --- helpers --------------------------------------------------------------

// suspiciousAPIs are functions commonly abused by macOS / iOS malware, grouped
// by capability. Keys are lower-cased (the leading underscore of a Mach-O C
// symbol is stripped before lookup). A hit is a labelled heuristic, not a
// verdict — many appear in benign software.
var suspiciousAPIs = map[string]bool{ //nolint:gochecknoglobals
	// Process injection / in-memory loading.
	"task_for_pid": true, "mach_vm_write": true, "mach_vm_allocate": true,
	"mach_vm_protect": true, "vm_write": true, "vm_allocate": true,
	"vm_protect": true, "thread_create_running": true,
	"nscreateobjectfileimagefrommemory": true, "nslinkmodule": true,
	"dlopen": true, "dlsym": true, "dyld_dynamic_interpose": true,
	// Execution / spawn.
	"system": true, "popen": true, "execve": true, "execv": true,
	"execl": true, "execlp": true, "execvp": true, "posix_spawn": true,
	"posix_spawnp": true, "fork": true, "vfork": true, "syscall": true,
	// Anti-debug / evasion.
	"ptrace": true, "sysctl": true, "csops": true, "csops_audittoken": true,
	"mach_task_self": true, "getppid": true,
	// RWX memory.
	"mmap": true, "mprotect": true,
	// Network / C2.
	"socket": true, "connect": true, "send": true, "recv": true,
	"cfstreamcreatepairwithsockettohost": true,
	// Keychain / credential theft.
	"seckeychainfindgenericpassword": true, "seckeychainfindinternetpassword": true,
	"seckeychaincopydefault": true, "secitemcopymatching": true,
	// Keylogging / synthetic input / accessibility abuse.
	"cgeventtapcreate": true, "cgeventtapcreateforpsn": true, "cgeventpost": true,
	"axisprocesstrusted": true, "axuielementcopyattributevalue": true,
	// Screen capture.
	"cgdisplaycreateimage": true, "cgwindowlistcreateimage": true,
	// Ransomware crypto.
	"cccrypt": true, "seckeyencrypt": true,
}

func machoBits(magic uint32) int {
	switch magic {
	case macho.Magic64:
		return 64
	case macho.Magic32:
		return 32
	default:
		return 0
	}
}

func cpuName(c macho.Cpu) string {
	switch c {
	case macho.CpuAmd64:
		return "x86-64"
	case macho.Cpu386:
		return "x86"
	case macho.CpuArm64:
		return "ARM64 (Apple Silicon)"
	case macho.CpuArm:
		return "ARM"
	case macho.CpuPpc64:
		return "PowerPC64"
	case macho.CpuPpc:
		return "PowerPC"
	default:
		return strings.TrimPrefix(c.String(), "Cpu")
	}
}

func typeName(t macho.Type) string {
	switch t {
	case macho.TypeExec:
		return "EXECUTE (executable)"
	case macho.TypeDylib:
		return "DYLIB (shared library)"
	case macho.TypeBundle:
		return "BUNDLE (dlopen-loadable)"
	case macho.TypeObj:
		return "OBJECT (relocatable)"
	default:
		return t.String()
	}
}

// headerFlags decodes the security-relevant Mach-O header flags.
func headerFlags(flags uint32) []string {
	var out []string
	for _, f := range []uint32{mhPIE, mhTwoLevel, mhAllowStackExecution, mhNoHeapExecution, mhRootSafe} {
		if flags&f != 0 {
			out = append(out, flagName(f))
		}
	}
	return out
}

func flagName(f uint32) string {
	switch f {
	case mhPIE:
		return "PIE"
	case mhTwoLevel:
		return "TWOLEVEL"
	case mhAllowStackExecution:
		return "ALLOW_STACK_EXECUTION"
	case mhNoHeapExecution:
		return "NO_HEAP_EXECUTION"
	case mhRootSafe:
		return "ROOT_SAFE"
	default:
		return fmt.Sprintf("0x%x", f)
	}
}

// sectionEntropy computes the Shannon entropy of a section's data, sampled under
// a byte cap.
func sectionEntropy(s *macho.Section) (float64, bool) {
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
