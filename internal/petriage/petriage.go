// Package petriage triages a Windows PE binary for malware indicators.
//
// PE (Portable Executable — .exe / .dll / .sys) is the executable format of
// Windows, the dominant malware target. After the delivery formats (email /
// .lnk / PDF) the payload on a Windows host is a PE, and the analyst question
// is "what is this binary and does it look hostile?". This parses the PE with
// the Go stdlib (debug/pe) and layers the triage: the CPU architecture
// (x86 / x86-64 / ARM64), the bitness, the subsystem (GUI / console / native
// driver), the entry point and image base, the link timestamp, the COFF
// characteristics (DLL / executable / driver), the present and *absent*
// exploit mitigations (ASLR / DEP / Control-Flow-Guard — their absence is a
// hardening red flag common to old packers and hand-rolled droppers), the
// imported DLLs and symbols with the suspicious Win32 APIs flagged (process
// injection — VirtualAllocEx / WriteProcessMemory / CreateRemoteThread;
// dynamic resolution — LoadLibrary / GetProcAddress; execution — WinExec /
// ShellExecute / CreateProcess; download — URLDownloadToFile / InternetOpenUrl;
// keylogging, anti-debug, ransomware-crypto, service install, process
// enumeration), and per-section Shannon entropy plus W^X / known-packer
// section names to spot a packed / self-modifying section (UPX, ASPack,
// MPRESS, VMProtect, Themida and friends).
//
// No confidently-wrong output: parsing uses stdlib debug/pe; fields absent
// from the binary are left empty, never guessed; the suspicious verdict is a
// labelled heuristic (a known-abused import, a high-entropy executable
// section, a writable+executable section, or a packer section name) — a clean
// result is not a guarantee of safety, and a flagged import is not proof of
// malice (many flagged APIs appear in benign software); section data is
// sampled under a byte cap for entropy; it never executes the binary.
//
// Wrap-vs-native: native — Go stdlib debug/pe + the analysis layer, no new
// go.mod dependency. Anchored to a real gcc/mingw-built PE binary (see the
// test): the Go toolchain's own debug/pe corpus.
package petriage

import (
	"bytes"
	"debug/pe"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"time"
)

// entropySampleCap bounds how many bytes of a section are read for entropy.
const entropySampleCap = 256 << 10

// Section is one section's triage facts.
type Section struct {
	Name        string  `json:"name"`
	VirtualSize uint32  `json:"virtual_size"`
	RawSize     uint32  `json:"raw_size"`
	Executable  bool    `json:"executable,omitempty"`
	Writable    bool    `json:"writable,omitempty"`
	WriteExec   bool    `json:"write_exec,omitempty"`
	Entropy     float64 `json:"entropy,omitempty"`
	HighEntropy bool    `json:"high_entropy,omitempty"`
}

// Result is the PE triage.
type Result struct {
	Format        string `json:"format"`
	Bits          int    `json:"bits"`
	Machine       string `json:"machine"`
	Type          string `json:"type"`
	Subsystem     string `json:"subsystem,omitempty"`
	EntryPoint    string `json:"entry_point,omitempty"`
	ImageBase     string `json:"image_base,omitempty"`
	TimeDateStamp string `json:"time_date_stamp,omitempty"`

	Characteristics    []string `json:"characteristics,omitempty"`
	Mitigations        []string `json:"mitigations,omitempty"`
	MissingMitigations []string `json:"missing_mitigations,omitempty"`

	ImportedDLLs      []string  `json:"imported_dlls,omitempty"`
	ImportedSymbols   []string  `json:"imported_symbols,omitempty"`
	SuspiciousSymbols []string  `json:"suspicious_symbols,omitempty"`
	ImportsUnparsed   bool      `json:"imports_unparsed,omitempty"`
	Sections          []Section `json:"sections,omitempty"`

	Suspicious        bool     `json:"suspicious"`
	SuspiciousReasons []string `json:"suspicious_reasons,omitempty"`
	Note              string   `json:"note"`
}

// Decode triages a PE byte stream. It never panics: the stdlib debug/pe import
// parser is known to slice-panic on a malformed import directory (and a
// hostile / corrupt PE is exactly this tool's input), so a recover converts any
// such panic into a graceful error rather than crashing the host.
func Decode(data []byte) (res *Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			res, err = nil, fmt.Errorf("petriage: malformed PE (recovered: %v)", r)
		}
	}()

	f, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("petriage: not a PE: %w", err)
	}
	defer f.Close()

	res = &Result{
		Format:          "pe",
		Machine:         machineName(f.Machine),
		Type:            peType(f.Characteristics),
		Characteristics: characteristicFlags(f.Characteristics),
	}
	if f.TimeDateStamp != 0 {
		res.TimeDateStamp = time.Unix(int64(f.TimeDateStamp), 0).UTC().Format(time.RFC3339)
	}
	res.readOptionalHeader(f)
	res.collectImports(f)
	res.collectSections(f)
	res.evaluate()
	return res, nil
}

// readOptionalHeader pulls bitness, entry point, image base, subsystem, and the
// exploit-mitigation flags from the optional header (absent in COFF objects).
func (res *Result) readOptionalHeader(f *pe.File) {
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		res.Bits = 32
		res.EntryPoint = fmt.Sprintf("0x%x", oh.AddressOfEntryPoint)
		res.ImageBase = fmt.Sprintf("0x%x", oh.ImageBase)
		res.Subsystem = subsystemName(oh.Subsystem)
		res.fillMitigations(oh.DllCharacteristics)
	case *pe.OptionalHeader64:
		res.Bits = 64
		res.EntryPoint = fmt.Sprintf("0x%x", oh.AddressOfEntryPoint)
		res.ImageBase = fmt.Sprintf("0x%x", oh.ImageBase)
		res.Subsystem = subsystemName(oh.Subsystem)
		res.fillMitigations(oh.DllCharacteristics)
	}
}

// fillMitigations records the present and absent exploit mitigations. A driver
// (no subsystem-driven mitigations) is judged the same — absence is surfaced,
// not auto-condemned.
func (res *Result) fillMitigations(dc uint16) {
	for _, m := range []struct {
		bit  uint16
		name string
	}{
		{pe.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, "ASLR"},
		{pe.IMAGE_DLLCHARACTERISTICS_NX_COMPAT, "DEP"},
		{pe.IMAGE_DLLCHARACTERISTICS_GUARD_CF, "CFG"},
		{pe.IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA, "HighEntropyVA"},
		{pe.IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY, "ForceIntegrity"},
	} {
		if dc&m.bit != 0 {
			res.Mitigations = append(res.Mitigations, m.name)
		} else if m.name == "ASLR" || m.name == "DEP" || m.name == "CFG" {
			res.MissingMitigations = append(res.MissingMitigations, m.name)
		}
	}
}

// collectImports records the imported DLLs and symbols, flagging the
// malware-relevant Win32 APIs. debug/pe returns "Symbol:DLL"; ImportedLibraries
// is unreliable (often empty) so the DLL set is derived from the symbol list.
// A corrupt import directory (common in packed malware) makes the stdlib parser
// error or slice-panic; either way the imports are marked unparsed and the rest
// of the triage (header / sections) still returns.
func (res *Result) collectImports(f *pe.File) {
	syms, ok := safeImportedSymbols(f)
	if !ok {
		res.ImportsUnparsed = true
		return
	}
	dlls := map[string]bool{}
	seen := map[string]bool{}
	for _, s := range syms {
		name, dll, ok := strings.Cut(s, ":")
		if !ok {
			name = s
		}
		if dll != "" {
			dlls[dll] = true
		}
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		res.ImportedSymbols = append(res.ImportedSymbols, name)
		if suspiciousAPIs[strings.ToLower(name)] {
			res.SuspiciousSymbols = append(res.SuspiciousSymbols, name)
		}
	}
	for d := range dlls {
		res.ImportedDLLs = append(res.ImportedDLLs, d)
	}
	sort.Strings(res.ImportedDLLs)
	sort.Strings(res.ImportedSymbols)
	sort.Strings(res.SuspiciousSymbols)
}

// safeImportedSymbols calls debug/pe's ImportedSymbols, recovering from the
// slice-bounds panic it raises on a malformed import directory so a hostile PE
// degrades to "imports unparsed" instead of crashing the host.
func safeImportedSymbols(f *pe.File) (syms []string, ok bool) {
	defer func() {
		if recover() != nil {
			syms, ok = nil, false
		}
	}()
	s, err := f.ImportedSymbols()
	if err != nil {
		return nil, false
	}
	return s, true
}

// collectSections records section facts, W^X violations, and per-section
// entropy.
func (res *Result) collectSections(f *pe.File) {
	for _, s := range f.Sections {
		exec := s.Characteristics&pe.IMAGE_SCN_MEM_EXECUTE != 0
		write := s.Characteristics&pe.IMAGE_SCN_MEM_WRITE != 0
		sec := Section{
			Name:        s.Name,
			VirtualSize: s.VirtualSize,
			RawSize:     s.Size,
			Executable:  exec,
			Writable:    write,
			WriteExec:   exec && write,
		}
		if s.Size > 0 {
			if e, ok := sectionEntropy(s); ok {
				sec.Entropy = round2(e)
				sec.HighEntropy = e >= 7.0 && exec
			}
		}
		res.Sections = append(res.Sections, sec)
	}
}

// evaluate fills the suspicious verdict.
func (res *Result) evaluate() {
	var reasons []string
	if len(res.SuspiciousSymbols) > 0 {
		reasons = append(reasons, "abused Win32 APIs: "+strings.Join(res.SuspiciousSymbols, ", "))
	}
	for _, s := range res.Sections {
		if s.HighEntropy {
			reasons = append(reasons, fmt.Sprintf("high-entropy executable section %q (entropy %.2f) — possibly packed", s.Name, s.Entropy))
		}
		if s.WriteExec {
			reasons = append(reasons, fmt.Sprintf("writable+executable section %q — self-modifying / unpacking stub", s.Name))
		}
		if pn := packerName(s.Name); pn != "" {
			reasons = append(reasons, fmt.Sprintf("known-packer section %q (%s)", s.Name, pn))
		}
	}
	if len(reasons) > 0 {
		res.Suspicious = true
		res.SuspiciousReasons = reasons
	}
	res.Note = noteFor(res)
}

func noteFor(res *Result) string {
	base := "Static analysis only — the binary was not executed. "
	if res.ImportsUnparsed {
		base += "Import table could not be parsed (malformed / corrupt directory — common in packed malware); imports not shown. "
	}
	if res.Suspicious {
		return base + "SUSPICIOUS: " + strings.Join(res.SuspiciousReasons, "; ") +
			". A flagged import is a labelled heuristic, not proof of malice — review before trusting this PE."
	}
	return base + "No strong malware indicator found — not a guarantee of safety (a stripped, mitigation-free, " +
		"or import-light PE can still be hostile; absence of imports often means a packed loader)."
}

// --- helpers --------------------------------------------------------------

// suspiciousAPIs are Win32 / NT functions commonly abused by Windows malware,
// grouped by capability. Keys are lower-cased; lookups lower-case the symbol so
// the ANSI/Wide (A/W) suffixes and case variants all match. A hit is a labelled
// heuristic, not a verdict — many appear in benign software.
var suspiciousAPIs = map[string]bool{ //nolint:gochecknoglobals
	// Process injection / memory.
	"virtualalloc": true, "virtualallocex": true, "virtualprotect": true,
	"virtualprotectex": true, "writeprocessmemory": true, "readprocessmemory": true,
	"createremotethread": true, "createremotethreadex": true, "ntcreatethreadex": true,
	"rtlcreateuserthread": true, "queueuserapc": true, "setthreadcontext": true,
	"getthreadcontext": true, "ntunmapviewofsection": true, "ntmapviewofsection": true,
	"mapviewoffile": true, "ntwritevirtualmemory": true, "ntallocatevirtualmemory": true,
	// Dynamic resolution (hide imports).
	"loadlibrarya": true, "loadlibraryw": true, "loadlibraryexa": true,
	"loadlibraryexw": true, "getprocaddress": true, "ldrloaddll": true,
	"ldrgetprocedureaddress": true,
	// Execution / spawn.
	"winexec": true, "createprocessa": true, "createprocessw": true,
	"createprocessinternalw": true, "shellexecutea": true, "shellexecutew": true,
	"shellexecuteexa": true, "shellexecuteexw": true, "system": true, "_wsystem": true,
	"ntcreateprocess": true, "ntcreateuserprocess": true,
	// Download / network C2.
	"urldownloadtofilea": true, "urldownloadtofilew": true, "internetopena": true,
	"internetopenw": true, "internetopenurla": true, "internetopenurlw": true,
	"internetreadfile": true, "internetconnecta": true, "internetconnectw": true,
	"httpsendrequesta": true, "httpsendrequestw": true, "winhttpopen": true,
	"winhttpconnect": true, "winhttpsendrequest": true, "wsastartup": true,
	"connect": true, "send": true, "recv": true, "socket": true,
	// Persistence / registry.
	"regsetvalueexa": true, "regsetvalueexw": true, "regcreatekeyexa": true,
	"regcreatekeyexw": true, "regopenkeyexa": true, "regopenkeyexw": true,
	// Keylogging / input.
	"setwindowshookexa": true, "setwindowshookexw": true, "getasynckeystate": true,
	"getkeystate": true, "getkeyboardstate": true, "registerrawinputdevices": true,
	// Anti-debug / evasion.
	"isdebuggerpresent": true, "checkremotedebuggerpresent": true,
	"ntqueryinformationprocess": true, "outputdebugstringa": true,
	"ntsetinformationthread": true, "blockinput": true,
	// Token / privilege.
	"adjusttokenprivileges": true, "openprocesstoken": true,
	"lookupprivilegevaluea": true, "lookupprivilegevaluew": true,
	"createprocesswithtokenw": true, "duplicatetokenex": true,
	// Ransomware crypto.
	"cryptencrypt": true, "cryptdecrypt": true, "cryptgenkey": true,
	"cryptacquirecontexta": true, "cryptacquirecontextw": true,
	"bcryptencrypt": true, "bcryptgeneratesymmetrickey": true,
	// Service install (persistence as a service).
	"createservicea": true, "createservicew": true, "openscmanagera": true,
	"openscmanagerw": true, "startservicea": true, "startservicew": true,
	// Process enumeration (targeting / AV-killing).
	"createtoolhelp32snapshot": true, "process32first": true, "process32firstw": true,
	"process32next": true, "process32nextw": true, "openprocess": true,
	"terminateprocess": true,
}

// machineName maps the common PE architectures to a friendly name, falling back
// to a hex machine code.
func machineName(m uint16) string {
	switch m {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "x86-64"
	case pe.IMAGE_FILE_MACHINE_I386:
		return "x86"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return "ARM64"
	case pe.IMAGE_FILE_MACHINE_ARMNT, pe.IMAGE_FILE_MACHINE_ARM:
		return "ARM"
	case pe.IMAGE_FILE_MACHINE_THUMB:
		return "ARM Thumb"
	case pe.IMAGE_FILE_MACHINE_IA64:
		return "Itanium (IA-64)"
	case pe.IMAGE_FILE_MACHINE_RISCV64:
		return "RISC-V 64"
	case pe.IMAGE_FILE_MACHINE_RISCV32:
		return "RISC-V 32"
	case pe.IMAGE_FILE_MACHINE_LOONGARCH64:
		return "LoongArch64"
	case pe.IMAGE_FILE_MACHINE_UNKNOWN:
		return "unknown"
	default:
		return fmt.Sprintf("0x%x", m)
	}
}

// peType classifies the image from the COFF characteristics.
func peType(c uint16) string {
	switch {
	case c&pe.IMAGE_FILE_DLL != 0:
		return "DLL (dynamic-link library)"
	case c&pe.IMAGE_FILE_SYSTEM != 0:
		return "SYS (driver / system file)"
	case c&pe.IMAGE_FILE_EXECUTABLE_IMAGE != 0:
		return "EXE (executable)"
	default:
		return "OBJ (object / unknown)"
	}
}

// characteristicFlags decodes the notable COFF characteristic bits.
func characteristicFlags(c uint16) []string {
	var out []string
	for _, f := range []struct {
		bit  uint16
		name string
	}{
		{pe.IMAGE_FILE_EXECUTABLE_IMAGE, "EXECUTABLE_IMAGE"},
		{pe.IMAGE_FILE_DLL, "DLL"},
		{pe.IMAGE_FILE_SYSTEM, "SYSTEM"},
		{pe.IMAGE_FILE_RELOCS_STRIPPED, "RELOCS_STRIPPED"},
		{pe.IMAGE_FILE_DEBUG_STRIPPED, "DEBUG_STRIPPED"},
		{pe.IMAGE_FILE_LARGE_ADDRESS_AWARE, "LARGE_ADDRESS_AWARE"},
	} {
		if c&f.bit != 0 {
			out = append(out, f.name)
		}
	}
	return out
}

// subsystemName maps the optional-header subsystem to a friendly name.
func subsystemName(s uint16) string {
	switch s {
	case pe.IMAGE_SUBSYSTEM_WINDOWS_GUI:
		return "Windows GUI"
	case pe.IMAGE_SUBSYSTEM_WINDOWS_CUI:
		return "Windows console"
	case pe.IMAGE_SUBSYSTEM_NATIVE:
		return "Native (driver)"
	case pe.IMAGE_SUBSYSTEM_EFI_APPLICATION:
		return "EFI application"
	case pe.IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
		return "EFI boot-service driver"
	case pe.IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
		return "EFI runtime driver"
	case pe.IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
		return "Windows CE GUI"
	case pe.IMAGE_SUBSYSTEM_UNKNOWN:
		return ""
	default:
		return fmt.Sprintf("subsystem %d", s)
	}
}

// knownPackers maps a section name (upper-cased) to the packer it signals.
var knownPackers = map[string]string{ //nolint:gochecknoglobals
	"UPX0": "UPX", "UPX1": "UPX", "UPX2": "UPX", "UPX3": "UPX",
	".ASPACK": "ASPack", ".ADATA": "ASPack", "ASPACK": "ASPack",
	".NSP0": "NsPack", ".NSP1": "NsPack", ".NSP2": "NsPack",
	"FSG!": "FSG", ".PETITE": "Petite",
	"MPRESS1": "MPRESS", "MPRESS2": "MPRESS",
	".VMP0": "VMProtect", ".VMP1": "VMProtect", ".VMP2": "VMProtect",
	".THEMIDA": "Themida", "WINLICEN": "WinLicense / Themida",
	".BOOM": "The Boomerang", ".TAZ": "PESpin", ".PACKED": "generic packer",
	".RLPACK": "RLPack", ".RMNET": "Ramnit", ".CHARMVE": "PIN tool",
	".SFORCE3": "StarForce", ".SPACK": "Simple Pack", ".SVKP": "SVKP",
	".Y0DA": "yoda crypter", ".PERPLEX": "Perplex", ".CCG": "CCG",
}

// packerName returns the packer a section name signals, or "" if none.
func packerName(name string) string {
	return knownPackers[strings.ToUpper(strings.TrimRight(name, "\x00"))]
}

// sectionEntropy computes the Shannon entropy of a section's data, sampled under
// a byte cap.
func sectionEntropy(s *pe.Section) (float64, bool) {
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
