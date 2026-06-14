// macho_decode.go — host-side Mach-O malware-triage Spec, delegating to
// internal/machotriage.
//
// Wrap-vs-native: native — Go stdlib debug/macho parse + the malware-analysis
// layer, no new go.mod dep. Mach-O is the executable format of macOS / iOS (the
// third of the ELF / PE / Mach-O payload triad); this surfaces the arch /
// signing / imports / packing signals without executing the binary. Offline; no
// network or device.

package tools

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/machotriage"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(machoDecodeSpec)
}

var machoDecodeSpec = Spec{
	Name: "macho_decode",
	Description: "Triage a **Mach-O binary** for **macOS / iOS malware** indicators. Mach-O is the executable format " +
		"of **macOS and iOS** — the third member of the executable-payload triad alongside **ELF** (`elf_decode`, " +
		"Linux / IoT) and **PE** (`pe_decode`, Windows). After the delivery formats (`eml_decode` / `lnk_decode` " +
		"/ `pdf_malware_scan`) the **payload** on an Apple host is a Mach-O, and the analyst question is *what is " +
		"this binary and does it look hostile?* This parses the Mach-O with the Go stdlib and surfaces the " +
		"**bitness / CPU architecture** (x86-64 / **arm64** — Apple-Silicon malware), the **file type** (EXECUTE " +
		"/ DYLIB / **BUNDLE** — a dlopen-loaded bundle is a classic injection vector), the security-relevant " +
		"**header flags** (**PIE**; **MH_ALLOW_STACK_EXECUTION** — a W^X red flag), whether the binary is " +
		"**code-signed** and whether a segment is **encrypted** (FairPlay / packer), the **imported dylibs / " +
		"frameworks** and the **LC_RPATH** search paths (**dylib-hijack** surface), the **imported symbols** with " +
		"the suspicious ones **flagged** (process injection — `task_for_pid` / `mach_vm_write` / " +
		"`NSCreateObjectFileImageFromMemory`; anti-debug — `ptrace`(PT_DENY_ATTACH) / `sysctl` / `csops`; exec — " +
		"`system` / `posix_spawn`; keylogging — `CGEventTapCreate` / `AXIsProcessTrusted`; keychain theft, " +
		"ransomware-crypto, screen capture), and per-section **Shannon entropy** to spot a **packed** section. " +
		"**Universal (fat) binaries** are triaged **per-architecture**.\n\n" +
		"**No confidently-wrong output**: parsing uses stdlib `debug/macho`; fields absent from the binary are " +
		"left empty, never guessed; the **suspicious** verdict is a labelled heuristic (a known-abused import, an " +
		"RPATH, a high-entropy executable section, an encrypted segment, or a stack-execution flag) — a clean " +
		"result is **not** a guarantee of safety, and a flagged import is **not** proof of malice (many flagged " +
		"APIs appear in benign software); section data is sampled under a byte cap for entropy; parsing is " +
		"panic-guarded (a malformed Mach-O yields an error, never a crash — verified by a 2M-input mutation " +
		"audit); it **never executes** the binary. No network, no device, transmits nothing — Low risk. Pairs " +
		"with the malware-triage suite.\n\n" +
		"Provide the Mach-O **base64-encoded** (it is binary). Source: docs/catalog/gap-analysis.md (malware " +
		"triage). Wrap-vs-native: native — `debug/macho` + the analysis layer, no new go.mod dep; anchored to " +
		"real clang/gcc-built Mach-O binaries (thin and fat).",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"macho_base64":{"type":"string","description":"The Mach-O binary, base64-encoded (it is binary)."}
		},
		"required":["macho_base64"]
	}`),
	Required:  []string{"macho_base64"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   machoDecodeHandler,
}

func machoDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	b64 := strings.TrimSpace(str(p, "macho_base64"))
	if b64 == "" {
		return "", fmt.Errorf("macho_decode: 'macho_base64' is required")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("macho_decode: 'macho_base64' is not valid base64: %w", err)
	}
	res, err := machotriage.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("macho_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
