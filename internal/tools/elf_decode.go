// elf_decode.go — host-side ELF malware-triage Spec, delegating to
// internal/elftriage.
//
// Wrap-vs-native: native — Go stdlib debug/elf parse + the malware-analysis
// layer, no new go.mod dep. ELF is the Linux / IoT payload format (Mirai-class
// botnets, router/camera backdoors); this surfaces the arch / imports / packing
// signals without executing the binary. Offline; no network or device.

package tools

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/elftriage"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(elfDecodeSpec)
}

var elfDecodeSpec = Spec{
	Name: "elf_decode",
	Description: "Triage an **ELF binary** for **Linux / IoT malware** indicators. ELF is the executable format of " +
		"Linux and the **embedded / IoT** world — routers, IP cameras, NAS boxes, and the **Mirai-class " +
		"botnets** that infest them, plus Linux backdoors and droppers. After the delivery formats " +
		"(`eml_decode` / `lnk_decode` / `pdf_malware_scan`) the **payload** is an ELF, and the analyst question " +
		"is *what is this binary and does it look hostile?* This parses the ELF with the Go stdlib and surfaces " +
		"the **class / endianness / type / CPU architecture** (IoT malware is cross-compiled for **MIPS / ARM / " +
		"…**), the entry point, the **dynamic linker** (or static), whether it is **stripped**, the **NEEDED** " +
		"shared libraries and **RPATH / RUNPATH**, the **imported symbols** with the suspicious libc / syscall " +
		"wrappers (`system` / `execve` / `ptrace` / `socket` …) **flagged**, and per-section **Shannon " +
		"entropy** to spot a **packed** (UPX-style) section.\n\n" +
		"**No confidently-wrong output**: parsing uses stdlib `debug/elf`; fields absent from the binary are " +
		"left empty, never guessed; the **suspicious** verdict is a labelled heuristic (a dangerous import, a " +
		"high-entropy executable section, or an RPATH/RUNPATH) — a clean result is **not** a guarantee of " +
		"safety; section data is sampled under a byte cap for entropy; it **never executes** the binary. No " +
		"network, no device, transmits nothing — Low risk. Pairs with the malware-triage suite.\n\n" +
		"Provide the ELF **base64-encoded** (it is binary). Source: docs/catalog/gap-analysis.md (malware " +
		"triage). Wrap-vs-native: native — `debug/elf` + the analysis layer, no new go.mod dep; anchored to " +
		"real gcc-built ELF binaries.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"elf_base64":{"type":"string","description":"The ELF binary, base64-encoded (it is binary)."}
		},
		"required":["elf_base64"]
	}`),
	Required:  []string{"elf_base64"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   elfDecodeHandler,
}

func elfDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	b64 := strings.TrimSpace(str(p, "elf_base64"))
	if b64 == "" {
		return "", fmt.Errorf("elf_decode: 'elf_base64' is required")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("elf_decode: 'elf_base64' is not valid base64: %w", err)
	}
	res, err := elftriage.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("elf_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
