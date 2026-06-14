// pe_decode.go — host-side Windows PE malware-triage Spec, delegating to
// internal/petriage.
//
// Wrap-vs-native: native — Go stdlib debug/pe parse + the malware-analysis
// layer, no new go.mod dep. PE is the executable format of Windows (the
// dominant malware target); this surfaces the arch / mitigations / imports /
// packing signals without executing the binary. Offline; no network or device.

package tools

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/petriage"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(peDecodeSpec)
}

var peDecodeSpec = Spec{
	Name: "pe_decode",
	Description: "Triage a **Windows PE binary** (`.exe` / `.dll` / `.sys`) for **malware** indicators. PE is the " +
		"executable format of **Windows**, the dominant malware target. After the delivery formats " +
		"(`eml_decode` / `lnk_decode` / `pdf_malware_scan`) the **payload** on a Windows host is a PE, and the " +
		"analyst question is *what is this binary and does it look hostile?* This parses the PE with the Go stdlib " +
		"and surfaces the **bitness / CPU architecture** (x86 / x86-64 / ARM64), the **subsystem** (GUI / console " +
		"/ native driver), the **entry point**, **image base**, and link **timestamp**, the **COFF " +
		"characteristics** (DLL / executable / driver), the present **and absent exploit mitigations** " +
		"(**ASLR / DEP / Control-Flow-Guard** — their absence is a hardening red flag common to old packers and " +
		"hand-rolled droppers), the **imported DLLs and symbols** with the **abused Win32 APIs flagged** " +
		"(process injection — `VirtualAllocEx` / `WriteProcessMemory` / `CreateRemoteThread`; dynamic resolution " +
		"— `LoadLibrary` / `GetProcAddress`; execution — `WinExec` / `ShellExecute` / `CreateProcess`; download — " +
		"`URLDownloadToFile` / `InternetOpenUrl`; keylogging, anti-debug, ransomware-crypto, service install, " +
		"process enumeration), and per-section **Shannon entropy** plus **W^X** (writable+executable) and " +
		"**known-packer section names** (UPX / ASPack / MPRESS / VMProtect / Themida …) to spot a **packed / " +
		"self-modifying** section.\n\n" +
		"**No confidently-wrong output**: parsing uses stdlib `debug/pe`; fields absent from the binary are left " +
		"empty, never guessed; the **suspicious** verdict is a labelled heuristic (an abused import, a " +
		"high-entropy executable section, a writable+executable section, or a packer section name) — a clean " +
		"result is **not** a guarantee of safety and a flagged import is **not** proof of malice (many flagged " +
		"APIs appear in benign software); section data is sampled under a byte cap for entropy; it **never " +
		"executes** the binary. No network, no device, transmits nothing — Low risk. Pairs with the " +
		"malware-triage suite.\n\n" +
		"Provide the PE **base64-encoded** (it is binary). Source: docs/catalog/gap-analysis.md (malware " +
		"triage). Wrap-vs-native: native — `debug/pe` + the analysis layer, no new go.mod dep; anchored to a " +
		"real mingw-built PE binary.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"pe_base64":{"type":"string","description":"The Windows PE binary, base64-encoded (it is binary)."}
		},
		"required":["pe_base64"]
	}`),
	Required:  []string{"pe_base64"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   peDecodeHandler,
}

func peDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	b64 := strings.TrimSpace(str(p, "pe_base64"))
	if b64 == "" {
		return "", fmt.Errorf("pe_decode: 'pe_base64' is required")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("pe_decode: 'pe_base64' is not valid base64: %w", err)
	}
	res, err := petriage.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("pe_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
