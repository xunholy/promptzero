// lnk_decode.go — host-side Windows Shell Link (.lnk) decoder Spec, delegating
// to internal/lnk.
//
// Wrap-vs-native: native — a bounds-checked walk of the documented [MS-SHLLINK]
// structure, stdlib only, no new go.mod dep. Malicious .lnk shortcuts are a top
// phishing / USB-drop delivery vector; this surfaces the command the shortcut
// runs and flags the LOLBins, never executing it. Offline; no network or device.

package tools

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/lnk"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(lnkDecodeSpec)
}

var lnkDecodeSpec = Spec{
	Name: "lnk_decode",
	Description: "Decode a **Windows Shell Link** (`.lnk` shortcut) and reveal **the command it runs** — a top " +
		"modern malware delivery vector. Since Microsoft began blocking Office macros, phishing and USB-drop " +
		"campaigns (**Qbot, IcedID, Emotet, …**) ship a benign-looking shortcut whose **hidden command-line " +
		"arguments** launch `powershell` / `mshta` / `rundll32` to stage the payload. The analyst question is " +
		"*what does this shortcut actually run?* — this parses the documented **[MS-SHLLINK]** structure " +
		"**offline** and surfaces the **link flags**, the **show command**, the StringData (**name** / relative " +
		"path / working dir / **command-line arguments** / icon), any LinkInfo **target path** + " +
		"EnvironmentVariableDataBlock target, and **flags the LOLBins / staging techniques** in the command " +
		"line (`powershell -enc`, `mshta http://…`, `certutil`, `-w hidden`, …).\n\n" +
		"**No confidently-wrong output**: the file is recognised only by its `0x0000004C` HeaderSize and the " +
		"`{00021401-…46}` LinkCLSID; every offset/length is **bounds-checked**; an optional section that does " +
		"not fit is skipped, not over-read; the **shell-item IDList is not decoded** (the target there is " +
		"shell-encoded — noted, not guessed); and the **suspicious** flag is a labelled indicator scan (a clean " +
		"scan is not a safety guarantee). No network, no device, transmits nothing, **never executes the " +
		"shortcut** — Low risk.\n\n" +
		"Provide the `.lnk` **base64-encoded** (it is binary). Source: docs/catalog/gap-analysis.md (malware " +
		"triage). Wrap-vs-native: native — a bounds-checked [MS-SHLLINK] walk, no new go.mod dep; anchored to " +
		"real `pylnk3`-generated shortcuts cross-decoded with `LnkParse3`.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"lnk_base64":{"type":"string","description":"The Windows .lnk shortcut file, base64-encoded (it is binary)."}
		},
		"required":["lnk_base64"]
	}`),
	Required:  []string{"lnk_base64"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   lnkDecodeHandler,
}

func lnkDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	b64 := strings.TrimSpace(str(p, "lnk_base64"))
	if b64 == "" {
		return "", fmt.Errorf("lnk_decode: 'lnk_base64' is required")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("lnk_decode: 'lnk_base64' is not valid base64: %w", err)
	}
	res, err := lnk.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("lnk_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
