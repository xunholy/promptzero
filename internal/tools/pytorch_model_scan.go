// pytorch_model_scan.go — host-side ML-model malicious-pickle scanner Spec,
// delegating to internal/modelscan.
//
// Wrap-vs-native: native — stdlib archive/zip + internal/pickle (the
// pickletools-anchored opcode walk); no new go.mod dep. A PyTorch checkpoint is
// a ZIP whose data.pkl runs on torch.load; this disassembles the embedded
// pickle(s) and flags code-exec gadgets, never loading the model. Offline; no
// network or device.

package tools

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/modelscan"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(pytorchModelScanSpec)
}

var pytorchModelScanSpec = Spec{
	Name: "pytorch_model_scan",
	Description: "Scan a **machine-learning model file** for **malicious embedded pickles** — the in-tree analogue " +
		"of **picklescan / modelscan**. Operators rarely get a bare pickle; they get a model file, and a modern " +
		"**PyTorch checkpoint** (`torch.save` ≥ 1.6 — `.pt` / `.pth` / `.ckpt` / `.bin`) is a **ZIP archive** " +
		"whose `…/data.pkl` member is a pickle that **runs code on `torch.load`** (a legacy checkpoint is a bare " +
		"pickle). This is the supply-chain attack behind the **HuggingFace / PyTorch-Hub** pickle scares: " +
		"loading an untrusted model executes arbitrary code. The tool detects the container, **disassembles " +
		"every embedded pickle** with the safe `pickletools`-style walk (`pickle_decode` under the hood — " +
		"**never `torch.load` / `pickle.load`**), and aggregates a verdict: per-entry **executes_code** + " +
		"**dangerous_imports**, and an overall **dangerous** flag with the union of dangerous imports.\n\n" +
		"**No confidently-wrong output**: a ZIP member is scanned only when its name ends in `.pkl` or it begins " +
		"with the pickle **PROTO** opcode (`0x80`) — catching a renamed/evasion pickle while skipping huge " +
		"tensor blobs; the disassembly **never executes** the stream and is anchored to CPython `pickletools`; " +
		"the danger flag is the labelled heuristic (absence of code-exec opcodes is **not** a safety guarantee). " +
		"`safetensors` (non-executable by design), GGUF and Keras-HDF5 are out of scope. No network, no device, " +
		"transmits nothing — Low risk. Pairs with `pickle_decode` (the per-pickle disassembler).\n\n" +
		"Provide the model file **base64-encoded** (it is binary). Source: docs/catalog/gap-analysis.md (AI " +
		"supply-chain / malware triage). Wrap-vs-native: native — `archive/zip` + `internal/pickle`, no new " +
		"go.mod dep; the embedded-pickle disassembly is anchored opcode-for-opcode to `pickletools`.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"model_base64":{"type":"string","description":"The model file (PyTorch .pt/.pth/.ckpt ZIP, or a raw pickle), base64-encoded."}
		},
		"required":["model_base64"]
	}`),
	Required:  []string{"model_base64"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   pytorchModelScanHandler,
}

func pytorchModelScanHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	b64 := strings.TrimSpace(str(p, "model_base64"))
	if b64 == "" {
		return "", fmt.Errorf("pytorch_model_scan: 'model_base64' is required")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("pytorch_model_scan: 'model_base64' is not valid base64: %w", err)
	}
	res, err := modelscan.Scan(raw)
	if err != nil {
		return "", fmt.Errorf("pytorch_model_scan: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
