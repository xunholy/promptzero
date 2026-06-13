// pickle_decode.go — host-side Python-pickle disassembler Spec, delegating to
// internal/pickle.
//
// Wrap-vs-native: native — a byte-cursor walk of the documented pickle opcode
// set (transcribed from CPython pickletools), stdlib only, no new go.mod dep.
// A malicious pickle is a top supply-chain RCE vector (model files, caches);
// this disassembles it and flags the code-exec opcodes, never unpickling it.
// Offline; no network or device.

package tools

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/pickle"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(pickleDecodeSpec)
}

var pickleDecodeSpec = Spec{
	Name: "pickle_decode",
	Description: "Disassemble a **Python pickle** byte stream and flag the **code-execution opcodes** that make a " +
		"pickle malicious — **without ever unpickling it**. A malicious pickle is a **top supply-chain RCE " +
		"vector**: PyTorch / TensorFlow / scikit-learn / **HuggingFace** model files, joblib caches, and Redis " +
		"values are all pickles, and merely **loading** one with `pickle.load` runs whatever its `GLOBAL` + " +
		"`REDUCE` opcodes encode (the classic gadget is `GLOBAL os system` / `STACK_GLOBAL` + `REDUCE`). This " +
		"walks the opcode stream — the **safe** operation `pickletools.dis` performs, never `pickle.load` — and " +
		"reports the **protocol** version, every **opcode**, the **imported callables** (`module.name` from " +
		"GLOBAL / STACK_GLOBAL / INST), whether the pickle **executes code** (an import opcode plus an " +
		"invocation opcode), and the **dangerous imports** (`os` / `subprocess` / `builtins.eval` / …) called " +
		"out.\n\n" +
		"**No confidently-wrong output**: the opcode + argument encodings are transcribed verbatim from " +
		"CPython's `pickletools.opcodes`; an unknown opcode **stops** the walk (its argument length is then " +
		"unknown) and is reported as `UNKNOWN(0x..)` rather than guessed; every length field is bounds-checked; " +
		"and the stream is **never executed**. The `STACK_GLOBAL` target is resolved heuristically from the two " +
		"preceding string pushes (how the pickler emits it) and the danger flag is a labelled heuristic — " +
		"absence of code-exec opcodes is not a safety guarantee. No network, no device, transmits nothing — Low " +
		"risk. Pairs with `secret_scan` / the malware-triage tools.\n\n" +
		"Provide the pickle **base64-encoded** (it is binary). Source: docs/catalog/gap-analysis.md (malware / " +
		"AI-supply-chain triage). Wrap-vs-native: native — a documented opcode walk, no new go.mod dep; " +
		"anchored opcode-for-opcode to Python's stdlib `pickletools`.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"pickle_base64":{"type":"string","description":"The Python pickle byte stream, base64-encoded (it is binary)."}
		},
		"required":["pickle_base64"]
	}`),
	Required:  []string{"pickle_base64"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   pickleDecodeHandler,
}

func pickleDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	b64 := strings.TrimSpace(str(p, "pickle_base64"))
	if b64 == "" {
		return "", fmt.Errorf("pickle_decode: 'pickle_base64' is required")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("pickle_decode: 'pickle_base64' is not valid base64: %w", err)
	}
	res, err := pickle.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("pickle_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
