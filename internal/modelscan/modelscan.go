// Package modelscan scans a machine-learning model file for malicious embedded
// Python pickles and reports which can execute code on load.
//
// Operators rarely receive a bare pickle — they receive a model file. A modern
// PyTorch checkpoint (torch.save ≥ 1.6: .pt / .pth / .ckpt / .bin) is a ZIP
// archive whose `…/data.pkl` member is a pickle that runs on torch.load; a
// legacy checkpoint is a bare pickle. Either way, loading an untrusted model can
// execute arbitrary code (the supply-chain attack behind the HuggingFace /
// PyTorch-Hub pickle scares). This is the in-tree analogue of picklescan /
// modelscan: it detects the container, disassembles every embedded pickle with
// internal/pickle (the safe pickletools-style walk — never torch.load /
// pickle.load), and aggregates the verdict.
//
// No confidently-wrong output: a ZIP member is scanned only when its name ends
// in `.pkl` or it begins with the pickle PROTO opcode (0x80), and an oversized
// member is skipped from the heuristic scan rather than read whole; the pickle
// disassembly itself never executes the stream and is anchored to pickletools;
// the danger flag is the labelled heuristic internal/pickle computes (absence of
// code-exec opcodes is not a safety guarantee).
//
// Wrap-vs-native: native — stdlib archive/zip plus internal/pickle; no new
// go.mod dependency. safetensors / GGUF / Keras-HDF5 model formats are out of
// scope (safetensors is by design non-executable; the others are separate
// container formats).
package modelscan

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/xunholy/promptzero/internal/pickle"
)

// scanByteCap bounds how many bytes of a candidate ZIP member are read before
// disassembly, and the largest member considered for the 0x80-prefix heuristic.
const scanByteCap = 64 << 20 // 64 MiB

// Entry is the scan result for one embedded pickle.
type Entry struct {
	Path             string   `json:"path"`
	PickleProtocol   int      `json:"pickle_protocol"`
	OpcodeCount      int      `json:"opcode_count"`
	ExecutesCode     bool     `json:"executes_code"`
	Imports          []string `json:"imports,omitempty"`
	DangerousImports []string `json:"dangerous_imports,omitempty"`
	Error            string   `json:"error,omitempty"`
}

// Result is the aggregate scan of a model file.
type Result struct {
	// Format is "pytorch-zip" (a ZIP container) or "raw-pickle".
	Format              string   `json:"format"`
	PickleCount         int      `json:"pickle_count"`
	Entries             []Entry  `json:"entries"`
	Dangerous           bool     `json:"dangerous"`
	ExecutesCode        bool     `json:"executes_code"`
	AllDangerousImports []string `json:"all_dangerous_imports,omitempty"`
	Note                string   `json:"note"`
}

// Scan detects the container and scans every embedded pickle.
func Scan(data []byte) (*Result, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("modelscan: empty input")
	}
	if bytes.HasPrefix(data, []byte("PK\x03\x04")) || bytes.HasPrefix(data, []byte("PK\x05\x06")) {
		return scanZip(data)
	}
	return scanRaw(data)
}

// scanRaw treats the whole input as a single pickle (a legacy torch checkpoint
// or a bare .pkl).
func scanRaw(data []byte) (*Result, error) {
	res := &Result{Format: "raw-pickle"}
	res.add("<root>", data)
	res.finish()
	return res, nil
}

// scanZip walks a ZIP container and scans every pickle member.
func scanZip(data []byte) (*Result, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("modelscan: not a readable ZIP: %w", err)
	}
	res := &Result{Format: "pytorch-zip"}
	for _, f := range zr.File {
		if !isPickleMember(f) {
			continue
		}
		body, err := readCapped(f)
		if err != nil {
			res.Entries = append(res.Entries, Entry{Path: f.Name, Error: err.Error()})
			res.PickleCount++
			continue
		}
		res.add(f.Name, body)
	}
	res.finish()
	return res, nil
}

// isPickleMember decides whether a ZIP member should be disassembled: a `.pkl`
// name (the PyTorch convention) always, or any member that starts with the
// pickle PROTO opcode and is not larger than the scan cap (an evasion / renamed
// pickle), but never a huge tensor blob that merely happens to start with 0x80.
func isPickleMember(f *zip.File) bool {
	if strings.HasSuffix(strings.ToLower(f.Name), ".pkl") {
		return true
	}
	if f.UncompressedSize64 == 0 || f.UncompressedSize64 > scanByteCap {
		return false
	}
	rc, err := f.Open()
	if err != nil {
		return false
	}
	defer rc.Close()
	var first [1]byte
	if _, err := io.ReadFull(rc, first[:]); err != nil {
		return false
	}
	return first[0] == 0x80 // PROTO opcode
}

// readCapped reads a ZIP member up to scanByteCap bytes.
func readCapped(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, scanByteCap))
}

// add disassembles one pickle and records its entry.
func (r *Result) add(path string, body []byte) {
	r.PickleCount++
	dec, err := pickle.Decode(body)
	if err != nil {
		r.Entries = append(r.Entries, Entry{Path: path, Error: err.Error()})
		return
	}
	r.Entries = append(r.Entries, Entry{
		Path:             path,
		PickleProtocol:   dec.Protocol,
		OpcodeCount:      dec.OpCount,
		ExecutesCode:     dec.ExecutesCode,
		Imports:          dec.Imports,
		DangerousImports: dec.DangerousImports,
	})
}

// finish aggregates the per-entry verdicts.
func (r *Result) finish() {
	dangerSet := map[string]bool{}
	for _, e := range r.Entries {
		if e.ExecutesCode {
			r.ExecutesCode = true
		}
		for _, d := range e.DangerousImports {
			dangerSet[d] = true
		}
	}
	if len(dangerSet) > 0 {
		r.Dangerous = true
		for d := range dangerSet {
			r.AllDangerousImports = append(r.AllDangerousImports, d)
		}
		sort.Strings(r.AllDangerousImports)
	}
	r.Note = r.note()
}

func (r *Result) note() string {
	switch {
	case r.PickleCount == 0:
		return "No embedded pickle found in this ZIP (no .pkl or PROTO-prefixed member) — nothing to disassemble. " +
			"Not a guarantee of safety; non-pickle model formats are out of scope. Nothing was executed."
	case r.Dangerous:
		return "DANGEROUS: an embedded pickle imports a known code-execution sink and runs code on torch.load / " +
			"pickle.load — do NOT load this model from an untrusted source. Disassembly only; nothing was executed."
	case r.ExecutesCode:
		return "An embedded pickle executes code on load (an import opcode plus an invocation opcode); the imported " +
			"callables may still be benign — review the entries. Disassembly only; nothing was executed."
	default:
		return fmt.Sprintf("Scanned %d embedded pickle(s); no code-execution opcodes found. Disassembly only; "+
			"absence of these opcodes is not a guarantee of safety. Nothing was executed.", r.PickleCount)
	}
}
