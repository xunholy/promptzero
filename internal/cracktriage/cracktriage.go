// Package cracktriage is the unified front-end over the crack-triage decoders:
// it detects an encrypted artifact by its magic bytes and routes to the matching
// in-tree decoder (KeePass .kdbx, encrypted ZIP, encrypted PDF), so an operator
// (or the agent) with a loot file of unknown type gets a single answer to "what
// is this, and which hashcat mode cracks it?".
//
// It is the crack-triage analogue of the project's secret_identify / hash_identify
// routers: detection is by the unambiguous file-format magic, dispatch is to the
// already-reference-anchored decoders, and nothing is guessed.
//
// No confidently-wrong output: a file that is not a recognised encrypted-artifact
// type is rejected (never mis-routed); each decoder keeps its own
// "parameters only — no crack/decrypt/hash" guarantee.
//
// Wrap-vs-native: native orchestration over internal/kdbx, internal/ziptriage,
// and internal/pdftriage; stdlib only, no new go.mod dependency.
package cracktriage

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/xunholy/promptzero/internal/kdbx"
	"github.com/xunholy/promptzero/internal/pdftriage"
	"github.com/xunholy/promptzero/internal/ziptriage"
)

// Result wraps the detected artifact type and the routed decoder's output.
type Result struct {
	// Artifact is the detected type: "KeePass KDBX", "ZIP archive", or "PDF document".
	Artifact string `json:"artifact"`
	// HashcatMode is the mode the routed decoder reports (0 when not crackable,
	// e.g. an unencrypted file).
	HashcatMode int    `json:"hashcat_mode"`
	JohnTool    string `json:"john_tool,omitempty"`
	// Detail is the full result from the routed decoder.
	Detail any    `json:"detail"`
	Note   string `json:"note"`
}

const (
	kdbxSig1 = 0x9AA2D903
	kdbxSig2 = 0xB54BFB67
)

// Detect returns the artifact kind ("kdbx", "zip", "pdf") from the leading magic
// bytes, or "" when none match.
func Detect(raw []byte) string {
	switch {
	case len(raw) >= 8 &&
		binary.LittleEndian.Uint32(raw[0:4]) == kdbxSig1 &&
		binary.LittleEndian.Uint32(raw[4:8]) == kdbxSig2:
		return "kdbx"
	case bytes.HasPrefix(raw, []byte("PK\x03\x04")),
		bytes.HasPrefix(raw, []byte("PK\x05\x06")),
		bytes.HasPrefix(raw, []byte("PK\x07\x08")):
		return "zip"
	case bytes.HasPrefix(raw, []byte("%PDF-")):
		return "pdf"
	default:
		return ""
	}
}

// Decode detects the artifact type and routes to the matching crack-triage
// decoder, wrapping its result.
func Decode(raw []byte) (*Result, error) {
	res := &Result{
		Note: "Detected by file magic and routed to the matching crack-triage decoder; parameters only — " +
			"nothing is cracked, decrypted, or emitted as a john/hashcat hash.",
	}
	switch Detect(raw) {
	case "kdbx":
		d, err := kdbx.Decode(raw)
		if err != nil {
			return nil, err
		}
		res.Artifact, res.HashcatMode, res.JohnTool, res.Detail = "KeePass KDBX", d.HashcatMode, d.JohnTool, d
	case "zip":
		d, err := ziptriage.Decode(raw)
		if err != nil {
			return nil, err
		}
		res.Artifact, res.HashcatMode, res.JohnTool, res.Detail = "ZIP archive", d.HashcatMode, d.JohnTool, d
	case "pdf":
		d, err := pdftriage.Decode(raw)
		if err != nil {
			return nil, err
		}
		res.Artifact, res.HashcatMode, res.JohnTool, res.Detail = "PDF document", d.HashcatMode, d.JohnTool, d
	default:
		return nil, fmt.Errorf("cracktriage: unrecognised artifact (not a KeePass .kdbx, ZIP, or PDF)")
	}
	return res, nil
}
