// checksum_compute.go — host-side simple-checksum compute / identify Spec,
// delegating to internal/checksum.
//
// Wrap-vs-native: native — the simple frame checksums (modular sum, XOR/LRC,
// Modbus LRC, Fletcher) are one-liners. It is the companion to crc_compute in
// the protocol-RE toolkit: when a captured frame's trailer is NOT a CRC — the
// common case for cheap RF remotes, sensors, and simple serial devices — this
// finds which simple checksum reproduces it. Offline compute, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/checksum"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(checksumComputeSpec)
}

var checksumComputeSpec = Spec{
	Name: "checksum_compute",
	Description: "Compute or identify a simple (non-CRC) frame checksum — the companion to crc_compute " +
		"in the protocol reverse-engineering toolkit. Cheap RF remotes, sensors, and simple serial " +
		"devices often end a frame with a plain sum or XOR rather than a CRC, which crc_compute's identify " +
		"will miss; this covers that case.\n\n" +
		"**compute** (default): give **data** (hex) and optionally an **algo** name; omit it or pass " +
		"'all' to compute every algorithm. **identify**: also give **expected** (the observed checksum as " +
		"hex) and the tool reports which algorithm(s) reproduce it over the data. An empty identify " +
		"result is an honest 'no simple checksum matches' (then try crc_compute for the CRC families).\n\n" +
		"Algorithms: SUM-8, SUM-16, XOR-8 (LRC), LRC-MODBUS (two's-complement sum), FLETCHER-16, " +
		"FLETCHER-32. The sum/XOR/LRC algorithms are definitional; the Fletcher checksums are verified " +
		"in-tree against their published reference vectors (Fletcher-16 of 'abcdefgh' = 0x0627, " +
		"Fletcher-32 of 'abcde' = 0xF04FC729). Offline compute — reads hex, transmits nothing, so it is " +
		"Low risk. Wrap-vs-native: native — running sum/XOR over a byte slice.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"data":{"type":"string","description":"Input bytes as hex. Separators tolerated."},
			"algo":{"type":"string","description":"Algorithm name (e.g. SUM-8, FLETCHER-16), or 'all' / omitted for every algorithm. Ignored in identify mode."},
			"expected":{"type":"string","description":"Optional: an observed checksum as hex. When set, switches to identify mode."}
		},
		"required":["data"]
	}`),
	Required:  []string{"data"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   checksumComputeHandler,
}

func checksumComputeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	data, err := decodeLooseHex(str(p, "data"))
	if err != nil {
		return "", fmt.Errorf("checksum_compute: data: %w", err)
	}

	if exp := strings.TrimSpace(str(p, "expected")); exp != "" {
		ev, err := parseHexUint(exp)
		if err != nil {
			return "", fmt.Errorf("checksum_compute: expected: %w", err)
		}
		matches := checksum.Identify(data, ev)
		out, _ := json.MarshalIndent(map[string]any{
			"mode":     "identify",
			"expected": exp,
			"matches":  matches,
			"count":    len(matches),
		}, "", "  ")
		return string(out), nil
	}

	algo := strings.TrimSpace(str(p, "algo"))
	type result struct {
		Algo     string `json:"algo"`
		Checksum string `json:"checksum"`
	}
	var results []result
	if algo == "" || strings.EqualFold(algo, "all") {
		for _, a := range checksum.Algos {
			results = append(results, result{a.Name, a.Format(a.Compute(data))})
		}
	} else {
		a, ok := checksum.Lookup(algo)
		if !ok {
			return "", fmt.Errorf("checksum_compute: unknown algo %q (pass 'all' to list every algorithm)", algo)
		}
		results = append(results, result{a.Name, a.Format(a.Compute(data))})
	}
	out, _ := json.MarshalIndent(map[string]any{
		"mode":    "compute",
		"results": results,
	}, "", "  ")
	return string(out), nil
}
