// subghz_debruijn.go — host-side de Bruijn brute-sequence generator Spec,
// delegating to internal/debruijn.
//
// Wrap-vs-native: native — a de Bruijn sequence is a classic combinatorial
// object from a few lines of the standard FKM algorithm; its pentest use is
// Samy Kamkar's OpenSesame optimal fixed-code brute. Generation only (emits
// a bit stream, transmits nothing). Complements subghz_bruteforce_generate
// (a naive sequential sweep) with the optimal sliding-window sequence.

package tools

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/debruijn"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(subghzDeBruijnSpec)
}

// maxDeBruijnBitString is the largest sequence length for which the full
// 0/1 string is included in the response (the hex-packed form is always
// returned).
const maxDeBruijnBitString = 8192

var subghzDeBruijnSpec = Spec{
	Name: "subghz_debruijn",
	Description: "Generate the optimal de Bruijn brute-force bit sequence for an n-bit FIXED-code " +
		"(non-rolling) receiver — Samy Kamkar's OpenSesame technique. A fixed-code receiver that " +
		"accepts a continuous bit stream is brute-forced by sliding an n-bit window across a de Bruijn " +
		"sequence B(2,n): all 2^n codes are exercised in 2^n + n - 1 transmitted bits instead of the " +
		"2^n * n bits a naive per-code sweep sends — an ~n-fold speedup. subghz_bruteforce_generate " +
		"emits the naive sequential sweep; this is the optimal-sequence complement.\n\n" +
		"Returns: the sequence as hex-packed bytes (MSB-first) and, for sequences up to 8192 bits, the " +
		"raw 0/1 string; plus codes_covered (2^n), the sequence length, the naive length, and the " +
		"speedup factor. The defining property — every length-n window appears exactly once — makes " +
		"the output self-verifiable.\n\n" +
		"Applies to continuous-bitstream fixed-code receivers (no inter-frame gap); rolling-code and " +
		"sync-gapped protocols are out of scope. Generation only — it produces the bit stream and " +
		"transmits nothing (pair with an OOK encode/TX stage), so it is Low risk. n is capped at 20 " +
		"(~1M bits) to keep the response sane; a 24-bit code's sequence is inherently 16 Mbit and must " +
		"be streamed externally. Wrap-vs-native: native — the public FKM algorithm, no dependency, no " +
		"hardware.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"bits":{"type":"integer","description":"Code width n (1..20). The sequence covers all 2^n n-bit codes."}
		},
		"required":["bits"]
	}`),
	Required:  []string{"bits"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   subghzDeBruijnHandler,
}

func subghzDeBruijnHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	n := intOf(p["bits"])
	if n < 1 {
		return "", fmt.Errorf("subghz_debruijn: 'bits' is required (1..%d)", debruijn.MaxBits)
	}
	lin, err := debruijn.Linear(n)
	if err != nil {
		return "", fmt.Errorf("subghz_debruijn: %w", err)
	}

	// Pack bits MSB-first into bytes.
	packed := make([]byte, (len(lin)+7)/8)
	for i, b := range lin {
		if b != 0 {
			packed[i/8] |= 1 << uint(7-(i%8))
		}
	}

	codes := 1 << uint(n)
	naive := codes * n
	out := struct {
		Bits         int     `json:"bits"`
		CodesCovered int     `json:"codes_covered"`
		SequenceBits int     `json:"sequence_bits"`
		NaiveBits    int     `json:"naive_bits"`
		Speedup      float64 `json:"speedup"`
		Hex          string  `json:"hex"`
		BitString    string  `json:"bit_string,omitempty"`
		Note         string  `json:"note,omitempty"`
	}{
		Bits:         n,
		CodesCovered: codes,
		SequenceBits: len(lin),
		NaiveBits:    naive,
		Speedup:      float64(naive) / float64(len(lin)),
		Hex:          strings.ToUpper(hex.EncodeToString(packed)),
	}
	if len(lin) <= maxDeBruijnBitString {
		sb := make([]byte, len(lin))
		for i, b := range lin {
			sb[i] = '0' + b
		}
		out.BitString = string(sb)
	} else {
		out.Note = fmt.Sprintf("bit_string omitted (%d bits > %d); use the hex-packed form (MSB-first)", len(lin), maxDeBruijnBitString)
	}

	body, _ := json.MarshalIndent(out, "", "  ")
	return string(body), nil
}
