// keeloq.go — sub-GHz rolling-code KeeLoq cracker Specs.
//
// Three primitives wired here:
//
//   - keeloq_decrypt        — apply a known 64-bit key to a captured 32-bit
//                              ciphertext block. Useful for verifying a
//                              recovered manufacturer key.
//   - keeloq_dictionary     — try every public-literature manufacturer key
//                              against a (plaintext, ciphertext) pair.
//                              Fast (<1 ms total), zero-cost first attempt.
//   - keeloq_bruteforce     — CPU brute-force across a bounded keyspace.
//                              Realistic ceiling ~2^32 in minutes; full 2^64
//                              requires the GPU path (CudaKeeloq) which is
//                              wired separately as a federated MCP tool.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/xunholy/promptzero/internal/keeloq"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(keeloqDecryptSpec)
	Register(keeloqDictionarySpec)
	Register(keeloqBruteforceSpec)
}

var keeloqDecryptSpec = Spec{
	Name: "keeloq_decrypt",
	Description: "Decrypt a 32-bit KeeLoq ciphertext block using a known 64-bit key. Returns the recovered plaintext, the decoded button bits and counter (HCS-format), and an HCS-validity flag. Use after keeloq_bruteforce or keeloq_dictionary recover the key, to confirm.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"ciphertext_hex":{"type":"string","description":"32-bit ciphertext as hex (e.g. 0DEADBEE or DEADBEEF)"},
			"key_hex":{"type":"string","description":"64-bit key as hex (16 chars)"}
		},
		"required":["ciphertext_hex","key_hex"]
	}`),
	Required:  []string{"ciphertext_hex", "key_hex"},
	Risk:      risk.Low,
	Group:     GroupFlipperSubGHz,
	AgentOnly: false,
	Handler:   keeloqDecryptHandler,
}

var keeloqDictionarySpec = Spec{
	Name: "keeloq_dictionary",
	Description: "Test every public-literature KeeLoq manufacturer key against a (plaintext, ciphertext) pair. Returns the matching ManufacturerKey entry (vendor, description, source citation) when one fits; reports no-match otherwise. Sub-millisecond runtime — always run before keeloq_bruteforce.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"plaintext_hex":{"type":"string","description":"32-bit plaintext as hex (the suspected encoded button + counter, often constructed from a captured rolling code)"},
			"ciphertext_hex":{"type":"string","description":"32-bit ciphertext as hex (the captured rolling-code value)"}
		},
		"required":["plaintext_hex","ciphertext_hex"]
	}`),
	Required:  []string{"plaintext_hex", "ciphertext_hex"},
	Risk:      risk.Medium,
	Group:     GroupFlipperSubGHz,
	AgentOnly: false,
	Handler:   keeloqDictionaryHandler,
}

var keeloqBruteforceSpec = Spec{
	Name: "keeloq_bruteforce",
	Description: "CPU brute-force search across a 64-bit KeeLoq keyspace for a key that satisfies a known (plaintext, ciphertext) pair. Sharded across all CPU cores. Practical for ~2^32 ranges in minutes; for full 2^64 use the federated CudaKeeloq MCP tool. Returns the recovered key when found, or no-match when the range exhausts.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"plaintext_hex":{"type":"string","description":"32-bit plaintext (suspected) as hex"},
			"ciphertext_hex":{"type":"string","description":"32-bit captured ciphertext as hex"},
			"keyspace_min_hex":{"type":"string","description":"Lower bound of the search range as hex (default 0)"},
			"keyspace_max_hex":{"type":"string","description":"Upper bound (exclusive) as hex. Required for sane runtimes — pick a window like 1<<32."},
			"workers":{"type":"integer","description":"Goroutines (default = runtime.NumCPU)"},
			"timeout_seconds":{"type":"integer","description":"Search budget. Default 300s."}
		},
		"required":["plaintext_hex","ciphertext_hex","keyspace_max_hex"]
	}`),
	Required:  []string{"plaintext_hex", "ciphertext_hex", "keyspace_max_hex"},
	Risk:      risk.Critical,
	Group:     GroupFlipperSubGHz,
	AgentOnly: false,
	Handler:   keeloqBruteforceHandler,
}

func keeloqDecryptHandler(_ context.Context, _ *Deps, args map[string]any) (string, error) {
	cipher, err := parseHex32(str(args, "ciphertext_hex"))
	if err != nil {
		return "", fmt.Errorf("keeloq_decrypt: ciphertext_hex: %w", err)
	}
	key, err := parseHex64(str(args, "key_hex"))
	if err != nil {
		return "", fmt.Errorf("keeloq_decrypt: key_hex: %w", err)
	}
	plain := keeloq.Decrypt(cipher, key)
	out := map[string]any{
		"ciphertext":      fmt.Sprintf("%08X", cipher),
		"plaintext":       fmt.Sprintf("%08X", plain),
		"plaintext_dec":   plain,
		"key":             fmt.Sprintf("%016X", key),
		"hcs_valid":       keeloq.IsValidHCS(plain),
	}
	body, _ := json.Marshal(out)
	return string(body), nil
}

func keeloqDictionaryHandler(_ context.Context, _ *Deps, args map[string]any) (string, error) {
	plain, err := parseHex32(str(args, "plaintext_hex"))
	if err != nil {
		return "", fmt.Errorf("keeloq_dictionary: plaintext_hex: %w", err)
	}
	cipher, err := parseHex32(str(args, "ciphertext_hex"))
	if err != nil {
		return "", fmt.Errorf("keeloq_dictionary: ciphertext_hex: %w", err)
	}
	hit, ok := keeloq.TryDictionary(plain, cipher)
	if !ok {
		body, _ := json.Marshal(map[string]any{
			"matched":     false,
			"plaintext":   fmt.Sprintf("%08X", plain),
			"ciphertext":  fmt.Sprintf("%08X", cipher),
			"dict_size":   len(keeloq.Known),
			"hint":        "no public manufacturer key fits — escalate to keeloq_bruteforce or the CudaKeeloq MCP",
		})
		return string(body), nil
	}
	body, _ := json.Marshal(map[string]any{
		"matched":         true,
		"vendor":          hit.Vendor,
		"description":     hit.Description,
		"key":             fmt.Sprintf("%016X", hit.Key),
		"source":          hit.Source,
		"plaintext":       fmt.Sprintf("%08X", plain),
		"ciphertext":      fmt.Sprintf("%08X", cipher),
	})
	return string(body), nil
}

func keeloqBruteforceHandler(ctx context.Context, _ *Deps, args map[string]any) (string, error) {
	plain, err := parseHex32(str(args, "plaintext_hex"))
	if err != nil {
		return "", fmt.Errorf("keeloq_bruteforce: plaintext_hex: %w", err)
	}
	cipher, err := parseHex32(str(args, "ciphertext_hex"))
	if err != nil {
		return "", fmt.Errorf("keeloq_bruteforce: ciphertext_hex: %w", err)
	}
	maxStr := str(args, "keyspace_max_hex")
	if maxStr == "" {
		return "", fmt.Errorf("keeloq_bruteforce: keyspace_max_hex is required")
	}
	max, err := parseHex64(maxStr)
	if err != nil {
		return "", fmt.Errorf("keeloq_bruteforce: keyspace_max_hex: %w", err)
	}
	var min uint64
	if m := str(args, "keyspace_min_hex"); m != "" {
		min, err = parseHex64(m)
		if err != nil {
			return "", fmt.Errorf("keeloq_bruteforce: keyspace_min_hex: %w", err)
		}
	}
	if max <= min {
		return "", fmt.Errorf("keeloq_bruteforce: empty range (max <= min)")
	}

	timeout := time.Duration(intOr(args, "timeout_seconds", 300)) * time.Second
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cfg := keeloq.BruteForceConfig{
		KnownPlaintext:  plain,
		KnownCiphertext: cipher,
		KeyspaceMin:     min,
		KeyspaceMax:     max,
		Workers:         intOr(args, "workers", 0),
	}

	start := time.Now()
	key, found, err := keeloq.BruteForce(runCtx, cfg)
	elapsed := time.Since(start)

	out := map[string]any{
		"keyspace_size": max - min,
		"workers":       cfg.Workers,
		"elapsed_ms":    elapsed.Milliseconds(),
	}
	if err != nil {
		out["status"] = "cancelled_or_error"
		out["error"] = err.Error()
		body, _ := json.Marshal(out)
		return string(body), err
	}
	if !found {
		out["status"] = "exhausted"
		out["matched"] = false
		body, _ := json.Marshal(out)
		return string(body), nil
	}
	out["status"] = "found"
	out["matched"] = true
	out["key"] = fmt.Sprintf("%016X", key)
	body, _ := json.Marshal(out)
	return string(body), nil
}

func parseHex32(s string) (uint32, error) {
	s = trimHexPrefix(s)
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return 0, err
	}
	return uint32(v), nil
}

func parseHex64(s string) (uint64, error) {
	return strconv.ParseUint(trimHexPrefix(s), 16, 64)
}

func trimHexPrefix(s string) string {
	if len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X") {
		return s[2:]
	}
	return s
}
