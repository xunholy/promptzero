// mifare.go — Mifare Classic offline-cracker Specs.
//
// v0.6 status:
//
//   • mfkey32_recover:  REAL — backed by internal/crypto1.RecoverWithRange.
//                        Default 16-bit search range (~70 ms); operators
//                        bump search_range_bits up to 48 for full-keyspace.
//
//   • mfoc_attack:      stub — points operators at the federated
//                        pm3 MCP (mplogas/pm3-mcp). The libnfc-based
//                        nested attack requires a live NFC reader,
//                        which the Flipper's NFC stack doesn't expose
//                        in libnfc shape. When an operator has captured
//                        nested-auth nonces offline, the algorithm
//                        reduces to the same crypto1 LFSR rollback as
//                        mfkey32 — wire through mfkey32_recover with
//                        the appropriate nonce tuples.
//
//   • mfcuk_attack:     stub — points operators at pm3-mcp federation.
//                        Darkside requires the cipher's parity-bit leak
//                        captured during malformed authentications;
//                        the Flipper firmware does not expose this
//                        surface. Pure-Go offline reimpl tracked for
//                        v0.6.1.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/xunholy/promptzero/internal/crypto1"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(mfocAttackSpec)
	Register(mfcukAttackSpec)
	Register(mfkey32RecoverSpec)
}

// federatedFallbackMsg explains the v0.6 redirect for live-NFC attacks.
// mfoc/mfcuk return this with an error so the agent's reflexion path
// treats the call as failure-with-redirect.
const federatedFallbackMsg = "Use the federated Proxmark3 MCP (configure mplogas/pm3-mcp under mcp_clients in config.yaml) — the live-NFC nested / darkside attacks require a real reader. " +
	"For OFFLINE recovery from already-captured (uid, nt, nr, ar) tuples, use mfkey32_recover with appropriate inputs."

func federatedFallback(specName string) Handler {
	return func(_ context.Context, _ *Deps, _ map[string]any) (string, error) {
		out, _ := json.Marshal(map[string]string{
			"status":  "live_nfc_required",
			"spec":    specName,
			"message": federatedFallbackMsg,
		})
		return string(out), fmt.Errorf("%s: %s", specName, federatedFallbackMsg)
	}
}

// --- mfoc_attack -------------------------------------------------------

var mfocAttackSpec = Spec{
	Name:        "mfoc_attack",
	Description: "Mifare Classic nested attack. The classical libnfc mfoc requires a live NFC reader to authenticate against unknown sectors with a known key and harvest the encrypted nonces. PromptZero's Flipper backend does not expose libnfc-shaped APIs over USB CLI, so this Spec is a redirect: federate mplogas/pm3-mcp (Proxmark3 iceman) for the live-card attack, OR use mfkey32_recover with already-captured nested-auth nonce tuples for the offline portion.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"uid_hex":{"type":"string","description":"Card UID as hex (4 or 7 bytes). Documentation only — handler returns a federated-fallback message."},
			"known_key_hex":{"type":"string","description":"At least one sector key already known, 6 bytes hex. Documentation only."},
			"known_sector":{"type":"integer","description":"Sector number whose key is provided in known_key_hex. Documentation only."},
			"key_type":{"type":"string","description":"Key type for known_key (A or B). Documentation only."}
		},
		"required":["uid_hex","known_key_hex","known_sector","key_type"]
	}`),
	Required:  []string{"uid_hex", "known_key_hex", "known_sector", "key_type"},
	Risk:      risk.High,
	Group:     GroupFlipperNFC,
	AgentOnly: false,
	Handler:   federatedFallback("mfoc_attack"),
}

// --- mfcuk_attack ------------------------------------------------------

var mfcukAttackSpec = Spec{
	Name:        "mfcuk_attack",
	Description: "Mifare Classic darkside attack. Recovers the first sector key without prior knowledge by exploiting the parity-bit leak in malformed authentications. Requires a live NFC reader and a misbehaving libnfc transaction loop — the Flipper's NFC stack does not expose this. Federate Proxmark3 (mplogas/pm3-mcp) for the live attack. Pure-Go offline reimpl tracked for v0.6.1.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"uid_hex":{"type":"string","description":"Card UID as hex. Documentation only — handler returns a federated-fallback message."}
		},
		"required":["uid_hex"]
	}`),
	Required:  []string{"uid_hex"},
	Risk:      risk.High,
	Group:     GroupFlipperNFC,
	AgentOnly: false,
	Handler:   federatedFallback("mfcuk_attack"),
}

// --- mfkey32_recover ---------------------------------------------------

var mfkey32RecoverSpec = Spec{
	Name: "mfkey32_recover",
	Description: "Recover a Mifare Classic 48-bit sector key from sniffed reader-authentication exchanges. Pure-Go via internal/crypto1 — closed-loop verified, no card I/O. Provide either ONE captured nonce repeated (the mfkey32 v1 case where the reader emitted the same nT twice — pass nt_hex + two nR/aR pairs) or TWO different captures (mfkey32 v2 case — pass nt0_hex/nt1_hex + matching nR/aR pairs). Default search bounds the keyspace to 16 bits (~70 ms); raise search_range_bits up to 48 for full-keyspace at hours of CPU time.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"uid_hex":{"type":"string","description":"Card UID as 4-byte hex (e.g. CAFEBABE)."},
			"nt_hex":{"type":"string","description":"Card nonce as 4-byte hex. Used for both captures when nt0_hex/nt1_hex are not provided (mfkey32 v1)."},
			"nt0_hex":{"type":"string","description":"Tag nonce of capture 0 (mfkey32 v2). Falls back to nt_hex when omitted."},
			"nr0_hex":{"type":"string","description":"Reader nonce of capture 0 as 4-byte hex."},
			"ar0_hex":{"type":"string","description":"Encrypted reader auth response of capture 0 as 4-byte hex."},
			"nt1_hex":{"type":"string","description":"Tag nonce of capture 1 (mfkey32 v2). Falls back to nt_hex when omitted."},
			"nr1_hex":{"type":"string","description":"Reader nonce of capture 1 as 4-byte hex."},
			"ar1_hex":{"type":"string","description":"Encrypted reader auth response of capture 1 as 4-byte hex."},
			"search_range_bits":{"type":"integer","description":"Number of high bits to search. 16 (default) ~70ms, 24 ~18s, 32 ~5min, 48 hours. Capped at 48."},
			"timeout_seconds":{"type":"integer","description":"Hard deadline. Default 300s. Returns a deadline-exceeded result if tripped before completion."}
		},
		"required":["uid_hex","nr0_hex","ar0_hex","nr1_hex","ar1_hex"]
	}`),
	Required:  []string{"uid_hex", "nr0_hex", "ar0_hex", "nr1_hex", "ar1_hex"},
	Risk:      risk.High,
	Group:     GroupFlipperNFC,
	AgentOnly: false,
	Handler:   mfkey32RecoverHandler,
}

func mfkey32RecoverHandler(ctx context.Context, _ *Deps, args map[string]any) (string, error) {
	uid, err := parseMfHex32(str(args, "uid_hex"))
	if err != nil {
		return "", fmt.Errorf("mfkey32_recover: uid_hex: %w", err)
	}

	// nT resolution: nt0_hex/nt1_hex win over nt_hex.
	nt0Str := str(args, "nt0_hex")
	if nt0Str == "" {
		nt0Str = str(args, "nt_hex")
	}
	nt1Str := str(args, "nt1_hex")
	if nt1Str == "" {
		nt1Str = str(args, "nt_hex")
	}
	if nt0Str == "" || nt1Str == "" {
		return "", fmt.Errorf("mfkey32_recover: provide nt_hex (v1) or both nt0_hex+nt1_hex (v2)")
	}
	nt0, err := parseMfHex32(nt0Str)
	if err != nil {
		return "", fmt.Errorf("mfkey32_recover: nt0: %w", err)
	}
	nt1, err := parseMfHex32(nt1Str)
	if err != nil {
		return "", fmt.Errorf("mfkey32_recover: nt1: %w", err)
	}

	nr0, err := parseMfHex32(str(args, "nr0_hex"))
	if err != nil {
		return "", fmt.Errorf("mfkey32_recover: nr0: %w", err)
	}
	ar0, err := parseMfHex32(str(args, "ar0_hex"))
	if err != nil {
		return "", fmt.Errorf("mfkey32_recover: ar0: %w", err)
	}
	nr1, err := parseMfHex32(str(args, "nr1_hex"))
	if err != nil {
		return "", fmt.Errorf("mfkey32_recover: nr1: %w", err)
	}
	ar1, err := parseMfHex32(str(args, "ar1_hex"))
	if err != nil {
		return "", fmt.Errorf("mfkey32_recover: ar1: %w", err)
	}

	rangeBits := intOr(args, "search_range_bits", 16)
	if rangeBits < 0 {
		rangeBits = 0
	}
	if rangeBits > 48 {
		rangeBits = 48
	}
	// hi32 enumerates the high 32 bits of the 48-bit key. range_bits N
	// means hi32 range [0, 1<<max(0, N-16)).
	//   range_bits=16 → [0,1)        — 16-bit keys (~70 ms)
	//   range_bits=24 → [0,1<<8)     — 24-bit keys (~18 s)
	//   range_bits=32 → [0,1<<16)    — 32-bit keys (~5 min)
	//   range_bits=40 → [0,1<<24)    — 40-bit keys (~16 h)
	//   range_bits=48 → [0,1<<32)    — full keyspace (days)
	hiCap := uint64(1)
	if rangeBits > 16 {
		hiCap = uint64(1) << uint(rangeBits-16)
	}

	timeout := time.Duration(intOr(args, "timeout_seconds", 300)) * time.Second
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	resCh := make(chan recoverResult, 1)
	start := time.Now()
	go func() {
		key, err := crypto1.RecoverWithRange(uid, nt0, nr0, ar0, nt1, nr1, ar1, 0, hiCap)
		resCh <- recoverResult{key: key, err: err}
	}()

	select {
	case <-runCtx.Done():
		body, _ := json.Marshal(map[string]any{
			"status":            "deadline_exceeded",
			"matched":           false,
			"search_range_bits": rangeBits,
			"elapsed_ms":        time.Since(start).Milliseconds(),
			"hint":              "raise timeout_seconds, lower search_range_bits, or federate Hashcat-MCP for GPU-class throughput",
		})
		return string(body), runCtx.Err()
	case res := <-resCh:
		elapsed := time.Since(start)
		if res.err != nil {
			body, _ := json.Marshal(map[string]any{
				"status":            "exhausted",
				"matched":           false,
				"search_range_bits": rangeBits,
				"elapsed_ms":        elapsed.Milliseconds(),
				"error":             res.err.Error(),
				"hint":              "raise search_range_bits or federate Hashcat-MCP",
			})
			return string(body), nil
		}
		body, _ := json.Marshal(map[string]any{
			"status":            "found",
			"matched":           true,
			"key":               fmt.Sprintf("%012X", res.key),
			"search_range_bits": rangeBits,
			"elapsed_ms":        elapsed.Milliseconds(),
		})
		return string(body), nil
	}
}

type recoverResult struct {
	key uint64
	err error
}

// parseMfHex32 parses a 4-byte hex string (with or without 0x prefix)
// into a uint32.
func parseMfHex32(s string) (uint32, error) {
	if s == "" {
		return 0, fmt.Errorf("empty hex value")
	}
	s = trimHexPrefix(s)
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return 0, err
	}
	return uint32(v), nil
}
