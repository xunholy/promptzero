// mifare.go — Mifare Classic offline-cracker Specs.
//
// v0.6 status:
//
//   • mfkey32_recover:  REAL — backed by internal/crypto1.RecoverWithRange.
//                        Default 16-bit search range (~70 ms); operators
//                        bump search_range_bits up to 48 for full-keyspace.
//
//   • mfoc_attack:      REAL — offline nested-authentication key recovery
//                        backed by internal/crypto1.RecoverNestedWithRange.
//                        Operator provides pre-captured nested-auth nonces
//                        (at least 2 NestedAttempts per NestedCapture).
//                        For live-NFC attacks requiring a real reader,
//                        federate mplogas/pm3-mcp.
//
//   • mfcuk_attack:     REAL — offline darkside key recovery backed by
//                        internal/crypto1.RecoverDarksideWithRange.
//                        Operator provides pre-captured malformed-auth
//                        (NR, parity) pairs — 8+ recommended for reliability.
//                        For live-NFC capture, federate mplogas/pm3-mcp.

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
// Preserved for documentation; the mfoc/mfcuk handlers now run offline.
const federatedFallbackMsg = "Use the federated Proxmark3 MCP (configure mplogas/pm3-mcp under mcp_clients in config.yaml) — the live-NFC nested / darkside attacks require a real reader. " +
	"For OFFLINE recovery from already-captured (uid, nt, nr, ar) tuples, use mfkey32_recover with appropriate inputs."

// --- mfoc_attack -------------------------------------------------------

var mfocAttackSpec = Spec{
	Name: "mfoc_attack",
	Description: "Mifare Classic offline nested-authentication key recovery (mfoc algorithm). " +
		"Provide pre-captured nested-auth nonces: at least 2 NestedAttempts, each containing " +
		"the known-sector re-authentication nonces (known_nt_hex, known_nr_hex) and the " +
		"nested target-sector capture (nt_enc_hex = encrypted target nT, nr_hex = reader nonce, " +
		"ar_hex = tag aR response). The cipher is walked from the known key through the known-sector " +
		"auth to decrypt the nested nT, yielding (uid, nt, nr, ar) tuples for mfkey32 recovery. " +
		"Default search covers 16-bit keys (~70 ms); raise search_range_bits for wider keyspaces. " +
		"For live-NFC capture requiring a real reader, federate mplogas/pm3-mcp.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"uid_hex":{"type":"string","description":"Card UID as 4-byte hex (e.g. CAFEBABE)."},
			"known_key_hex":{"type":"string","description":"Known sector key as 6-byte hex (e.g. A0A1A2A3A4A5)."},
			"attempts":{"type":"array","description":"Array of nested-auth attempt objects. At least 2 required.","items":{
				"type":"object",
				"properties":{
					"known_nt_hex":{"type":"string","description":"Plain tag nonce from the known-sector re-auth for this attempt (4-byte hex)."},
					"known_nr_hex":{"type":"string","description":"Plain reader nonce sent to the known sector (4-byte hex)."},
					"nt_enc_hex":{"type":"string","description":"Encrypted nested target-sector nT as observed on wire (4-byte hex)."},
					"nr_hex":{"type":"string","description":"Plain reader nonce sent to the target sector (4-byte hex)."},
					"ar_hex":{"type":"string","description":"Encrypted tag aR response for the target sector (4-byte hex)."}
				},
				"required":["known_nt_hex","known_nr_hex","nt_enc_hex","nr_hex","ar_hex"]
			}},
			"search_range_bits":{"type":"integer","description":"Number of high bits to search. 16 (default) ~70ms, 24 ~18s, 32 ~5min, 48 hours. Capped at 48."},
			"timeout_seconds":{"type":"integer","description":"Hard deadline. Default 300s."}
		},
		"required":["uid_hex","known_key_hex","attempts"]
	}`),
	Required:  []string{"uid_hex", "known_key_hex", "attempts"},
	Risk:      risk.High,
	Group:     GroupFlipperNFC,
	AgentOnly: false,
	Handler:   mfocAttackHandler,
}

func mfocAttackHandler(ctx context.Context, _ *Deps, args map[string]any) (string, error) {
	uid, err := parseMfHex32(str(args, "uid_hex"))
	if err != nil {
		return "", fmt.Errorf("mfoc_attack: uid_hex: %w", err)
	}

	knownKey, err := parseMfHex48(str(args, "known_key_hex"))
	if err != nil {
		return "", fmt.Errorf("mfoc_attack: known_key_hex: %w", err)
	}

	rawAttempts, ok := args["attempts"]
	if !ok {
		return "", fmt.Errorf("mfoc_attack: attempts field is required")
	}
	attemptsSlice, ok := rawAttempts.([]any)
	if !ok {
		return "", fmt.Errorf("mfoc_attack: attempts must be an array")
	}
	if len(attemptsSlice) < 2 {
		return "", fmt.Errorf("mfoc_attack: at least 2 attempts are required")
	}

	attempts := make([]crypto1.NestedAttempt, len(attemptsSlice))
	for i, raw := range attemptsSlice {
		m, ok := raw.(map[string]any)
		if !ok {
			return "", fmt.Errorf("mfoc_attack: attempts[%d] is not an object", i)
		}

		knownNT, err := parseMfHex32(strFromMap(m, "known_nt_hex"))
		if err != nil {
			return "", fmt.Errorf("mfoc_attack: attempts[%d].known_nt_hex: %w", i, err)
		}
		knownNR, err := parseMfHex32(strFromMap(m, "known_nr_hex"))
		if err != nil {
			return "", fmt.Errorf("mfoc_attack: attempts[%d].known_nr_hex: %w", i, err)
		}
		ntEnc, err := parseMfHex32(strFromMap(m, "nt_enc_hex"))
		if err != nil {
			return "", fmt.Errorf("mfoc_attack: attempts[%d].nt_enc_hex: %w", i, err)
		}
		nr, err := parseMfHex32(strFromMap(m, "nr_hex"))
		if err != nil {
			return "", fmt.Errorf("mfoc_attack: attempts[%d].nr_hex: %w", i, err)
		}
		ar, err := parseMfHex32(strFromMap(m, "ar_hex"))
		if err != nil {
			return "", fmt.Errorf("mfoc_attack: attempts[%d].ar_hex: %w", i, err)
		}

		attempts[i] = crypto1.NestedAttempt{
			KnownNT: knownNT,
			KnownNR: knownNR,
			NTEnc:   ntEnc,
			NR:      nr,
			AR:      ar,
		}
	}

	rangeBits := intOr(args, "search_range_bits", 16)
	if rangeBits < 0 {
		rangeBits = 0
	}
	if rangeBits > 48 {
		rangeBits = 48
	}
	hiCap := uint64(1)
	if rangeBits > 16 {
		hiCap = uint64(1) << uint(rangeBits-16)
	}

	cap := crypto1.NestedCapture{
		UID:      uid,
		KnownKey: knownKey,
		Attempts: attempts,
	}

	timeout := time.Duration(intOr(args, "timeout_seconds", 300)) * time.Second
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	resCh := make(chan recoverResult, 1)
	start := time.Now()
	go func() {
		key, err := crypto1.RecoverNestedWithRange(cap, 0, hiCap)
		resCh <- recoverResult{key: key, err: err}
	}()

	select {
	case <-runCtx.Done():
		body, _ := json.Marshal(map[string]any{
			"status":            "deadline_exceeded",
			"matched":           false,
			"search_range_bits": rangeBits,
			"elapsed_ms":        time.Since(start).Milliseconds(),
			"hint":              "raise timeout_seconds or lower search_range_bits",
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
				"hint":              "raise search_range_bits or federate mplogas/pm3-mcp for live capture",
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

// --- mfcuk_attack ------------------------------------------------------

var mfcukAttackSpec = Spec{
	Name: "mfcuk_attack",
	Description: "Mifare Classic offline darkside key recovery (mfcuk algorithm). " +
		"Provide pre-captured malformed-authentication observations: a card UID, the card's " +
		"plain nT, and at least 8 (NR, parity) pairs where each NR had a deliberate parity " +
		"error in the first byte. Each pair yields 4 keystream bits (enc_NACK XOR 0x5); " +
		"256 pairs with distinct NR low bytes uniquely identify the key in the 16-bit range. " +
		"Default search covers 16-bit keys (sub-millisecond); raise search_range_bits for wider " +
		"keyspaces. For live-NFC capture using malformed auth frames, federate mplogas/pm3-mcp.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"uid_hex":{"type":"string","description":"Card UID as 4-byte hex (e.g. CAFEBABE)."},
			"nt_hex":{"type":"string","description":"Plain tag nonce as 4-byte hex."},
			"pairs":{"type":"array","description":"Array of (NR, parity) observation objects. 8+ recommended; 256 with distinct NR low bytes guarantees unique recovery.","items":{
				"type":"object",
				"properties":{
					"nr_hex":{"type":"string","description":"Plain reader nonce as 4-byte hex."},
					"parity":{"type":"integer","description":"4-bit encrypted NACK nibble observed on wire (enc_NACK = plain_NACK XOR keystream)."}
				},
				"required":["nr_hex","parity"]
			}},
			"search_range_bits":{"type":"integer","description":"Number of high bits to search. 16 (default) sub-ms, 24 ~18s, 32 ~5min, 48 hours. Capped at 48."},
			"timeout_seconds":{"type":"integer","description":"Hard deadline. Default 300s."}
		},
		"required":["uid_hex","nt_hex","pairs"]
	}`),
	Required:  []string{"uid_hex", "nt_hex", "pairs"},
	Risk:      risk.High,
	Group:     GroupFlipperNFC,
	AgentOnly: false,
	Handler:   mfcukAttackHandler,
}

func mfcukAttackHandler(ctx context.Context, _ *Deps, args map[string]any) (string, error) {
	uid, err := parseMfHex32(str(args, "uid_hex"))
	if err != nil {
		return "", fmt.Errorf("mfcuk_attack: uid_hex: %w", err)
	}

	nt, err := parseMfHex32(str(args, "nt_hex"))
	if err != nil {
		return "", fmt.Errorf("mfcuk_attack: nt_hex: %w", err)
	}

	rawPairs, ok := args["pairs"]
	if !ok {
		return "", fmt.Errorf("mfcuk_attack: pairs field is required")
	}
	pairsSlice, ok := rawPairs.([]any)
	if !ok {
		return "", fmt.Errorf("mfcuk_attack: pairs must be an array")
	}
	if len(pairsSlice) == 0 {
		return "", fmt.Errorf("mfcuk_attack: at least 1 pair is required")
	}

	pairs := make([]crypto1.DarksidePair, len(pairsSlice))
	for i, raw := range pairsSlice {
		m, ok := raw.(map[string]any)
		if !ok {
			return "", fmt.Errorf("mfcuk_attack: pairs[%d] is not an object", i)
		}

		nr, err := parseMfHex32(strFromMap(m, "nr_hex"))
		if err != nil {
			return "", fmt.Errorf("mfcuk_attack: pairs[%d].nr_hex: %w", i, err)
		}
		parity := uint8(intOr(m, "parity", 0) & 0xF)

		pairs[i] = crypto1.DarksidePair{
			NR:     nr,
			Parity: parity,
		}
	}

	rangeBits := intOr(args, "search_range_bits", 16)
	if rangeBits < 0 {
		rangeBits = 0
	}
	if rangeBits > 48 {
		rangeBits = 48
	}
	hiCap := uint64(1)
	if rangeBits > 16 {
		hiCap = uint64(1) << uint(rangeBits-16)
	}

	cap := crypto1.DarksideCapture{
		UID:   uid,
		NT:    nt,
		NRArs: pairs,
	}

	timeout := time.Duration(intOr(args, "timeout_seconds", 300)) * time.Second
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	resCh := make(chan recoverResult, 1)
	start := time.Now()
	go func() {
		key, err := crypto1.RecoverDarksideWithRange(cap, 0, hiCap)
		resCh <- recoverResult{key: key, err: err}
	}()

	select {
	case <-runCtx.Done():
		body, _ := json.Marshal(map[string]any{
			"status":            "deadline_exceeded",
			"matched":           false,
			"search_range_bits": rangeBits,
			"elapsed_ms":        time.Since(start).Milliseconds(),
			"hint":              "raise timeout_seconds or lower search_range_bits",
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
				"hint":              "add more pairs with distinct NR low bytes, raise search_range_bits, or federate mplogas/pm3-mcp",
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

// parseMfHex48 parses a 6-byte hex string (with or without 0x prefix)
// into a uint64 (low 48 bits populated).
func parseMfHex48(s string) (uint64, error) {
	if s == "" {
		return 0, fmt.Errorf("empty hex value")
	}
	s = trimHexPrefix(s)
	v, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		return 0, err
	}
	return v & 0xFFFFFFFFFFFF, nil
}

// strFromMap extracts a string value from a nested map[string]any.
func strFromMap(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
