// argon2.go — host-side Argon2 (argon2id / argon2i) password-hash compute +
// verify Spec.
//
// Wrap-vs-native: wrap (existing dependency). Argon2 is the OWASP-recommended
// modern password hash (the Password Hashing Competition winner, the successor
// to bcrypt); this is the compute/verify side of the credential toolkit
// (hash_identify recognises $argon2id/$argon2i/$argon2d, but nothing generates
// or single-shot-verifies one). Like bcrypt, Argon2 is NOT reimplemented
// natively: it is a memory-hard KDF built on BLAKE2b with an intricate
// memory-fill/indexing pass — a faithful port is ~hundreds of lines and would be
// less trustworthy than the audited golang.org/x/crypto/argon2 (part of the
// x/crypto module already required by the project for bcrypt/md4). No new module
// dependency is added and a native port is genuinely infeasible: the
// documented-exception case the Wrap-vs-native convention allows. Only the PHC
// string parse/encode around it is our own code — and that is gated against real
// argon2 hashes from the reference argon2-cffi library. Offline compute/verify
// from an operator-supplied string; no network or device.

package tools

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"

	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(argon2Spec)
}

var argon2Spec = Spec{
	Name: "argon2",
	Description: "Compute or verify an Argon2 password hash (argon2id / argon2i, PHC string format) — the " +
		"OWASP-recommended modern password hash and the compute/verify side of the credential toolkit. " +
		"hash_identify recognises Argon2 ($argon2id/$argon2i/$argon2d) but nothing generates one or does a " +
		"single-shot verify. Use it to confirm a cracked password, build a hash for an authorized " +
		"lab/account, or check one candidate against a captured hash.\n\n" +
		"Provide **password** and either a full **hash** ($argon2id$… / $argon2i$…) to verify against " +
		"(constant-time; parameters are read from the hash), or — for compute mode — optional **variant** " +
		"(argon2id default, or argon2i), **memory** (KiB, default 65536 = 64 MiB), **time** (passes, " +
		"default 3), **parallelism** (lanes, default 1), and **salt** (random 16 bytes if omitted). Output " +
		"is the PHC string in compute mode, or matched true/false + the parsed parameters in verify mode. " +
		"argon2d is recognised but not supported for compute/verify (data-dependent; out of scope).\n\n" +
		"Offline compute/verify from an operator-supplied string — no network, no device, transmits " +
		"nothing, so it is Low risk. Verified in-tree against real argon2id/argon2i hashes from the " +
		"reference argon2-cffi library plus a compute→verify round-trip. Wrap-vs-native: wrap — Argon2 is a " +
		"memory-hard BLAKE2b KDF; the audited golang.org/x/crypto/argon2 (already a dependency) is used, " +
		"with our own PHC string parse/encode around it.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"password":{"type":"string","description":"The password to hash or verify."},
			"hash":{"type":"string","description":"A full $argon2id$/$argon2i$ PHC hash to verify the password against (verify mode)."},
			"variant":{"type":"string","description":"Compute-mode variant: argon2id (default) or argon2i.","enum":["argon2id","argon2i"]},
			"memory":{"type":"integer","description":"Compute-mode memory cost in KiB (default 65536 = 64 MiB)."},
			"time":{"type":"integer","description":"Compute-mode time cost / passes (default 3)."},
			"parallelism":{"type":"integer","description":"Compute-mode parallelism / lanes (default 1)."},
			"salt":{"type":"string","description":"Compute-mode salt (raw string; random 16 bytes if omitted)."}
		},
		"required":["password"]
	}`),
	Required:  []string{"password"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   argon2Handler,
}

// argon2MaxMemoryKiB caps the memory cost we will honour (2 GiB) — generous for
// any legitimate password hash, but it rejects an absurd m= in a hostile hash
// that would otherwise OOM the host on compute or verify.
const argon2MaxMemoryKiB = 2 * 1024 * 1024

// argon2MaxTime caps the time cost (iteration count). Real Argon2 hashes use
// t=1..~10 (RFC 9106 recommends 1 or 3); 1024 is hugely generous yet rejects a
// hostile t= (e.g. t=4294967295) that would otherwise spin the host on ~4
// billion passes — an unbounded CPU hang that, unlike m=, the memory cap does
// not catch. Applied on both the parse/verify path and compute.
const argon2MaxTime = 1024

// argon2Params holds the fields parsed from an Argon2 PHC string.
type argon2Params struct {
	Variant     string // "argon2id" / "argon2i" / "argon2d"
	Memory      uint32 // KiB
	Time        uint32
	Parallelism uint8
	Salt        []byte
	Digest      []byte
}

// parseArgon2PHC parses a $argon2id$v=19$m=…,t=…,p=…$salt$hash PHC string (raw
// base64, no padding — the Argon2 convention). Only v=19 (Argon2 1.3) is
// accepted; the salt and digest are returned decoded.
func parseArgon2PHC(hash string) (*argon2Params, error) {
	parts := strings.Split(hash, "$")
	// "" / variant / v=19 / m=,t=,p= / salt / digest
	if len(parts) != 6 || parts[0] != "" {
		return nil, fmt.Errorf("not a v=19 Argon2 PHC string (expected $argon2id$v=19$m=…,t=…,p=…$salt$hash)")
	}
	p := &argon2Params{Variant: parts[1]}
	switch p.Variant {
	case "argon2id", "argon2i", "argon2d":
	default:
		return nil, fmt.Errorf("unknown Argon2 variant %q", p.Variant)
	}
	if parts[2] != "v=19" {
		return nil, fmt.Errorf("unsupported Argon2 version %q (only v=19 / Argon2 1.3)", parts[2])
	}
	for _, kv := range strings.Split(parts[3], ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return nil, fmt.Errorf("malformed Argon2 parameter %q", kv)
		}
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("malformed Argon2 parameter %q: %w", kv, err)
		}
		switch k {
		case "m":
			p.Memory = uint32(n)
		case "t":
			p.Time = uint32(n)
		case "p":
			if n < 1 || n > 255 {
				return nil, fmt.Errorf("Argon2 parallelism out of range: %d", n)
			}
			p.Parallelism = uint8(n)
		}
	}
	if p.Memory == 0 || p.Time == 0 || p.Parallelism == 0 {
		return nil, fmt.Errorf("Argon2 PHC missing m/t/p parameters")
	}
	if p.Memory > argon2MaxMemoryKiB {
		return nil, fmt.Errorf("Argon2 memory cost %d KiB exceeds the %d KiB safety cap (rejecting to avoid OOM)", p.Memory, argon2MaxMemoryKiB)
	}
	if p.Time > argon2MaxTime {
		return nil, fmt.Errorf("Argon2 time cost %d exceeds the %d-pass safety cap (rejecting to avoid an unbounded CPU hang)", p.Time, argon2MaxTime)
	}
	var err error
	if p.Salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil {
		return nil, fmt.Errorf("Argon2 salt is not valid base64: %w", err)
	}
	if p.Digest, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil {
		return nil, fmt.Errorf("Argon2 digest is not valid base64: %w", err)
	}
	if len(p.Salt) == 0 || len(p.Digest) == 0 {
		return nil, fmt.Errorf("Argon2 PHC has an empty salt or digest")
	}
	return p, nil
}

// argon2Derive computes the raw tag for the given variant/params.
func argon2Derive(variant string, password, salt []byte, time, memory uint32, par uint8, keyLen uint32) ([]byte, error) {
	switch variant {
	case "argon2id":
		return argon2.IDKey(password, salt, time, memory, par, keyLen), nil
	case "argon2i":
		return argon2.Key(password, salt, time, memory, par, keyLen), nil
	case "argon2d":
		return nil, fmt.Errorf("argon2d is not supported (data-dependent variant; use argon2id or argon2i)")
	default:
		return nil, fmt.Errorf("unknown Argon2 variant %q", variant)
	}
}

// verifyArgon2 parses a PHC hash and constant-time-compares a recomputed tag.
// Shared with hash_crack_dictionary's "argon2" algorithm.
func verifyArgon2(password, hash string) (bool, error) {
	p, err := parseArgon2PHC(hash)
	if err != nil {
		return false, err
	}
	got, err := argon2Derive(p.Variant, []byte(password), p.Salt, p.Time, p.Memory, p.Parallelism, uint32(len(p.Digest)))
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(got, p.Digest) == 1, nil
}

func argon2Handler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	password, ok := p["password"].(string)
	if !ok {
		return "", fmt.Errorf("argon2: 'password' is required")
	}

	// Verify mode.
	if h := strings.TrimSpace(str(p, "hash")); h != "" {
		params, perr := parseArgon2PHC(h)
		if perr != nil {
			return "", fmt.Errorf("argon2: %w", perr)
		}
		matched, verr := verifyArgon2(password, h)
		if verr != nil {
			return "", fmt.Errorf("argon2: %w", verr)
		}
		out, _ := json.MarshalIndent(map[string]any{
			"mode": "verify", "matched": matched, "variant": params.Variant,
			"memory": params.Memory, "time": params.Time, "parallelism": params.Parallelism,
		}, "", "  ")
		return string(out), nil
	}

	// Compute mode.
	variant := strings.ToLower(strings.TrimSpace(str(p, "variant")))
	if variant == "" {
		variant = "argon2id"
	}
	if variant != "argon2id" && variant != "argon2i" {
		return "", fmt.Errorf("argon2: variant %q must be \"argon2id\" or \"argon2i\"", variant)
	}
	// Validate as signed ints BEFORE the uint32 narrowing — otherwise a
	// negative value (e.g. time=-1) wraps to a huge uint32 and slips past a
	// lower-bound-only check, the same unbounded-work hazard as a hostile hash.
	par := intOr(p, "parallelism", 1)
	if par < 1 || par > 255 {
		return "", fmt.Errorf("argon2: parallelism must be 1-255 (got %d)", par)
	}
	timeInt := intOr(p, "time", 3)
	if timeInt < 1 || timeInt > argon2MaxTime {
		return "", fmt.Errorf("argon2: time must be 1-%d (got %d)", argon2MaxTime, timeInt)
	}
	memInt := intOr(p, "memory", 65536)
	if memInt < 8*par {
		return "", fmt.Errorf("argon2: memory (%d KiB) must be >= 8 * parallelism (%d)", memInt, 8*par)
	}
	if memInt > argon2MaxMemoryKiB {
		return "", fmt.Errorf("argon2: memory %d KiB exceeds the %d KiB cap", memInt, argon2MaxMemoryKiB)
	}
	memory := uint32(memInt)
	timeCost := uint32(timeInt)

	var salt []byte
	if s := str(p, "salt"); s != "" {
		salt = []byte(s)
	} else {
		salt = make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return "", fmt.Errorf("argon2: %w", err)
		}
	}

	const keyLen = 32
	tag, err := argon2Derive(variant, []byte(password), salt, timeCost, memory, uint8(par), keyLen)
	if err != nil {
		return "", fmt.Errorf("argon2: %w", err)
	}
	phc := fmt.Sprintf("$%s$v=19$m=%d,t=%d,p=%d$%s$%s",
		variant, memory, timeCost, par,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(tag))
	out, _ := json.MarshalIndent(map[string]any{
		"mode": "compute", "variant": variant, "hash": phc,
		"memory": memory, "time": timeCost, "parallelism": par,
	}, "", "  ")
	return string(out), nil
}
