// hardnested.go — mifare_hardnested_host container bridge.
//
// Hardnested is the attack against MIFARE Classic Plus / EV1 hardened
// nonces. Pure-Go reimplementation is a multi-day effort (the canonical
// nfc-tools/mfoc-hardnested impl is ~2 kloc with bitslice optimisation
// + a 16-bit filter LUT). For v0.6 we ship a thin container bridge to
// the upstream binary so operators can run end-to-end attacks today
// without waiting for the pure-Go port.
//
// Defaults to ghcr.io/nfc-tools/mfoc-hardnested:latest. Override via
// HARDNESTED_IMAGE env or the `image` argument.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/xunholy/promptzero/internal/containerbridge"
	"github.com/xunholy/promptzero/internal/risk"
)

const defaultHardnestedImage = "ghcr.io/nfc-tools/mfoc-hardnested:latest"

func init() { //nolint:gochecknoinits
	Register(mifareHardnestedHostSpec)
}

var mifareHardnestedHostSpec = Spec{
	Name:        "mifare_hardnested_host",
	Description: "Recover a hardened-nonce MIFARE Classic key (Plus, EV1) by running mfoc-hardnested in a sandboxed container. Inputs are the captured (uid, target_block, known_block, known_key, target_key_type) and the algorithm explores ~2^16 candidate nonces with bitslice optimisations (~minutes per sector on a multicore CPU). Requires Docker on the operator host. For pure-Go offline reimpl tracking, see v0.6.1 follow-up.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"uid_hex":{"type":"string","description":"Card UID, 4-byte hex (e.g. CAFEBABE)"},
			"known_block":{"type":"integer","description":"Block number of the sector with the known key"},
			"known_key_hex":{"type":"string","description":"Known sector key, 6-byte hex"},
			"known_key_type":{"type":"string","description":"Key type for the known key (A or B)"},
			"target_block":{"type":"integer","description":"Block number of the sector whose key is unknown"},
			"target_key_type":{"type":"string","description":"Key type to recover for the target sector (A or B)"},
			"image":{"type":"string","description":"Override mfoc-hardnested image. Defaults to HARDNESTED_IMAGE env or ghcr.io/nfc-tools/mfoc-hardnested:latest."},
			"timeout_seconds":{"type":"integer","description":"Per-call timeout. Default 1800s (30 min)."}
		},
		"required":["uid_hex","known_block","known_key_hex","known_key_type","target_block","target_key_type"]
	}`),
	Required:  []string{"uid_hex", "known_block", "known_key_hex", "known_key_type", "target_block", "target_key_type"},
	Risk:      risk.High,
	Group:     GroupFlipperNFC,
	AgentOnly: false,
	Handler:   mifareHardnestedHostHandler,
}

func mifareHardnestedHostHandler(ctx context.Context, _ *Deps, args map[string]any) (string, error) {
	if !containerbridge.Available() {
		return "", fmt.Errorf("mifare_hardnested_host: docker not available — install Docker to use the hardnested bridge")
	}

	uid := strings.ToLower(strings.TrimSpace(str(args, "uid_hex")))
	if uid == "" {
		return "", fmt.Errorf("mifare_hardnested_host: uid_hex is required")
	}
	knownKey := strings.ToLower(strings.TrimSpace(str(args, "known_key_hex")))
	if knownKey == "" {
		return "", fmt.Errorf("mifare_hardnested_host: known_key_hex is required")
	}
	knownType := strings.ToUpper(strings.TrimSpace(str(args, "known_key_type")))
	if knownType != "A" && knownType != "B" {
		return "", fmt.Errorf("mifare_hardnested_host: known_key_type must be A or B")
	}
	targetType := strings.ToUpper(strings.TrimSpace(str(args, "target_key_type")))
	if targetType != "A" && targetType != "B" {
		return "", fmt.Errorf("mifare_hardnested_host: target_key_type must be A or B")
	}
	knownBlock := intOr(args, "known_block", -1)
	if knownBlock < 0 {
		return "", fmt.Errorf("mifare_hardnested_host: known_block is required")
	}
	targetBlock := intOr(args, "target_block", -1)
	if targetBlock < 0 {
		return "", fmt.Errorf("mifare_hardnested_host: target_block is required")
	}

	image := str(args, "image")
	if image == "" {
		image = os.Getenv("HARDNESTED_IMAGE")
	}
	if image == "" {
		image = defaultHardnestedImage
	}

	timeout := time.Duration(intOr(args, "timeout_seconds", 1800)) * time.Second

	// mfoc-hardnested CLI shape (from upstream README):
	//
	//   mfoc-hardnested -O <out> -k <known> -K <type> -B <known_block>
	//                   -t <target_type> -T <target_block>
	//
	// We pass --uid as well because some forks need it without a live
	// reader. If the operator's image variant uses different flags,
	// they can shell into the container directly via docker run.
	cargs := []string{
		"-k", knownKey,
		"-K", knownType,
		"-B", fmt.Sprintf("%d", knownBlock),
		"-t", targetType,
		"-T", fmt.Sprintf("%d", targetBlock),
		"--uid", uid,
	}

	cfg := containerbridge.Config{
		Image:          image,
		Args:           cargs,
		Timeout:        timeout,
		Network:        "none",
		ReadOnlyRootfs: true,
	}

	res, err := containerbridge.Run(ctx, cfg)

	out := map[string]any{
		"image":       image,
		"duration_ms": res.Duration.Milliseconds(),
		"stdout":      tail(res.Stdout, 16384),
		"stderr":      tail(res.Stderr, 16384),
	}

	// hardnested prints the recovered key prefixed by "key:" or
	// "Found key:" depending on the build. Surface it explicitly.
	if k := scanRecoveredKey(string(res.Stdout)); k != "" {
		out["recovered_key"] = k
		out["status"] = "found"
	} else {
		out["status"] = "no_key"
	}

	if err != nil {
		body, _ := json.Marshal(out)
		return string(body), fmt.Errorf("mifare_hardnested_host: %w", err)
	}
	body, _ := json.Marshal(out)
	return string(body), nil
}

// scanRecoveredKey looks for the upstream's recovered-key line and
// returns the 12-hex-char key if present. Tolerates either
// "Found key: 0xAABBCCDDEEFF" or "key: AABBCCDDEEFF" formats.
func scanRecoveredKey(s string) string {
	lines := strings.Split(s, "\n")
	for _, line := range lines {
		lower := strings.ToLower(strings.TrimSpace(line))
		if !strings.Contains(lower, "key") {
			continue
		}
		// Pull out hex tokens of length 12.
		fields := strings.FieldsFunc(line, func(r rune) bool {
			return r == ' ' || r == ':' || r == '\t' || r == '='
		})
		for _, f := range fields {
			f = strings.TrimPrefix(strings.ToLower(f), "0x")
			if len(f) == 12 && isHex(f) {
				return strings.ToUpper(f)
			}
		}
	}
	return ""
}

func isHex(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}
