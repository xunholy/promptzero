// urh.go — urh-ng host bridge for SubGHz protocol analysis.
//
// PentHertz/urh-ng is the actively-maintained fork of jopohl/urh
// (Universal Radio Hacker), packaging an extensive protocol-signature
// table (~327 protocols including rtl_433, Flipper-ARF, and ProtoPirate
// catalogues). PromptZero captures .sub files via the Flipper Sub-GHz
// stack; this Spec hands them to urh-ng for protocol classification +
// bit-level demodulation, returning a structured analysis JSON.
//
// The bridge runs urh-ng in a docker container (see internal/containerbridge).
// Default image is `ghcr.io/penthertz/urh-ng:latest`; operators can
// override via the URH_IMAGE env var or the `image` argument.

package tools

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/xunholy/promptzero/internal/containerbridge"
	"github.com/xunholy/promptzero/internal/risk"
)

const defaultURHImage = "ghcr.io/penthertz/urh-ng:latest"

func init() { //nolint:gochecknoinits
	Register(urhDecodeSubSpec)
}

var urhDecodeSubSpec = Spec{
	Name:        "urh_decode_sub",
	Description: "Analyse a Flipper .sub capture with urh-ng (PentHertz fork of Universal Radio Hacker). Identifies the modulation scheme, demodulates to bits, and runs urh-ng's protocol-signature classifier against ~327 known SubGHz protocols (KeeLoq, Princeton, CAME, Holtek, Linear, etc.). Returns a JSON object with detected_protocol, confidence, demodulated_bits, and a hexdump of recovered payload bytes. Requires Docker on the operator host.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"sub_path":{"type":"string","description":"Local filesystem path to the .sub file. Mutually exclusive with sub_data_b64."},
			"sub_data_b64":{"type":"string","description":"Base64-encoded .sub file bytes. Useful when the data was just captured into memory and not persisted yet."},
			"image":{"type":"string","description":"Override the urh-ng docker image. Defaults to URH_IMAGE env or ghcr.io/penthertz/urh-ng:latest."},
			"timeout_seconds":{"type":"integer","description":"Per-call timeout. Defaults to 60s."}
		}
	}`),
	Required:  nil,
	Risk:      risk.Low,
	Group:     GroupFlipperSubGHz,
	AgentOnly: false,
	Handler:   urhDecodeSubHandler,
}

func urhDecodeSubHandler(ctx context.Context, _ *Deps, args map[string]any) (string, error) {
	if !containerbridge.Available() {
		return "", fmt.Errorf("urh_decode_sub: docker not available — install Docker to use the urh-ng bridge")
	}

	var subBytes []byte
	if p := str(args, "sub_path"); p != "" {
		b, err := os.ReadFile(p) //nolint:gosec // operator-supplied path; risk gate already passed
		if err != nil {
			return "", fmt.Errorf("urh_decode_sub: read %s: %w", p, err)
		}
		subBytes = b
	} else if d := str(args, "sub_data_b64"); d != "" {
		b, err := base64.StdEncoding.DecodeString(d)
		if err != nil {
			return "", fmt.Errorf("urh_decode_sub: decode sub_data_b64: %w", err)
		}
		subBytes = b
	} else {
		return "", fmt.Errorf("urh_decode_sub: provide sub_path or sub_data_b64")
	}

	image := str(args, "image")
	if image == "" {
		image = os.Getenv("URH_IMAGE")
	}
	if image == "" {
		image = defaultURHImage
	}

	timeout := time.Duration(intOr(args, "timeout_seconds", 60)) * time.Second

	cfg := containerbridge.Config{
		Image:   image,
		Args:    []string{"--cli", "--no-gui", "--analyze-stdin", "--json"},
		Stdin:   strings.NewReader(string(subBytes)),
		Timeout: timeout,
		// urh-ng is a passive analysis tool — no host filesystem
		// access, no network needed.
		Network:        "none",
		ReadOnlyRootfs: true,
	}

	res, err := containerbridge.Run(ctx, cfg)
	if err != nil {
		return string(res.Stdout), fmt.Errorf("urh_decode_sub: %w", err)
	}

	out := map[string]any{
		"raw_output":  string(res.Stdout),
		"stderr":      string(res.Stderr),
		"duration_ms": res.Duration.Milliseconds(),
		"image":       image,
		"input_size":  len(subBytes),
	}
	// Try to surface urh-ng's structured output directly when it
	// emitted JSON. Falls back to raw text when the parse fails so the
	// agent always sees something.
	var parsed map[string]any
	if err := json.Unmarshal(res.Stdout, &parsed); err == nil {
		out["urh_ng"] = parsed
	}

	body, _ := json.Marshal(out)
	return string(body), nil
}
