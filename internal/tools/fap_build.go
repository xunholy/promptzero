// fap_build.go — flipperdevices/flipperzero-ufbt bridge for compiling
// Flipper application packages (.fap) from source.
//
// ufbt (the user-facing flipper build tool) wraps the full Flipper SDK
// + a pinned clang/Python chain. Running it inside a container gives a
// hermetic build that doesn't pollute the operator host.
//
// Default image: `ghcr.io/flipperdevices/ufbt:latest` (mirrors the
// upstream PyPI release). Override with UFBT_IMAGE env or the `image`
// argument.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xunholy/promptzero/internal/containerbridge"
	"github.com/xunholy/promptzero/internal/risk"
)

const defaultUFBTImage = "ghcr.io/flipperdevices/ufbt:latest"

func init() { //nolint:gochecknoinits
	Register(fapBuildSpec)
}

var fapBuildSpec = Spec{
	Name: "fap_build",
	Description: "Compile a Flipper application package (.fap) from a source directory using flipperdevices/flipperzero-ufbt. Runs in a containerised SDK toolchain to avoid host setup. Returns the path to the built .fap, the stdout/stderr of the build, and any warnings detected. The deploy flag will additionally push the built .fap to the connected Flipper's /ext/apps directory. Requires Docker on the operator host.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"source_dir":{"type":"string","description":"Local filesystem path to the .fap source directory (must contain application.fam)."},
			"output_dir":{"type":"string","description":"Host directory to receive the built .fap. Defaults to a TempDir."},
			"deploy":{"type":"boolean","description":"After a successful build, push the .fap to the connected Flipper's /ext/apps via storage_write. Default false."},
			"image":{"type":"string","description":"Override ufbt docker image. Defaults to UFBT_IMAGE env or ghcr.io/flipperdevices/ufbt:latest."},
			"timeout_seconds":{"type":"integer","description":"Per-call timeout. Defaults to 600s (Flipper SDK builds can be slow on first run)."}
		},
		"required":["source_dir"]
	}`),
	Required:  []string{"source_dir"},
	Risk:      risk.Medium,
	Group:     GroupGen,
	AgentOnly: false,
	Handler:   fapBuildHandler,
}

func fapBuildHandler(ctx context.Context, d *Deps, args map[string]any) (string, error) {
	if !containerbridge.Available() {
		return "", fmt.Errorf("fap_build: docker not available — install Docker to use the ufbt bridge")
	}

	srcDir := str(args, "source_dir")
	if srcDir == "" {
		return "", fmt.Errorf("fap_build: source_dir is required")
	}
	absSrc, err := filepath.Abs(srcDir)
	if err != nil {
		return "", fmt.Errorf("fap_build: resolve %s: %w", srcDir, err)
	}
	famPath := filepath.Join(absSrc, "application.fam")
	if _, err := os.Stat(famPath); err != nil {
		return "", fmt.Errorf("fap_build: missing application.fam in %s", absSrc)
	}

	outDir := str(args, "output_dir")
	if outDir == "" {
		outDir, err = os.MkdirTemp("", "promptzero-fap-build-*")
		if err != nil {
			return "", fmt.Errorf("fap_build: create temp output dir: %w", err)
		}
	} else {
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			return "", fmt.Errorf("fap_build: create %s: %w", outDir, err)
		}
	}
	absOut, err := filepath.Abs(outDir)
	if err != nil {
		return "", fmt.Errorf("fap_build: resolve output_dir: %w", err)
	}

	image := str(args, "image")
	if image == "" {
		image = os.Getenv("UFBT_IMAGE")
	}
	if image == "" {
		image = defaultUFBTImage
	}

	timeout := time.Duration(intOr(args, "timeout_seconds", 600)) * time.Second

	cfg := containerbridge.Config{
		Image:   image,
		Args:    []string{"build"},
		WorkDir: "/src",
		Mounts: []containerbridge.Mount{
			{HostPath: absSrc, ContainerPath: "/src", ReadOnly: false},
			{HostPath: absOut, ContainerPath: "/out", ReadOnly: false},
		},
		Network: "bridge", // ufbt may pull SDK toolchain on first run
		Timeout: timeout,
	}

	res, err := containerbridge.Run(ctx, cfg)
	out := map[string]any{
		"source_dir":  absSrc,
		"output_dir":  absOut,
		"image":       image,
		"duration_ms": res.Duration.Milliseconds(),
		"exit_code":   res.ExitCode,
		"stdout":      tail(res.Stdout, 16384),
		"stderr":      tail(res.Stderr, 16384),
	}

	if err != nil {
		body, _ := json.Marshal(out)
		return string(body), fmt.Errorf("fap_build: %w", err)
	}

	// Locate the produced .fap.
	produced := findFAP(absSrc, absOut)
	out["fap_paths"] = produced
	if len(produced) == 0 {
		body, _ := json.Marshal(out)
		return string(body), fmt.Errorf("fap_build: build succeeded but no .fap found in %s or %s", absSrc, absOut)
	}

	// Optional deploy step.
	if deploy := boolOr(args, "deploy", false); deploy {
		if d == nil || d.Flipper == nil {
			out["deploy_status"] = "skipped: Flipper transport unavailable"
		} else {
			pushed, perr := pushFAPs(d, produced)
			out["deploy_pushed"] = pushed
			if perr != nil {
				out["deploy_error"] = perr.Error()
			}
		}
	}

	body, _ := json.Marshal(out)
	return string(body), nil
}

// findFAP recursively scans dirs for *.fap files and returns absolute
// paths. Both source and output dirs are searched because ufbt may
// place the artifact in either location depending on its config.
func findFAP(dirs ...string) []string {
	var out []string
	for _, d := range dirs {
		_ = filepath.WalkDir(d, func(p string, e os.DirEntry, err error) error {
			if err != nil || e.IsDir() {
				return nil
			}
			if strings.HasSuffix(strings.ToLower(p), ".fap") {
				out = append(out, p)
			}
			return nil
		})
	}
	return out
}

// pushFAPs writes each built .fap to the connected Flipper's /ext/apps
// directory. Returns the on-device paths successfully written and a
// joined error for any that failed.
func pushFAPs(d *Deps, faps []string) ([]string, error) {
	var pushed []string
	var errs []string
	for _, p := range faps {
		bytes, err := os.ReadFile(p) //nolint:gosec // operator-built artifact
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: read: %v", p, err))
			continue
		}
		dst := "/ext/apps/" + filepath.Base(p)
		d.SnapshotBeforeWrite(context.Background(), dst)
		if err := d.Flipper.WriteFile(dst, bytes); err != nil {
			errs = append(errs, fmt.Sprintf("%s: write %s: %v", p, dst, err))
			continue
		}
		pushed = append(pushed, dst)
	}
	if len(errs) > 0 {
		return pushed, fmt.Errorf("fap_build deploy: %s", strings.Join(errs, "; "))
	}
	return pushed, nil
}
