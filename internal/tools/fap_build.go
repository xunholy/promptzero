// fap_build.go — flipperdevices/ufbt bridge for compiling Flipper
// application packages (.fap) from source.
//
// ufbt is the upstream Flipper build tool distributed as a Python package:
//
//	pip install ufbt          # install once
//	ufbt                      # builds the FAP in the current directory
//
// This tool shells out to the ufbt binary found on the operator's PATH.
// If ufbt is not available, the handler returns an actionable error
// pointing at the install step.  No Docker or container runtime is required.

package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(fapBuildSpec)
}

var fapBuildSpec = Spec{
	Name: "fap_build",
	Description: "Compile a Flipper application package (.fap) from a source directory " +
		"using the flipperdevices/ufbt tool (install with `pip install ufbt`). " +
		"ufbt must be present on the operator's PATH; no Docker is required. " +
		"Returns the path to the built .fap, stdout/stderr of the build, and any " +
		"warnings detected. The deploy flag additionally pushes the built .fap to " +
		"the connected Flipper's /ext/apps directory.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"source_dir":{"type":"string","description":"Local filesystem path to the .fap source directory (must contain application.fam)."},
			"output_dir":{"type":"string","description":"Host directory to receive the built .fap. Defaults to a TempDir."},
			"deploy":{"type":"boolean","description":"After a successful build, push the .fap to the connected Flipper's /ext/apps via WriteFile. Default false."},
			"ufbt_path":{"type":"string","description":"Explicit path to the ufbt binary. Defaults to 'ufbt' on PATH (or UFBT_PATH env var)."},
			"timeout_seconds":{"type":"integer","description":"Per-call timeout in seconds. Defaults to 300 (5 min)."}
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
	// Resolve ufbt binary: explicit arg > env var > PATH.
	ufbt := str(args, "ufbt_path")
	if ufbt == "" {
		ufbt = os.Getenv("UFBT_PATH")
	}
	if ufbt == "" {
		ufbt = "ufbt"
	}
	ufbtBin, err := exec.LookPath(ufbt)
	if err != nil {
		return "", fmt.Errorf(
			"fap_build: ufbt not found on PATH (looked for %q) — "+
				"install with `pip install ufbt` or set UFBT_PATH to the binary location",
			ufbt,
		)
	}

	srcDir := str(args, "source_dir")
	if srcDir == "" {
		return "", errors.New("fap_build: source_dir is required")
	}
	absSrc, err := filepath.Abs(srcDir)
	if err != nil {
		return "", fmt.Errorf("fap_build: resolve %s: %w", srcDir, err)
	}
	if _, err := os.Stat(filepath.Join(absSrc, "application.fam")); err != nil {
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
		return "", fmt.Errorf("fap_build: resolve output_dir %s: %w", outDir, err)
	}

	timeoutSecs := intOr(args, "timeout_seconds", 300)
	buildCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSecs)*time.Second)
	defer cancel()

	// ufbt is invoked in the source directory; it auto-discovers
	// application.fam there and writes build artefacts to .ufbt/dist/.
	cmd := exec.CommandContext(buildCtx, ufbtBin) //nolint:gosec
	cmd.Dir = absSrc
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	buildErr := cmd.Run()

	out := map[string]any{
		"source_dir": absSrc,
		"output_dir": absOut,
		"stdout":     tail(stdout.Bytes(), 16384),
		"stderr":     tail(stderr.Bytes(), 16384),
		"exit_code":  exitCode(cmd),
	}
	if buildErr != nil {
		body, _ := json.Marshal(out)
		return string(body), fmt.Errorf("fap_build: %w", buildErr)
	}

	// Scan only the canonical ufbt output directory. Searching the
	// LLM-controlled output_dir would let an adversarial invocation set
	// output_dir=/ to harvest every .fap on the host and (with deploy=true)
	// push them to the Flipper. ufbt writes to .ufbt/dist/ inside the
	// source dir; nothing else is in scope.
	produced := findFAP(filepath.Join(absSrc, ".ufbt", "dist"))
	out["fap_paths"] = produced
	if len(produced) == 0 {
		body, _ := json.Marshal(out)
		return string(body), fmt.Errorf(
			"fap_build: build succeeded but no .fap found in %s/.ufbt/dist/",
			absSrc,
		)
	}

	if deploy := boolOr(args, "deploy", false); deploy {
		switch {
		case d == nil || d.Flipper == nil:
			out["deploy_status"] = "skipped: Flipper transport unavailable"
		case !confirmFAPDeploy(ctx, d, produced):
			// Risk-inheritance gate: fap_build's base risk is Medium
			// (host-side compile + SD write), but pushing native ARM
			// code to /ext/apps elevates the composite blast radius
			// to High — the operator only needs one loader_open click
			// to execute the payload. Re-gate here so a Medium
			// autoconfirm does not silently land the binary.
			out["deploy_status"] = "declined: operator refused fap_deploy_to_flipper at high-risk gate"
		default:
			pushed, perr := pushFAPs(ctx, d, produced)
			out["deploy_pushed"] = pushed
			if perr != nil {
				out["deploy_error"] = perr.Error()
			}
		}
	}

	body, _ := json.Marshal(out)
	return string(body), nil
}

// findFAP scans the canonical ufbt dist directory for *.fap files and
// returns absolute paths. Restricted by design: it must NOT walk an
// LLM-controlled directory, otherwise deploy=true becomes an arbitrary
// .fap discovery + write primitive.
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

// confirmFAPDeploy invokes the operator-confirmation hook with risk level
// "high" before pushing built .fap files to /ext/apps. Returns true when
// the hook is absent (auto-approve, matches workflows.gateSubtool fallback)
// or when the operator approves. Mirrors the wifi_sniff_pmkid re-gate inside
// WiFiTargetToHashcat — the operator's earlier consent to fap_build at
// Medium does not cover a native-code write to the Flipper.
//
// The dialog includes both source paths (so the operator can verify what
// is being pushed) and destination paths (so they see where it lands).
func confirmFAPDeploy(ctx context.Context, d *Deps, faps []string) bool {
	if d == nil || d.WorkflowConfirm == nil {
		return true
	}
	dsts := make([]string, 0, len(faps))
	for _, p := range faps {
		dsts = append(dsts, "/ext/apps/"+filepath.Base(p))
	}
	return d.WorkflowConfirm(ctx, "fap_deploy_to_flipper",
		map[string]any{
			"sources":      faps,
			"destinations": dsts,
		}, "high")
}

// pushFAPs writes each built .fap to the connected Flipper's /ext/apps.
// Returns the on-device paths successfully written and a joined error for
// any that failed.
func pushFAPs(ctx context.Context, d *Deps, faps []string) ([]string, error) {
	var pushed []string
	var errs []string
	for _, p := range faps {
		b, err := os.ReadFile(p) //nolint:gosec
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: read: %v", p, err))
			continue
		}
		dst := "/ext/apps/" + filepath.Base(p)
		d.SnapshotBeforeWrite(ctx, dst)
		if err := d.Flipper.WriteFile(dst, b); err != nil {
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

// exitCode reads the process exit code, or -1 when unavailable.
func exitCode(cmd *exec.Cmd) int {
	if cmd.ProcessState == nil {
		return -1
	}
	return cmd.ProcessState.ExitCode()
}
