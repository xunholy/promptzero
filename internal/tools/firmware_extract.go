// firmware_extract.go — onekey-sec/unblob bridge for firmware extraction.
//
// unblob is the modern replacement for legacy binwalk (which EOLs at the
// end of 2025). It identifies and extracts known container formats
// (squashfs, jffs2, cpio, gzip-streams, kernel images, etc.) recursively
// from a firmware blob. PromptZero gets firmware blobs via spi_flash_*
// dumps or operator-supplied files; this Spec runs the extraction in a
// container and surfaces the resulting tree.
//
// Default image: `ghcr.io/onekey-sec/unblob:latest`. Override with
// UNBLOB_IMAGE env or the `image` argument.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/xunholy/promptzero/internal/containerbridge"
	"github.com/xunholy/promptzero/internal/risk"
)

const defaultUnblobImage = "ghcr.io/onekey-sec/unblob:latest"

func init() { //nolint:gochecknoinits
	Register(firmwareExtractSpec)
}

var firmwareExtractSpec = Spec{
	Name: "firmware_extract",
	Description: "Recursively extract a firmware blob using onekey-sec/unblob (modern replacement for legacy binwalk). Identifies squashfs, jffs2, cpio, gzip, ext, kernel, U-Boot, and dozens of other container formats. Output is a directory tree summary plus interesting-file callouts (ssh keys, certs, init scripts, hardcoded credentials in plain-text strings). Requires Docker on the operator host.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"input_path":{"type":"string","description":"Local filesystem path to the firmware blob (.bin, .img, .upd, raw flash dump)."},
			"output_dir":{"type":"string","description":"Host directory to populate. Defaults to a TempDir under os.TempDir(); the path is returned in the result."},
			"image":{"type":"string","description":"Override the unblob docker image. Defaults to UNBLOB_IMAGE env or ghcr.io/onekey-sec/unblob:latest."},
			"timeout_seconds":{"type":"integer","description":"Per-call timeout. Defaults to 300s (large firmwares can take time)."}
		},
		"required":["input_path"]
	}`),
	Required:  []string{"input_path"},
	Risk:      risk.Medium,
	Group:     GroupFlipperHW,
	AgentOnly: false,
	Handler:   firmwareExtractHandler,
}

func firmwareExtractHandler(ctx context.Context, _ *Deps, args map[string]any) (string, error) {
	if !containerbridge.Available() {
		return "", fmt.Errorf("firmware_extract: docker not available — install Docker to use the unblob bridge")
	}

	inputPath := str(args, "input_path")
	if inputPath == "" {
		return "", fmt.Errorf("firmware_extract: input_path is required")
	}
	abs, err := filepath.Abs(inputPath)
	if err != nil {
		return "", fmt.Errorf("firmware_extract: resolve %s: %w", inputPath, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("firmware_extract: stat %s: %w", abs, err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("firmware_extract: input_path %q is a directory; provide a single firmware blob", abs)
	}

	outDir := str(args, "output_dir")
	if outDir == "" {
		outDir, err = os.MkdirTemp("", "promptzero-unblob-*")
		if err != nil {
			return "", fmt.Errorf("firmware_extract: create temp output dir: %w", err)
		}
	} else {
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			return "", fmt.Errorf("firmware_extract: create %s: %w", outDir, err)
		}
	}
	outAbs, err := filepath.Abs(outDir)
	if err != nil {
		return "", fmt.Errorf("firmware_extract: resolve output_dir: %w", err)
	}

	image := str(args, "image")
	if image == "" {
		image = os.Getenv("UNBLOB_IMAGE")
	}
	if image == "" {
		image = defaultUnblobImage
	}

	timeout := time.Duration(intOr(args, "timeout_seconds", 300)) * time.Second

	cfg := containerbridge.Config{
		Image: image,
		Args: []string{
			"--extract-dir", "/out",
			"/in/" + filepath.Base(abs),
		},
		Mounts: []containerbridge.Mount{
			{HostPath: filepath.Dir(abs), ContainerPath: "/in", ReadOnly: true},
			{HostPath: outAbs, ContainerPath: "/out", ReadOnly: false},
		},
		Timeout: timeout,
		Network: "none",
	}

	res, err := containerbridge.Run(ctx, cfg)
	tree := summariseTree(outAbs, 200)

	out := map[string]any{
		"input_path":  abs,
		"input_size":  info.Size(),
		"output_dir":  outAbs,
		"image":       image,
		"duration_ms": res.Duration.Milliseconds(),
		"stdout":      tail(res.Stdout, 8192),
		"stderr":      tail(res.Stderr, 8192),
		"file_tree":   tree,
		"interesting": classifyInteresting(tree),
	}
	body, _ := json.Marshal(out)
	if err != nil {
		return string(body), fmt.Errorf("firmware_extract: %w", err)
	}
	return string(body), nil
}

// summariseTree walks dir and returns up to maxFiles relative paths in
// breadth-first order. Symlinks are resolved as their literal name (not
// followed) to prevent loops. Errors are silenced — partial output is
// always more useful than nothing.
func summariseTree(root string, maxFiles int) []string {
	var files []string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		files = append(files, rel)
		if len(files) >= maxFiles {
			return filepath.SkipAll
		}
		return nil
	})
	sort.Strings(files)
	return files
}

// classifyInteresting picks file paths that match common
// "look-here-first" patterns. This is a heuristic — operators should
// still inspect the full tree.
func classifyInteresting(tree []string) []string {
	patterns := []string{
		"id_rsa", "id_ed25519", "authorized_keys",
		"shadow", "passwd", "htpasswd",
		".pem", ".crt", ".key", ".p12",
		"rcS", "rc.local", "init",
		"hardcode", "secret", "token", "config.bin",
	}
	var hits []string
	for _, f := range tree {
		lower := strings.ToLower(f)
		for _, p := range patterns {
			if strings.Contains(lower, p) {
				hits = append(hits, f)
				break
			}
		}
	}
	return hits
}

// tail returns the last n bytes of b; for stdout/stderr capture so very
// large outputs don't blow up the agent's prompt cache. Shared by other
// container-bridge specs (urh.go, fap_build.go) — defined here because
// firmware_extract.go is the first file in the family alphabetically.
func tail(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return "...[truncated " + strconv.Itoa(len(b)-n) + " bytes]...\n" + string(b[len(b)-n:])
}
