// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/mod/semver"

	"github.com/xunholy/promptzero/internal/version"
)

// releasesBase is the GitHub release download root. Keep it a constant
// rather than plumbing through config — the install path explicitly
// pins itself to the official repo's releases.
const (
	releasesBase = "https://github.com/xunholy/promptzero/releases"
	assetPrefix  = "promptzero"
)

// upgradeOpts captures every knob the upgrade subcommand exposes. Kept as
// a struct so the dispatcher in main.go can construct it from its own
// flag parsing without this file reaching back into runFlags.
type upgradeOpts struct {
	targetVersion string // empty ⇒ latest
	force         bool   // skip downgrade / dev-build guardrails
	dryRun        bool   // show what would happen, don't touch disk
}

// runUpgrade downloads the target release and atomically replaces the
// currently-running binary. Guardrails: refuses to downgrade, refuses to
// run against a dev build, verifies the SHA-256 against the release's
// checksums.txt, and runs the candidate binary with --version before
// swapping so a mismatched asset can't clobber a working install.
func runUpgrade(ctx context.Context, opts upgradeOpts) error {
	self, err := resolveSelf()
	if err != nil {
		return fmt.Errorf("resolving own binary path: %w", err)
	}
	current := version.Version

	if current == "dev" && !opts.force {
		return fmt.Errorf("refusing to upgrade a local dev build — re-install via install.sh " +
			"or pass --force to override")
	}

	target := strings.TrimSpace(opts.targetVersion)
	if target != "" {
		target = normaliseTag(target)
		if !semver.IsValid(target) {
			return fmt.Errorf("invalid version %q (expected vX.Y.Z)", opts.targetVersion)
		}
	} else {
		tag, err := latestTag(ctx)
		if err != nil {
			return fmt.Errorf("resolving latest release: %w", err)
		}
		target = tag
	}

	fmt.Fprintf(os.Stderr, "  %s%s▸%s current: %s\n", dim, cyan, reset, current)
	fmt.Fprintf(os.Stderr, "  %s%s▸%s target:  %s\n", dim, cyan, reset, target)
	fmt.Fprintf(os.Stderr, "  %s%s▸%s path:    %s\n", dim, cyan, reset, self)

	if current != "dev" && semver.IsValid(current) {
		cmp := semver.Compare(target, current)
		switch {
		case cmp == 0:
			statusOK(fmt.Sprintf("already at %s — nothing to do", current))
			return nil
		case cmp < 0 && !opts.force:
			return fmt.Errorf("refusing to downgrade from %s to %s "+
				"(promptzero encourages staying on the latest release; pass --force to override)",
				current, target)
		}
	}

	installDir := filepath.Dir(self)
	if err := checkWritable(installDir); err != nil {
		return err
	}

	if opts.dryRun {
		statusInfo(fmt.Sprintf("dry-run: would install %s to %s", target, self))
		return nil
	}

	// Stage in a tmp dir on the same filesystem so the final rename is
	// atomic. Cross-device renames fall back to copy+unlink and can
	// leave the target in a half-written state on interrupt.
	stagingDir, err := os.MkdirTemp(installDir, ".promptzero-upgrade-*")
	if err != nil {
		return fmt.Errorf("creating staging dir in %s: %w", installDir, err)
	}
	defer os.RemoveAll(stagingDir)

	candidate, err := downloadAndVerify(ctx, target, stagingDir)
	if err != nil {
		return err
	}

	if err := preflightNewBinary(candidate, target); err != nil {
		return fmt.Errorf("pre-flight failed: %w", err)
	}

	if err := atomicReplace(candidate, self); err != nil {
		return fmt.Errorf("replacing %s: %w", self, err)
	}

	statusOK(fmt.Sprintf("upgraded %s → %s", current, target))
	return nil
}

// runVersionCheck prints the current version and, when check is true,
// also fetches the latest release tag and reports whether an update is
// available. Always exits zero; the advisory is purely informational.
func runVersionCheck(ctx context.Context, check bool) error {
	fmt.Printf("promptzero %s\n", version.String())
	if !check {
		return nil
	}
	latest, err := latestTag(ctx)
	if err != nil {
		statusWarn(fmt.Sprintf("couldn't check for updates: %v", err))
		return nil
	}
	cur := version.Version
	switch {
	case cur == "dev":
		statusInfo(fmt.Sprintf("latest release is %s (running a dev build)", latest))
	case !semver.IsValid(cur):
		statusInfo(fmt.Sprintf("latest release is %s (running %s — version format unrecognised)", latest, cur))
	case semver.Compare(latest, cur) > 0:
		statusWarn(fmt.Sprintf("a newer release is available: %s (you have %s) — run `promptzero upgrade`",
			latest, cur))
	default:
		statusOK(fmt.Sprintf("up to date (%s)", cur))
	}
	return nil
}

// normaliseTag prepends a leading v if the caller passed "0.2.0" instead
// of "v0.2.0". semver.IsValid then does the real validation.
func normaliseTag(v string) string {
	if strings.HasPrefix(v, "v") {
		return v
	}
	return "v" + v
}

// resolveSelf returns the absolute, symlink-resolved path of the running
// binary. EvalSymlinks matters because apt / brew / manual installs may
// leave a /usr/local/bin/promptzero symlink pointing into a versioned
// install dir — we want to replace the real file, not the symlink.
func resolveSelf() (string, error) {
	p, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		return resolved, nil
	}
	return p, nil
}

// checkWritable returns a helpful error if dir isn't writable by the
// current user. On a read-only install dir we surface the exact sudo
// command rather than invoking sudo ourselves — we never want to
// escalate silently.
func checkWritable(dir string) error {
	probe, err := os.CreateTemp(dir, ".promptzero-writable-check-*")
	if err != nil {
		return fmt.Errorf("%s is not writable — re-run with sudo, e.g. `sudo promptzero upgrade`",
			dir)
	}
	name := probe.Name()
	probe.Close()
	_ = os.Remove(name)
	return nil
}

// latestTag follows the /releases/latest redirect on github.com and
// returns the tag from the final URL. Unauthenticated, no rate limit,
// no JSON parsing — same technique as install.sh.
func latestTag(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead,
		releasesBase+"/latest", nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf(
			"GET %s/latest returned HTTP %d — GitHub releases unreachable or the project has no releases yet",
			releasesBase, resp.StatusCode)
	}
	final := resp.Request.URL.Path
	tag := filepath.Base(final)
	if !semver.IsValid(tag) {
		return "", fmt.Errorf("redirect URL %q didn't end in a semver tag", final)
	}
	return tag, nil
}

// downloadAndVerify fetches the platform tarball + checksums.txt into
// stagingDir, checks the SHA-256, extracts the tar, chmods the binary
// executable, and returns its path. The returned file lives inside
// stagingDir so callers can rename it over the running binary.
func downloadAndVerify(ctx context.Context, tag, stagingDir string) (string, error) {
	goos := runtime.GOOS
	goarch := runtime.GOARCH
	if goos == "windows" {
		return "", fmt.Errorf("promptzero upgrade doesn't support Windows yet " +
			"(a running .exe can't be replaced) — download the .zip from " + releasesBase)
	}
	if goos != "linux" && goos != "darwin" {
		return "", fmt.Errorf("unsupported OS: %s", goos)
	}
	if goarch != "amd64" && goarch != "arm64" {
		return "", fmt.Errorf("unsupported architecture: %s", goarch)
	}

	asset := fmt.Sprintf("%s-%s-%s.tar.gz", assetPrefix, goos, goarch)
	base := fmt.Sprintf("%s/download/%s", releasesBase, tag)
	tarPath := filepath.Join(stagingDir, asset)
	sumPath := filepath.Join(stagingDir, "checksums.txt")

	statusInfo(fmt.Sprintf("downloading %s", asset))
	if err := downloadFile(ctx, base+"/"+asset, tarPath); err != nil {
		return "", fmt.Errorf("download %s: %w", asset, err)
	}
	statusInfo("downloading checksums.txt")
	if err := downloadFile(ctx, base+"/checksums.txt", sumPath); err != nil {
		return "", fmt.Errorf("download checksums.txt: %w", err)
	}

	statusInfo("verifying sha256")
	expected, err := lookupChecksum(sumPath, asset)
	if err != nil {
		return "", err
	}
	got, err := sha256File(tarPath)
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(got, expected) {
		return "", fmt.Errorf("checksum mismatch for %s\n  expected: %s\n  got:      %s",
			asset, expected, got)
	}

	statusInfo("extracting")
	innerBin := fmt.Sprintf("%s-%s-%s", assetPrefix, goos, goarch)
	if err := extractTarGzEntry(tarPath, innerBin, filepath.Join(stagingDir, innerBin)); err != nil {
		return "", err
	}
	candidate := filepath.Join(stagingDir, innerBin)
	if err := os.Chmod(candidate, 0o755); err != nil {
		return "", err
	}
	return candidate, nil
}

// preflightNewBinary runs `<candidate> --version` with a short timeout
// and compares its reported version against tag. A mismatch means the
// release assets were mis-built or the archive was tampered with —
// refuse to replace the running binary on that evidence.
func preflightNewBinary(candidate, tag string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, candidate, "--version").Output()
	if err != nil {
		return fmt.Errorf("running candidate --version: %w", err)
	}
	fields := strings.Fields(string(out))
	if len(fields) < 2 {
		return fmt.Errorf(
			"candidate binary at %s printed %q for --version (expected `promptzero <tag>`); "+
				"this usually means the release archive was mis-built or tampered with — "+
				"re-run `promptzero upgrade` to retry, or report the issue with this output attached",
			candidate, strings.TrimSpace(string(out)))
	}
	reported := fields[1]
	if reported != tag {
		return fmt.Errorf("candidate binary reports %s but release tag is %s", reported, tag)
	}
	return nil
}

// atomicReplace renames newPath over target. os.Rename is atomic on
// Linux/macOS even when target is the currently-running binary: the
// inode stays referenced by the running process while the filesystem
// entry flips to the new inode. New invocations pick up the upgraded
// binary; the current process keeps running the old code until exit.
func atomicReplace(newPath, target string) error {
	return os.Rename(newPath, target)
}

// downloadFile streams url into dst. Uses the provided ctx so callers
// can cancel the HTTP round-trip via SIGINT. The destination file's
// Close error is surfaced — on a self-upgrade flow a delayed flush
// failure (disk full, fsync error) would silently leave a truncated
// binary that breaks the next launch.
func downloadFile(ctx context.Context, url, dst string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d fetching %s", resp.StatusCode, url)
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// lookupChecksum parses the GitHub release checksums.txt (GNU
// sha256sum output format: "<hex>  <filename>") and returns the hash
// for asset. Matches exact filename; release workflow never produces
// star-prefixed names so "*name" variants aren't supported.
func lookupChecksum(path, asset string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) != 2 {
			continue
		}
		name := strings.TrimPrefix(fields[1], "*")
		if name == asset {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("no checksum entry for %s in checksums.txt", asset)
}

// sha256File streams a file through sha256 and returns the lowercase
// hex digest. Streaming avoids buffering multi-MB archives in memory.
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// extractTarGzEntry extracts a single named entry from a .tar.gz into
// dst. Avoids zip-slip by refusing absolute paths / ".." traversals
// inside the archive and by matching entries by exact basename — the
// release tarballs flatten the binary at the archive root anyway, so
// there's no nested path to honour.
func extractTarGzEntry(archivePath, entryName, dst string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	gzr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gzr.Close()
	tr := tar.NewReader(gzr)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if filepath.IsAbs(hdr.Name) || strings.Contains(hdr.Name, "..") {
			return fmt.Errorf("unsafe path in archive: %q", hdr.Name)
		}
		if filepath.Base(hdr.Name) != entryName {
			continue
		}
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		if _, err := io.CopyN(out, tr, hdr.Size); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	}
	return fmt.Errorf("entry %q not found in %s", entryName, filepath.Base(archivePath))
}

// parseUpgradeFlags is the subcommand-level flag parser, called by the
// dispatcher in main.go when os.Args[1] is "upgrade". Kept separate from
// the top-level parseFlags() so `promptzero upgrade --help` shows only
// the flags that actually apply here.
func parseUpgradeFlags(args []string) upgradeOpts {
	fs := flag.NewFlagSet("upgrade", flag.ExitOnError)
	var o upgradeOpts
	fs.StringVar(&o.targetVersion, "version", "", "Target release tag (default: latest)")
	fs.BoolVar(&o.force, "force", false, "Skip safety checks (downgrade allowed, dev-build allowed)")
	fs.BoolVar(&o.dryRun, "dry-run", false, "Print the plan without touching disk")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: promptzero upgrade [--version vX.Y.Z] [--force] [--dry-run]")
		fmt.Fprintln(fs.Output(), "")
		fmt.Fprintln(fs.Output(), "Upgrade in place to the latest release (or --version pin).")
		fmt.Fprintln(fs.Output(), "")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	return o
}

// parseVersionFlags is the companion for the "version" subcommand.
// Accepts only --check; anything else returns its help text.
func parseVersionFlags(args []string) bool {
	fs := flag.NewFlagSet("version", flag.ExitOnError)
	var check bool
	fs.BoolVar(&check, "check", false, "Also fetch the latest release tag and report if an update is available")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: promptzero version [--check]")
		fmt.Fprintln(fs.Output(), "")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	return check
}
