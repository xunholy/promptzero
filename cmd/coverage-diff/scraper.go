package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Source describes one upstream repository whose README the scraper fetches.
type Source struct {
	// Name is a human-readable identifier used in the report.
	Name string
	// URL is the raw HTTP(S) URL of the file to fetch.
	URL string
}

// upstreamSources is the hardcoded list of awesome-flipperzero-style
// repositories listed in §A.5 of the v0.5 runbook.
var upstreamSources = []Source{
	{
		Name: "djsime1/awesome-flipperzero",
		URL:  "https://raw.githubusercontent.com/djsime1/awesome-flipperzero/main/README.md",
	},
	{
		Name: "RogueMaster/awesome-flipperzero-withModules",
		URL:  "https://raw.githubusercontent.com/RogueMaster/awesome-flipperzero-withModules/main/README.md",
	},
	{
		Name: "xMasterX/all-the-plugins",
		URL:  "https://raw.githubusercontent.com/xMasterX/all-the-plugins/dev/README.md",
	},
	{
		Name: "jamisonderek/flipper-zero-tutorials",
		URL:  "https://raw.githubusercontent.com/jamisonderek/flipper-zero-tutorials/main/README.md",
	},
	{
		Name: "UberGuidoZ/Flipper",
		URL:  "https://raw.githubusercontent.com/UberGuidoZ/Flipper/main/README.md",
	},
}

// httpClient is the package-level HTTP client used by FetchContent. Exposed
// as a package variable so tests can substitute a transport that points at
// an httptest.Server instead of the real internet.
var httpClient = &http.Client{
	Timeout: 30 * time.Second,
}

// cacheDir returns the per-run cache directory, creating it if absent.
// The directory lives under os.TempDir() so it is automatically cleaned
// by the OS between reboots.
func cacheDir() (string, error) {
	dir := filepath.Join(os.TempDir(), "coverage-diff")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create cache dir: %w", err)
	}
	return dir, nil
}

// cacheKey returns the SHA-256 hex digest of url, used as the cache filename
// so that different URLs never collide.
func cacheKey(url string) string {
	sum := sha256.Sum256([]byte(url))
	return fmt.Sprintf("%x", sum)
}

// FetchContent returns the text of url, optionally consulting a local
// tmpdir cache to avoid redundant HTTP round-trips within the same run.
// With useCache=true the response is written to (and on subsequent calls
// read from) ${TMPDIR}/coverage-diff/<sha256-of-url>.
func FetchContent(url string, useCache bool) (string, error) {
	if useCache {
		dir, err := cacheDir()
		if err == nil {
			cachePath := filepath.Join(dir, cacheKey(url))
			if data, err := os.ReadFile(cachePath); err == nil {
				return string(data), nil
			}
		}
	}

	resp, err := httpClient.Get(url) //nolint:noctx // 30 s deadline baked into httpClient.Timeout
	if err != nil {
		return "", fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch %s: unexpected status %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read body %s: %w", url, err)
	}

	if useCache {
		dir, err := cacheDir()
		if err == nil {
			// Best-effort cache write — ignore errors so a read-only tmpdir
			// never prevents the binary from producing a report.
			_ = os.WriteFile(filepath.Join(dir, cacheKey(url)), body, 0o644)
		}
	}

	return string(body), nil
}
