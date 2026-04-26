// install-companion-fap is a one-shot utility that pushes the
// PromptZero Companion FAP onto a connected Flipper. Useful when
// you don't want to bring up qFlipper or run a full agent session
// just to copy a 6 KB file to /ext/apps/.
//
// Usage:
//
//	install-companion-fap                           # auto-detect port + default fap path
//	install-companion-fap -port /dev/ttyACM0 -fap bin/fap/promptzero_companion.fap
//
// Exits 0 on success. The FAP lands at /ext/apps/Tools/ by default
// (the location PromptZero's Detect() probes first).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/xunholy/promptzero/internal/flipper"
)

func main() {
	port := flag.String("port", "/dev/ttyACM0", "Flipper serial device")
	baud := flag.Int("baud", 230400, "serial baud rate")
	fapPath := flag.String("fap", "bin/fap/promptzero_companion.fap", "local path to the .fap to install")
	dest := flag.String("dest", "/ext/apps/Tools/promptzero_companion.fap", "destination path on the Flipper SD card. The Tools/ subfolder is what the Flipper apps menu indexes into the Tools category — installing into /ext/apps/ directly leaves the FAP uncategorised and not visible from Apps → Tools on most firmware.")
	timeout := flag.Duration("timeout", 30*time.Second, "overall operation deadline")
	flag.Parse()

	if err := run(*port, *baud, *fapPath, *dest, *timeout); err != nil {
		fmt.Fprintf(os.Stderr, "install-companion-fap: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("ok")
}

func run(port string, baud int, fapPath, dest string, deadline time.Duration) error {
	abs, err := filepath.Abs(fapPath)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", fapPath, err)
	}
	data, err := os.ReadFile(abs) //nolint:gosec // operator-supplied artifact
	if err != nil {
		return fmt.Errorf("read %s: %w", abs, err)
	}
	if len(data) == 0 {
		return fmt.Errorf("empty fap file: %s", abs)
	}
	fmt.Printf("local:  %s (%d bytes)\n", abs, len(data))

	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()

	fmt.Printf("connect: %s @ %d ...\n", port, baud)
	f, err := flipper.Connect(ctx, port, baud, 10*time.Second)
	if err != nil {
		return fmt.Errorf("connect %s: %w", port, err)
	}
	defer func() { _ = f.Close() }()

	// Probe with a cheap read-only command first so a permanently
	// hung CLI fails loudly here instead of silently consuming the
	// 30s timeout on the WriteFile path.
	probeCtx, probeCancel := context.WithTimeout(ctx, 8*time.Second)
	if out, err := f.ExecCtx(probeCtx, "storage info /ext"); err != nil {
		probeCancel()
		return fmt.Errorf("probe storage info: %w (is the Flipper on the home screen?)", err)
	} else {
		fmt.Printf("probe:   storage info /ext → %s\n", trim(out))
	}
	probeCancel()

	// Best-effort mkdir for the destination's parent — succeeds
	// silently if the directory already exists. /ext/apps always
	// exists so by default we skip this entirely.
	parent := filepath.Dir(dest)
	if parent != "" && parent != "/" && parent != "/ext/apps" {
		mkCtx, mkCancel := context.WithTimeout(ctx, 8*time.Second)
		if _, err := f.ExecCtx(mkCtx, "storage mkdir "+parent); err != nil {
			fmt.Printf("mkdir:   %s — %v (continuing)\n", parent, err)
		} else {
			fmt.Printf("mkdir:   %s\n", parent)
		}
		mkCancel()
	}

	// Remove any prior file at dest. Some Flipper firmware forks
	// (notably Momentum dev) make `storage write_chunk` append to
	// an existing file instead of truncating, so without this the
	// re-installed .fap ends up double-sized and corrupt. Failure
	// is silent — most often it just means "no such file".
	rmCtx, rmCancel := context.WithTimeout(ctx, 5*time.Second)
	if out, err := f.ExecCtx(rmCtx, "storage remove "+dest); err != nil {
		fmt.Printf("rm:      %s — %v (continuing)\n", dest, err)
	} else {
		fmt.Printf("rm:      %s — %s\n", dest, trim(out))
	}
	rmCancel()

	fmt.Printf("write:   %s ...\n", dest)
	if err := f.WriteFileCtx(ctx, dest, data); err != nil {
		return fmt.Errorf("write %s: %w", dest, err)
	}

	// Verify by reading the file's stat (size should match).
	if out, err := f.StorageStat(dest); err == nil {
		fmt.Printf("verify:  %s\n", trim(out))
	}
	return nil
}

func trim(s string) string {
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}
