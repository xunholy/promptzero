package discover

import (
	"fmt"
	"sort"
	"strings"

	"github.com/xunholy/promptzero/internal/flipper"
)

type App struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Type string `json:"type"`
}

// parseStorageListFile extracts the file basename from a single
// `storage list` output line. The firmware (per
// internal/flipper/commands.go) emits:
//
//	"\t[F] <name> <size>b"   for files
//	"\t[D] <name>"            for directories
//
// Returns ("", false) for directory entries, blank lines, and
// malformed input so callers can `continue` past them. For valid
// file lines the [F] marker is stripped and the trailing
// " <size>b" is dropped, so the returned name is just the
// filename.
func parseStorageListFile(line string) (string, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "[D]") {
		return "", false
	}
	if !strings.HasPrefix(line, "[F] ") {
		// Tolerate a future firmware that drops the marker, or pre-
		// formatted lines from RPC builders. Return the trimmed line
		// so callers stay compatible.
		return line, true
	}
	rest := strings.TrimPrefix(line, "[F] ")
	// Drop the trailing " <size>b". Look from the right so a
	// filename containing spaces (rare but legal) survives. Confirm
	// the tail looks like digits-then-b before stripping; otherwise
	// it might be part of the filename.
	if idx := strings.LastIndex(rest, " "); idx > 0 {
		tail := rest[idx+1:]
		if strings.HasSuffix(tail, "b") {
			digits := strings.TrimSuffix(tail, "b")
			allDigits := digits != ""
			for _, r := range digits {
				if r < '0' || r > '9' {
					allDigits = false
					break
				}
			}
			if allDigits {
				rest = rest[:idx]
			}
		}
	}
	return rest, true
}

// ScanApps discovers FAP applications and signal files on the Flipper SD card.
func ScanApps(f *flipper.Flipper) ([]App, error) {
	var apps []App

	// Scan for FAP applications
	fapDirs := []string{"/ext/apps", "/ext/apps_data"}
	for _, dir := range fapDirs {
		out, err := f.StorageList(dir)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(out, "\n") {
			name, ok := parseStorageListFile(line)
			if !ok {
				continue
			}
			if strings.HasSuffix(name, ".fap") {
				apps = append(apps, App{
					Name: strings.TrimSuffix(name, ".fap"),
					Path: dir + "/" + name,
					Type: "fap",
				})
			}
		}
	}

	// Scan signal libraries. Pairs are kept in a slice rather than a map
	// so the iteration order is fixed — without this, ScanApps's
	// returned []App appeared in a different order every call (Go map
	// iteration is randomised). FormatApps sorted by Type so the
	// human-facing output looked stable, but any other caller of the
	// raw slice saw shuffle-per-run.
	signalDirs := []struct{ dir, sigType string }{
		{"/ext/badusb", "badusb"},
		{"/ext/ibutton", "ibutton"},
		{"/ext/infrared", "ir"},
		{"/ext/lfrfid", "rfid"},
		{"/ext/nfc", "nfc"},
		{"/ext/subghz", "subghz"},
	}

	for _, sd := range signalDirs {
		out, err := f.StorageList(sd.dir)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(out, "\n") {
			name, ok := parseStorageListFile(line)
			if !ok {
				continue
			}
			apps = append(apps, App{
				Name: name,
				Path: sd.dir + "/" + name,
				Type: sd.sigType,
			})
		}
	}

	return apps, nil
}

// FormatApps returns a human-readable summary of discovered apps and files.
// Output is deterministic: groups are emitted in alphabetical order by
// type, and entries within each group preserve the input order. Without
// the sort, Go's randomised map iteration produced a different layout
// every call, which made operator-facing diff comparisons noisy and
// broke any caller doing a textual equality check on prior output.
func FormatApps(apps []App) string {
	if len(apps) == 0 {
		return "No applications or signal files found on SD card."
	}

	groups := make(map[string][]App)
	for _, a := range apps {
		groups[a.Type] = append(groups[a.Type], a)
	}

	types := make([]string, 0, len(groups))
	for t := range groups {
		types = append(types, t)
	}
	sort.Strings(types)

	var sb strings.Builder
	for _, t := range types {
		list := groups[t]
		fmt.Fprintf(&sb, "\n[%s] (%d files)\n", strings.ToUpper(t), len(list))
		for _, a := range list {
			fmt.Fprintf(&sb, "  %s  ->  %s\n", a.Name, a.Path)
		}
	}
	return sb.String()
}
