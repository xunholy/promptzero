package discover

import (
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/flipper"
)

type App struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Type string `json:"type"`
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
			line = strings.TrimSpace(line)
			if strings.HasSuffix(line, ".fap") {
				apps = append(apps, App{
					Name: strings.TrimSuffix(line, ".fap"),
					Path: dir + "/" + line,
					Type: "fap",
				})
			}
		}
	}

	// Scan signal libraries
	signalDirs := map[string]string{
		"/ext/subghz":   "subghz",
		"/ext/infrared": "ir",
		"/ext/nfc":      "nfc",
		"/ext/lfrfid":   "rfid",
		"/ext/ibutton":  "ibutton",
		"/ext/badusb":   "badusb",
	}

	for dir, sigType := range signalDirs {
		out, err := f.StorageList(dir)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "[D]") {
				continue
			}
			apps = append(apps, App{
				Name: line,
				Path: dir + "/" + line,
				Type: sigType,
			})
		}
	}

	return apps, nil
}

// FormatApps returns a human-readable summary of discovered apps and files.
func FormatApps(apps []App) string {
	if len(apps) == 0 {
		return "No applications or signal files found on SD card."
	}

	groups := make(map[string][]App)
	for _, a := range apps {
		groups[a.Type] = append(groups[a.Type], a)
	}

	var sb strings.Builder
	for t, list := range groups {
		fmt.Fprintf(&sb, "\n[%s] (%d files)\n", strings.ToUpper(t), len(list))
		for _, a := range list {
			fmt.Fprintf(&sb, "  %s  ->  %s\n", a.Name, a.Path)
		}
	}
	return sb.String()
}
