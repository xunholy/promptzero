package flipper

import (
	"strings"
	"testing"
)

// BadUSBRun and LoaderOpen now reject empty/whitespace args before
// transport. Pre-fix, BadUSBRun("") produced `loader open "Bad USB" `
// (trailing space) and LoaderOpen("", "") produced `loader open ""`.
// The first launches BadUSB with no script (operator sees the app
// idle on screen with no diagnostic); the second fails with an opaque
// firmware parse error.

func TestBadUSBRun_RejectsEmptyPath(t *testing.T) {
	f := &Flipper{}
	for _, p := range []string{"", "   ", "\t", "\n\n"} {
		_, err := f.BadUSBRun(p)
		if err == nil {
			t.Errorf("expected error for path=%q; got nil", p)
			continue
		}
		if !strings.Contains(err.Error(), "BadUSB script path") {
			t.Errorf("path=%q err = %v; want BadUSB script path error", p, err)
		}
	}
}

func TestLoaderOpen_RejectsEmptyAppName(t *testing.T) {
	f := &Flipper{}
	for _, name := range []string{"", "   ", "\t"} {
		_, err := f.LoaderOpen(name, "/ext/test.txt")
		if err == nil {
			t.Errorf("expected error for appName=%q; got nil", name)
			continue
		}
		if !strings.Contains(err.Error(), "app name") {
			t.Errorf("appName=%q err = %v; want app name error", name, err)
		}
	}
}
