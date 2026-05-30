//go:build linux

package flipper_test

import (
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/flipper/mock"
)

// gpioLinesAfter returns the `gpio ...` command lines the mock observed
// after the given offset, in order.
func gpioLinesAfter(m *mock.Mock, offset int) []string {
	var out []string
	all := m.Lines()
	if offset > len(all) {
		offset = len(all)
	}
	for _, l := range all[offset:] {
		if strings.HasPrefix(strings.TrimSpace(l), "gpio ") {
			out = append(out, strings.TrimSpace(l))
		}
	}
	return out
}

func indexOf(lines []string, want string) int {
	for i, l := range lines {
		if l == want {
			return i
		}
	}
	return -1
}

// TestGPIO_CLISetsModeBeforeReadAndSet pins the v0.368 fix: current
// firmware (verified momentum/mntm-dev) rejects a bare `gpio read`/`gpio
// set` with "Err: pin <pin> is not set as an input/output." until the pin
// mode is set. The CLI path must therefore issue `gpio mode <pin> <0|1>`
// before the read/set, mirroring the RPC path.
func TestGPIO_CLISetsModeBeforeReadAndSet(t *testing.T) {
	m := mock.Spawn(t,
		mock.WithHandler("gpio", func(args []string) string {
			if len(args) >= 1 && args[0] == "read" {
				return "Pin PC0 <= 0"
			}
			return "" // mode / set — firmware emits a banner we don't assert on
		}),
	)
	flip := connectAndDetect(t, m)

	// --- read: expect `gpio mode PC0 0` then `gpio read PC0` ---
	before := len(m.Lines())
	if _, err := flip.GPIORead("PC0"); err != nil {
		t.Fatalf("GPIORead: %v", err)
	}
	rl := gpioLinesAfter(m, before)
	mi, ri := indexOf(rl, "gpio mode PC0 0"), indexOf(rl, "gpio read PC0")
	if mi < 0 || ri < 0 {
		t.Fatalf("GPIORead lines = %v; want both 'gpio mode PC0 0' and 'gpio read PC0'", rl)
	}
	if mi > ri {
		t.Errorf("GPIORead issued mode after read (mode@%d read@%d); want mode first; lines=%v", mi, ri, rl)
	}

	// --- set (drive output): expect `gpio mode PC1 1` then `gpio set PC1 1` ---
	before = len(m.Lines())
	if _, err := flip.GPIOSet("PC1", 1); err != nil {
		t.Fatalf("GPIOSet: %v", err)
	}
	sl := gpioLinesAfter(m, before)
	mi, si := indexOf(sl, "gpio mode PC1 1"), indexOf(sl, "gpio set PC1 1")
	if mi < 0 || si < 0 {
		t.Fatalf("GPIOSet lines = %v; want both 'gpio mode PC1 1' and 'gpio set PC1 1'", sl)
	}
	if mi > si {
		t.Errorf("GPIOSet issued mode after set (mode@%d set@%d); want output mode first; lines=%v", mi, si, sl)
	}
}
