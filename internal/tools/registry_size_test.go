package tools_test

import (
	"os"
	"testing"

	"github.com/xunholy/promptzero/internal/tools"
)

// initialRegistrySize captures the number of registered names (canonical + aliases)
// after all package init() functions have run — before any test calls resetForTest()
// (which lives in spec_test.go and resets the global registry between unit tests).
// Captured in TestMain so it is always the pre-test, post-init count regardless
// of test ordering.
var initialRegistrySize int

func TestMain(m *testing.M) {
	// tools.Names() counts every invocable name: canonical names plus aliases.
	// The runbook §D cumulative counts use this metric (e.g. device_info +
	// system_info alias = 2 names from 1 Spec; Wave 0 contributes 4 names,
	// but the Wave 0 test used All() = 3, so Wave 1 switches to Names()
	// to align with the runbook's "34 entries" target).
	initialRegistrySize = len(tools.Names())
	os.Exit(m.Run())
}

func TestRegistrySize(t *testing.T) {
	// Wave 2: 34 (Wave 1 cumulative) + 50 new specs (no aliases) = 84.
	// The 50 new specs are: 7 subghz + 6 ir + 8 nfc (7 new primitives +
	// nfc_detect from Wave 0 already counted) + 14 loader FAPs + 7 rfid +
	// 3 ibutton + 2 badusb + 1 js + 3 fileformat = 50 new names.
	// 3 of these are AgentOnly: list_devices (Wave 1), subghz_bruteforce,
	// ir_bruteforce.
	const expected = 84
	if initialRegistrySize != expected {
		t.Errorf("registry names at init = %d, want %d (wave-by-wave checked in §D of runbook)",
			initialRegistrySize, expected)
	}
}
