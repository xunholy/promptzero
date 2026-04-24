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

// initialSpecs is the snapshot of the full production registry captured before
// any test can call resetForTest(). TestRegistryCoverage iterates over this
// slice instead of calling tools.All() at test-run time, which would see a
// partial registry if TestNames_IncludesAliases (or any other spec_test.go
// test) has already reset it.
var initialSpecs []tools.Spec

func TestMain(m *testing.M) {
	// tools.Names() counts every invocable name: canonical names plus aliases.
	// The runbook §D cumulative counts use this metric (e.g. device_info +
	// system_info alias = 2 names from 1 Spec; Wave 0 contributes 4 names,
	// but the Wave 0 test used All() = 3, so Wave 1 switches to Names()
	// to align with the runbook's "34 entries" target).
	initialRegistrySize = len(tools.Names())
	initialSpecs = tools.All()
	os.Exit(m.Run())
}

func TestRegistrySize(t *testing.T) {
	// Wave 3: 84 (Wave 2 cumulative) + 62 new specs (no aliases) = 146.
	// Wave 4: 146 + 33 new AgentOnly specs (no aliases) = 179.
	// The 33 new specs are:
	//   1 nfc_read_save
	//   8 generate_* + run_payload + generate_deploy_run (= 10 total in gen family)
	//   1 analyze_image
	//   1 discover_apps
	//   1 docs_search
	//   3 audit_* (audit_query, audit_export, audit_stats)
	//   3 target_* (target_remember, target_recall, target_forget)
	//   2 nrf24_mousejack_start + nrf24_payload_build (added to nrf24.go)
	//   4 *_build (subghz_build, rfid_build, ir_build, nfc_build)
	//   2 subghz_bruteforce_generate + subghz_freq_sweep
	//   8 workflow_* (3 AgentOnly:false + 5 AgentOnly:true)
	// None of the 33 new specs carry aliases.
	// AgentOnly specs cumulative: list_devices (W1), subghz_bruteforce,
	// ir_bruteforce (W2), nrf24_sniff_start, nrf24_list_targets (W3),
	// plus all 33 Wave 4 specs except the 3 MCP-accessible workflows = 38 total.
	// Wave 5: no new specs — deletion only.
	const expected = 179
	if initialRegistrySize != expected {
		t.Errorf("registry names at init = %d, want %d (wave-by-wave checked in §D of runbook)",
			initialRegistrySize, expected)
	}
}
