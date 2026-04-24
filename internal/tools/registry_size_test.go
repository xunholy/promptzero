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
	// Wave 3: 84 (Wave 2 cumulative) + 62 new specs (no aliases) = 146.
	// The 62 new specs are:
	//   53 wifi_*  — 35 in both MCP+agent + 17 agent-only extras + 1 MCP-only
	//                (wifi_portscan_service)
	//    7 marauder_* — gps_data, gps_field, nmea, packet_count, storage_ls,
	//                   led_set, led_rainbow (all MCP-only before Wave 3)
	//    2 nrf24_*  — nrf24_sniff_start, nrf24_list_targets (AgentOnly)
	// None of the 62 new specs carry aliases.
	// AgentOnly specs: list_devices (Wave 1), subghz_bruteforce, ir_bruteforce
	// (Wave 2), nrf24_sniff_start, nrf24_list_targets (Wave 3) = 5 total.
	const expected = 146
	if initialRegistrySize != expected {
		t.Errorf("registry names at init = %d, want %d (wave-by-wave checked in §D of runbook)",
			initialRegistrySize, expected)
	}
}
