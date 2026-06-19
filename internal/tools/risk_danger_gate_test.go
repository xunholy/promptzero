package tools

import (
	"testing"

	"github.com/xunholy/promptzero/internal/risk"
)

// dangerousTools is the curated set of genuinely active / destructive tools —
// active RF/IR transmission, keystroke injection, emulation, device reflash/
// reboot, the unrestricted CLI passthrough, and the offensive workflows. The
// MCP consent gate (internal/mcp.add) refuses risk>=High unless the operator
// opts in, so EVERY tool here MUST classify >=High or it is reachable ungated
// by any local MCP client. This guard pins that invariant: it caught
// ir_transmit_raw silently sitting at Medium (bucketed next to the passive
// ir_receive) while its sibling ir_transmit was High.
//
// Adding a new active-TX / injection / destructive tool? Add it here AND
// classify it >=High in risk.go + its Spec — that is the safety contract.
var dangerousTools = []string{ //nolint:gochecknoglobals
	"wifi_deauth", "wifi_beacon_spam", "wifi_ble_spam", "wifi_karma",
	"wifi_sae_flood", "wifi_csa_attack", "wifi_probe_flood",
	"wifi_evil_portal_start", "wifi_attack_badmsg", "wifi_attack_quiet",
	"wifi_attack_sleep", "wifi_bt_spoof_airtag",
	"nrf24_mousejack_start",
	"ir_bruteforce", "ir_transmit", "ir_transmit_raw",
	"subghz_bruteforce", "subghz_transmit", "subghz_tx_key",
	"device_reboot", "power_reboot_dfu", "update_install", "flipper_raw_cli",
	"generate_deploy_run", "run_payload",
	"rfid_write", "nfc_emulate", "crypto_store_key",
	"workflow_mousejack", "workflow_rolljam_lab_demo",
}

func TestDangerousToolsGatedHigh(t *testing.T) {
	for _, name := range dangerousTools {
		if _, ok := Get(name); !ok {
			t.Errorf("dangerousTools lists %q which is not a registered tool — "+
				"remove or rename it (the safety list must stay accurate)", name)
			continue
		}
		if lvl := risk.Classify(name); lvl < risk.High {
			t.Errorf("active/destructive tool %q is %s (< High) — it is exposed UNGATED over MCP; "+
				"classify it >=High in risk.go and its Spec", name, lvl.String())
		}
	}
}
