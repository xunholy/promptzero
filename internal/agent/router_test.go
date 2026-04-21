package agent

import (
	"context"
	"errors"
	"testing"

	"github.com/anthropics/anthropic-sdk-go"
)

func TestToolGroup_PrefixMapping(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		// Audit — always-on.
		{"audit_query", GroupMetaAudit},
		{"audit_export", GroupMetaAudit},
		{"audit_stats", GroupMetaAudit},
		// Meta utilities — always-on.
		{"list_devices", GroupMetaUtil},
		{"discover_apps", GroupMetaUtil},
		{"fileformat_read", GroupMetaUtil},
		{"fileformat_edit", GroupMetaUtil},
		{"fileformat_diff", GroupMetaUtil},
		// Flipper RF surfaces.
		{"subghz_transmit", GroupFlipperSubGHz},
		{"subghz_rx_raw", GroupFlipperSubGHz},
		{"ir_transmit", GroupFlipperIR},
		{"ir_decode_file", GroupFlipperIR},
		// NFC / RFID / iButton.
		{"nfc_detect", GroupFlipperNFC},
		{"nfc_apdu", GroupFlipperNFC},
		{"rfid_read", GroupFlipperRFID},
		{"ibutton_read", GroupFlipperIButton},
		// BadUSB.
		{"badusb_run", GroupFlipperBadUSB},
		{"badusb_validate", GroupFlipperBadUSB},
		// Hardware recon.
		{"gpio_set", GroupFlipperHW},
		{"i2c_scan", GroupFlipperHW},
		{"onewire_search", GroupFlipperHW},
		// WiFi.
		{"wifi_scan_ap", GroupMarauderWiFi},
		{"wifi_deauth", GroupMarauderWiFi},
		{"wifi_evil_portal_start", GroupMarauderWiFi},
		// Generation pipeline.
		{"generate_badusb", GroupGen},
		{"generate_subghz", GroupGen},
		{"run_payload", GroupGen},
		{"generate_deploy_run", GroupGen},
		// Workflows.
		{"workflow_nfc_badge_pipeline", GroupWorkflows},
		// Vision.
		{"analyze_image", GroupVision},
		// Flipper system surfaces.
		{"storage_list", GroupFlipperSystem},
		{"loader_mfkey", GroupFlipperSystem},
		{"system_info", GroupFlipperSystem},
		{"power_info", GroupFlipperSystem},
		{"flipper_raw_cli", GroupFlipperSystem},
		{"device_reboot", GroupFlipperSystem},
		// Unknown tool falls back to meta.util (safe default).
		{"completely_new_tool_invented_tomorrow", GroupMetaUtil},
	}
	for _, c := range cases {
		if got := ToolGroup(c.name); got != c.want {
			t.Errorf("ToolGroup(%q) = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestNarrowTools_NilRouterPassesThrough verifies the feature is
// strictly opt-in: a nil routerFn leaves the catalog unchanged, so
// agents created via New() keep the legacy behaviour.
func TestNarrowTools_NilRouterPassesThrough(t *testing.T) {
	tools := []anthropic.ToolUnionParam{
		tool("subghz_transmit", "x", nil),
		tool("wifi_scan_ap", "x", nil),
		tool("audit_query", "x", nil),
	}
	got := narrowTools(context.Background(), "scan wifi", tools, nil)
	if len(got) != len(tools) {
		t.Fatalf("nil router should pass through: got %d tools, want %d", len(got), len(tools))
	}
}

// TestNarrowTools_HappyPath demonstrates the primary win: a wifi-only
// request drops RF/NFC tools but keeps always-on meta groups.
func TestNarrowTools_HappyPath(t *testing.T) {
	tools := []anthropic.ToolUnionParam{
		tool("subghz_transmit", "x", nil),
		tool("nfc_detect", "x", nil),
		tool("ir_receive", "x", nil),
		tool("wifi_scan_ap", "x", nil),
		tool("wifi_deauth", "x", nil),
		tool("audit_query", "x", nil),   // always-on (meta.audit)
		tool("list_devices", "x", nil),  // always-on (meta.util)
		tool("discover_apps", "x", nil), // always-on (meta.util)
	}
	router := func(ctx context.Context, userInput string, avail map[string]bool) (map[string]bool, error) {
		return map[string]bool{GroupMarauderWiFi: true}, nil
	}
	got := narrowTools(context.Background(), "scan the nearest AP and deauth it", tools, router)

	// Expected: wifi_scan_ap, wifi_deauth, audit_query, list_devices, discover_apps
	gotNames := toolNameSet(got)
	wantNames := []string{"wifi_scan_ap", "wifi_deauth", "audit_query", "list_devices", "discover_apps"}
	if len(gotNames) != len(wantNames) {
		t.Fatalf("narrowed set size = %d, want %d (%v)", len(gotNames), len(wantNames), gotNames)
	}
	for _, n := range wantNames {
		if !gotNames[n] {
			t.Errorf("narrowed set missing %q: %v", n, gotNames)
		}
	}
	// Negative assertions — the unrelated groups must be gone.
	for _, n := range []string{"subghz_transmit", "nfc_detect", "ir_receive"} {
		if gotNames[n] {
			t.Errorf("narrowed set should not contain %q: %v", n, gotNames)
		}
	}
}

// TestNarrowTools_RouterErrorFallsBack ensures a broken router never
// breaks a session — the full catalog is returned unchanged.
func TestNarrowTools_RouterErrorFallsBack(t *testing.T) {
	tools := []anthropic.ToolUnionParam{
		tool("subghz_transmit", "x", nil),
		tool("wifi_scan_ap", "x", nil),
	}
	router := func(context.Context, string, map[string]bool) (map[string]bool, error) {
		return nil, errors.New("router blew up")
	}
	got := narrowTools(context.Background(), "x", tools, router)
	if len(got) != 2 {
		t.Fatalf("router error should fall back to full catalog: got %d", len(got))
	}
}

// TestNarrowTools_EmptySelectionFallsBack — the router returning zero
// groups is functionally equivalent to "I don't know", not "don't
// bother the model".
func TestNarrowTools_EmptySelectionFallsBack(t *testing.T) {
	tools := []anthropic.ToolUnionParam{
		tool("subghz_transmit", "x", nil),
		tool("wifi_scan_ap", "x", nil),
	}
	router := func(context.Context, string, map[string]bool) (map[string]bool, error) {
		return map[string]bool{}, nil
	}
	got := narrowTools(context.Background(), "x", tools, router)
	if len(got) != 2 {
		t.Fatalf("empty router response should fall back to full catalog: got %d", len(got))
	}
}

// TestNarrowTools_BelowFloorFallsBack — if the router picks nothing
// meaningful and the narrowed result drops under the floor, revert
// to the full catalog so the operator can always query state.
func TestNarrowTools_BelowFloorFallsBack(t *testing.T) {
	tools := []anthropic.ToolUnionParam{
		tool("subghz_transmit", "x", nil),
		tool("nfc_detect", "x", nil),
		tool("wifi_scan_ap", "x", nil),
		tool("ir_receive", "x", nil),
		tool("ibutton_read", "x", nil),
	}
	// Router picks one group; only one tool matches. No meta group
	// available -> filter yields 1 tool. Must fall back.
	router := func(context.Context, string, map[string]bool) (map[string]bool, error) {
		return map[string]bool{GroupFlipperSubGHz: true}, nil
	}
	got := narrowTools(context.Background(), "x", tools, router)
	if len(got) != 5 {
		t.Fatalf("below-floor result should fall back to full catalog: got %d", len(got))
	}
}

// TestNarrowTools_MultipleGroupsKept — a user spanning RF + vision
// gets both groups plus meta tools.
func TestNarrowTools_MultipleGroupsKept(t *testing.T) {
	tools := []anthropic.ToolUnionParam{
		tool("subghz_transmit", "x", nil),
		tool("nfc_detect", "x", nil),
		tool("analyze_image", "x", nil),
		tool("audit_query", "x", nil),
		tool("list_devices", "x", nil),
	}
	router := func(context.Context, string, map[string]bool) (map[string]bool, error) {
		return map[string]bool{GroupVision: true, GroupFlipperSubGHz: true}, nil
	}
	got := narrowTools(context.Background(), "analyze this photo and play back the signal", tools, router)
	names := toolNameSet(got)
	for _, want := range []string{"subghz_transmit", "analyze_image", "audit_query", "list_devices"} {
		if !names[want] {
			t.Errorf("missing expected tool %q in %v", want, names)
		}
	}
	if names["nfc_detect"] {
		t.Errorf("nfc_detect should have been trimmed: %v", names)
	}
}

func toolNameSet(tools []anthropic.ToolUnionParam) map[string]bool {
	out := make(map[string]bool, len(tools))
	for _, t := range tools {
		if t.OfTool == nil {
			continue
		}
		out[t.OfTool.Name] = true
	}
	return out
}

// TestEnableAndDisableDynamicCatalog — the toggles install and remove
// the routeGroups hook.
func TestEnableAndDisableDynamicCatalog(t *testing.T) {
	a := agentForModelTest("claude-sonnet-4-6", nil)
	if a.routerFn != nil {
		t.Fatalf("routerFn should start nil")
	}
	a.EnableDynamicCatalog()
	if a.routerFn == nil {
		t.Fatalf("EnableDynamicCatalog did not set routerFn")
	}
	a.DisableDynamicCatalog()
	if a.routerFn != nil {
		t.Fatalf("DisableDynamicCatalog did not clear routerFn")
	}
}
