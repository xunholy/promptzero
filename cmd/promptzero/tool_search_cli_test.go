package main

import (
	"testing"

	"github.com/xunholy/promptzero/internal/agent"
)

// TestRankCatalog verifies /tools <query> wires the catalogue (name, aliases,
// group, description) into the shared ranker: an exact name ranks first, a task
// word reaches a tool via the synonym map + group, and a no-match query yields
// nothing — the CLI's half of the cross-surface discovery layer.
func TestRankCatalog(t *testing.T) {
	cat := []agent.ToolCatalogEntry{
		{Name: "subghz_bruteforce", Group: "subghz", Description: "brute-force a fixed-code garage/gate remote"},
		{Name: "wifi_pmkid_hc22000", Group: "wifi", Description: "convert a PMKID into a hashcat line for cracking the WPA password"},
		{Name: "nfc_mfu_rdbl", Aliases: []string{"mifare_ultralight_read"}, Group: "nfc", Description: "read a card block"},
		{Name: "device_info", Group: "flipper.system", Description: "firmware version + hardware revision"},
	}

	// Exact name ranks first.
	if got := rankCatalog(cat, "subghz_bruteforce", 0); len(got) == 0 || got[0].Name != "subghz_bruteforce" {
		t.Fatalf("exact name did not rank first: %+v", got)
	}

	// Task synonym reaches the subghz tool via 'garage'.
	got := rankCatalog(cat, "garage", 0)
	found := false
	for _, r := range got {
		if r.Name == "subghz_bruteforce" {
			found = true
		}
	}
	if !found {
		t.Errorf("'garage' did not surface subghz_bruteforce via synonym: %+v", got)
	}

	// Alias is searchable (Group/Aliases must flow through from the catalogue).
	gotAlias := rankCatalog(cat, "ultralight", 0)
	if len(gotAlias) == 0 || gotAlias[0].Name != "nfc_mfu_rdbl" {
		t.Errorf("alias query did not surface nfc_mfu_rdbl: %+v", gotAlias)
	}

	// No-match query is empty, not a panic.
	if got := rankCatalog(cat, "zzqqxx-nope", 0); len(got) != 0 {
		t.Errorf("no-match query: got %d results, want 0", len(got))
	}
}
