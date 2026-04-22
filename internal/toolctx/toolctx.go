// Package toolctx serves static per-tool cheat sheets the agent
// appends to tool descriptions at catalog registration time. Each
// sheet covers the "things the model forgets" for a given tool —
// file format headers, command quirks, bit-layout conventions —
// content that would otherwise bloat the system prompt and isn't
// specific enough to warrant a full RAG lookup.
//
// The sheets are bundled at compile time so the binary stays
// self-contained. Adding a sheet is a new entry in the sheets map
// below; the tool builder picks it up automatically via
// EnrichDescription.
package toolctx

import "strings"

// sheets maps tool name → cheat sheet markdown. Keep each sheet
// under ~400 tokens so the full catalog stays cache-friendly
// (prompt caching amortises cost, but oversized descriptions hurt
// the initial cache-miss turn).
var sheets = map[string]string{
	"subghz_build": `Princeton/PT2240 remotes use 24-bit keys, TE=400µs, preset OOK650Async.
ISM bands: 315/433.92/868/915 MHz. Key hex is space-separated, 8 bytes padded from LSB.
Full spectrum unlocked on modded firmware — no frequency filter.`,

	"rfid_build": `EM4100 = 40-bit fixed, 10 hex chars. HIDProx = 26-bit, varies.
T5577 blanks accept any protocol via mode switch.
"Key type" matches the protocol name verbatim (case-sensitive).`,

	"ir_build": `Parsed signals: NEC (32-bit address+command), Samsung32, Sony SIRC12/15/20.
Raw signals: frequency in Hz (usually 38000), duty_cycle 0.33, data as int array of microsecond timings.
Each IRSignal needs a non-empty Name; duplicates allowed across buttons.`,

	"nfc_build": `Mifare Classic 1K: 4 or 7-byte UID, 64 blocks of 16 bytes.
NTAG213/215/216: always 7-byte UID, 45/135/231 pages of 4 bytes.
ATQA/SAK are ISO14443 response bytes; omit for NTAGs. Block 0 carries the UID on Classic.`,

	"subghz_bruteforce_generate": `Encodes Princeton OOK: bit=1 → (+3*TE, -TE); bit=0 → (+TE, -3*TE); sync gap (+TE, -31*TE) between keys.
Cap: 10000 keys per file. For wider sweeps, issue successive calls with sliding start/end.
Default TE=400µs matches PT2240/SC5262. RawData produced as int32 microsecond deltas.`,

	"badusb_run": `DuckyScript payloads: DELAY <ms>, STRING <text>, GUI / CTRL / ALT / SHIFT key combos.
Target OS matters for keyboard layouts and shortcuts (WIN+R vs CMD+SPACE).
Add DELAY 2000 after WIN+R so the Run dialog opens before typing. Loops need an explicit BREAK.`,

	"wifi_evil_portal_start": `Portal HTML lives at /ext/apps_data/evil_portal/index.html by default.
Form action MUST be /get (the Marauder FAP looks for that path); method MUST be GET.
Credential field names MUST be exactly "email" and "password". No external resources — all CSS/JS inline.`,

	"wifi_deauth": `Select the AP via wifi_select_ap before deauth; otherwise the attack falls back to broadcast.
Duration in seconds; anything above 60s on a single AP tends to trip vendor rate-limits and look inert.
Pair with wifi_sniff_pmkid to capture the handshake the deauth forces.`,

	"wifi_sniff_pmkid": `PMKID capture is passive — the AP must voluntarily emit an M1 frame.
Runs best after a fresh deauth forced a reconnect. channel=0 auto-scans.
Output contains a hex PMKID + BSSID:SSID on success; empty means no suitable handshake observed.`,

	"nfc_emulate": `Emulates the saved .nfc file as a tag. Reader sees the UID + ATQA + SAK from the file.
MIFARE Classic emulation requires block contents to match for full reader interaction (door systems check block 0 + Access Bits).
NTAG emulation is UID-only — write-back operations from the reader are not persisted.`,

	"rfid_write": `Writes onto a blank T5577 — original fob stays intact.
Protocol + Data must match (EM4100 expects 10 hex chars; HIDProx varies).
Write through the Flipper's back antenna (LF side), not the NFC face.`,

	"subghz_receive": `Captures OOK/2FSK in the selected band. duration_seconds bounds the scan.
Output is a series of Protocol+Frequency+Key+Bit blocks (one per detected signal) plus raw lines.
Freq+bit mismatch with the target device yields empty candidates — try adjacent ISM bands.`,
}

// Get returns the cheat sheet for toolName, or "" when no sheet is
// bundled. Safe to call on any tool name — absent sheets are
// treated as "no extra context" rather than an error.
func Get(toolName string) string {
	return sheets[toolName]
}

// Has reports whether a cheat sheet is registered for toolName.
// Used by tests to lock sheet presence on high-priority tools so a
// future refactor can't silently drop them.
func Has(toolName string) bool {
	_, ok := sheets[toolName]
	return ok
}

// EnrichDescription appends the cheat sheet for toolName to an
// existing description, prefixed with a stable "Context:" section
// marker. When no sheet exists the description passes through
// unchanged. Used by the tool catalog at registration time.
func EnrichDescription(toolName, description string) string {
	sheet := Get(toolName)
	if sheet == "" {
		return description
	}
	var b strings.Builder
	b.WriteString(description)
	b.WriteString("\n\nContext:\n")
	b.WriteString(sheet)
	return b.String()
}

// ToolsWithSheets returns every tool name that has a bundled
// cheat sheet, sorted. Useful for the /tools REPL command and for
// tests that want to enforce coverage on specific tool families.
func ToolsWithSheets() []string {
	out := make([]string, 0, len(sheets))
	for name := range sheets {
		out = append(out, name)
	}
	// sort not imported here — callers that need sorted slices can
	// sort on their own. Order stability across runs is a test
	// concern, not a correctness one.
	return out
}
