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

import (
	"sort"
	"strings"
)

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

	"nfc_read_save": `THIS is the tool for "scan my fob / badge / card / tag" — NOT nfc_detect alone.
Does detect → map Type to DeviceType → BuildNFC → verify → write /ext/nfc/<name>.nfc in one call. Default timeout 15s.
Classic-family tags: the UID-only save works as a first pass, but full block cloning needs sector keys (chain loader_mfkey + loader_mifare_nested). NTAG/Ultralight: UID + ATQA + SAK is usually sufficient.
If no tag detected after the timeout, the operator likely needs to reposition — flat against the Flipper back (NFC antenna side). For 125 kHz LF prox fobs, use rfid_read.`,

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

	"subghz_rx_raw": `Records raw OOK/2FSK samples to a .sub file rather than decoding protocol.
Use when subghz_receive returns nothing because the protocol is unknown — rx_raw captures the waveform so subghz_decode can be tried later, or the file can replay as-is via subghz_transmit.
Files can get large: ~2KB/s at 433 MHz with moderate RF activity.`,

	"rfid_raw_read": `Captures raw 125 kHz LF modulation to a .lfrfid file. Complementary to rfid_read, which parses a known protocol and fails on unknown ones.
Use raw_read when the badge ISN'T EM4100/HIDProx/Indala/AWID/FDX, then rfid_raw_analyze for pulse stats + best-guess protocol.
Typical duration: 2-5s. Longer captures help with noisy readers.`,

	"rfid_raw_analyze": `Reads a .lfrfid raw capture and reports frequency, duty cycle, pulse sum, duration sum, protocol guess.
"Protocol: Unknown" + low pulse count usually means the card wasn't close enough to the antenna — retry.
Average field near NaN indicates no modulation detected; try a different dwell position on the reader pad.`,

	"ibutton_read": `Reads a Dallas 1-Wire contact key. Auto-detects protocol: Dallas (DS1990A, 64-bit ROM), Cyfral, Metakom.
Output shape: Key type: <proto> | Data: <hex>. 64-bit Dallas is the most common fob format.
Firm contact matters — the probe needs ~100ms of steady contact to clock out the ROM.`,

	"ibutton_emulate": `Emulates a previously-read iButton fob. Requires Protocol + Data (hex) matching the original read.
Dallas fobs expect a 8-byte ROM including the 1-byte family code prefix and 1-byte CRC suffix.
Emulation tx is bidirectional; the reader polls, the Flipper responds — so the antenna side (iButton pins) must be the contact.`,

	"ibutton_write": `Writes onto a rewritable iButton blank (e.g. RW1990, TM2004).
Protocol + Data must match the original fob. Most real building fobs are read-only DS1990A and can only be cloned to RW blanks.
If the write fails with "no response", the blank is either factory-locked or the contact positioning is off.`,

	"nfc_apdu": `Sends raw ISO14443 APDU frames to a detected card. Use for EMV (payment), DESFire, MRTD (passport).
SELECT PPSE = "00 A4 04 00 0E 32 50 41 59 2E 53 59 53 2E 44 44 46 30 31 00". Response starts with TLV tag 6F.
Common AIDs: Visa=A000000003, Mastercard=A000000004, Amex=A000000025. No response → card not selected or 14443-4 state missed.`,

	"loader_mfkey": `Launches the MFKey32 FAP for Mifare Classic key recovery from captured reader nonces.
Prerequisite: nonces are already on the SD card from a "key32.log" capture (nfc detect with a target reader, or sniffed traffic).
MFKey32 runs offline and brute-forces in ~minutes. Keys land in /ext/nfc/mfkey32.nfc; merge them into your .nfc target file's key block.`,

	"loader_mifare_nested": `Launches the Mifare Nested FAP for sector-key recovery when AT LEAST ONE key is already known.
Standard chain: nfc_detect → try default keys (FFFFFFFFFFFF, A0A1A2A3A4A5) → if one hits, loader_mifare_nested to derive the rest.
Nested is fast (seconds per sector) but fails against hardened cards — those need hardnested, which the firmware does not yet include.`,

	"loader_nfc_magic": `Launches the NFC Magic FAP — writes UIDs and locked blocks to "magic" Mifare Classic tags (gen1a, gen4).
Use only with known-compatible magic blanks; gen1a accepts unlock via "direct write" command, gen2 requires backdoor key.
Most modern access-control readers detect and reject gen1a clones — test on the target reader before the engagement.`,

	"loader_picopass": `HID iClass / PicoPass tooling via the PicoPass FAP.
Prerequisites: a PicoPass-compatible antenna and the iClass bypass keys already on the SD card at /ext/nfc/assets/iclass_bypass_keys.bin.
PicoPass cards are HF (13.56 MHz), NOT to be confused with HID Prox (LF 125 kHz via rfid_read).`,

	"loader_seader": `SEADER FAP — advanced iClass SE / SEOS attack toolkit (beyond PicoPass scope).
Requires SEOS diversification keys on the SD card; factory keys are widely published for SE but SEOS itself remains hard target.
Use for controlled-lab authorised engagements only — many deployments of iClass SE are high-value access systems.`,

	"nrf24_sniff_start": `Launches the NRF24 Sniffer FAP. Passive 2.4 GHz scan that writes captured peripheral addresses to /ext/apps_data/nrfsniff/addresses.txt (one ADDR,RATE per line).
Requires an NRF24L01+ devboard wired to the GPIO header (pins 2,3,4,5,6,7 — CE=PA2 typical). The Flipper has no nrf24 CLI; operator drives the FAP UI and exits via the back button.
Momentum firmware typically writes to the nrfsniff/ path; Unleashed/RogueMaster variants may use nrf24_sniffer/ — check both if the list is empty.`,

	"nrf24_list_targets": `Parses /ext/apps_data/nrfsniff/addresses.txt and returns structured targets.
Rate decoding: 1=1 Mbps (Microsoft wireless), 2=2 Mbps (Logitech Unifying / MX family), 250=250 kbps (rare).
Empty result means run nrf24_sniff_start first. Warnings surface malformed lines without failing the read.`,

	"nrf24_payload_build": `Synthesises a DuckyScript payload for /ext/mousejacker/<name>.txt. Runs the BadUSB static validator (same lexical format), so destructive patterns (rm -rf, reverse shells, persistence) block by default.
Mousejack-specific rule: DELAY capped at 5000 ms by default — 2.4 GHz injection loses sync on longer pauses. Override via max_delay_ms if you know better.
Common injection patterns: GUI r / DELAY 500 / STRING powershell -c "..." / ENTER. Keep scripts under ~30 lines for reliability.`,

	"nrf24_mousejack_start": `Launches the NRF24 Mousejacker FAP. The FAP reads targets from /ext/apps_data/nrfsniff/addresses.txt and payloads from /ext/mousejacker/ — populate BOTH before launching.
Critical-risk: this leads directly to keystroke injection into the paired host, same blast radius as BadUSB.
PromptZero cannot script the FAP beyond launching it; keystroke sequence runs under operator UI control. Back button exits.`,
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
// cheat sheet, sorted alphabetically. Useful for the /tools REPL
// command and for tests that want to enforce coverage on specific
// tool families.
//
// The sort is load-bearing for the docstring contract: Go map
// iteration is randomised, so without it the slice order shuffles
// every call and any caller relying on a stable layout (a test
// comparing returned[0], the /tools UI rendering top-N families,
// a future regression-baseline checker) would silently flake.
func ToolsWithSheets() []string {
	out := make([]string, 0, len(sheets))
	for name := range sheets {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
