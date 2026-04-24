package flipper

import (
	"regexp"
	"strconv"
	"strings"
)

// Capabilities captures the firmware-specific CLI surface of the connected
// Flipper, detected from `device_info` at connect time. Different custom
// firmwares (stock, Unleashed, RogueMaster, Xtreme, Momentum, ...) expose
// different CLI commands and behaviours; wrappers branch on these flags to
// stay portable across all five active forks.
//
// Field ordering: identity → CLI surface → RF/NFC quirks → apps/FAPs →
// storage → marauder. Existing fields are preserved byte-for-byte; new
// fields are appended in their sections so callers that embed Capabilities
// by value are not broken.
type Capabilities struct {
	// ===== Identity (existing, preserved) =====
	FirmwareFork    string // "" (stock/OFW), "Unleashed", "Momentum", "Xtreme", "RogueMaster", …
	FirmwareVersion string // fork-specific version string from firmware_version
	FirmwareCommit  string // short git SHA from firmware_commit
	FirmwareDate    string // build date string from firmware_build_date (DD-MM-YYYY)
	HardwareUID     string // STM32 unique ID (16 hex chars) from hardware_uid
	HardwareName    string // user-settable dolphin name from hardware_name

	// ===== Identity (new) =====
	// FirmwareBand is the resolved fork+version band, e.g. "momentum/mntm-dev",
	// "unleashed/unlshd-086", "stock/1.0.x". See resolveBand() for the full
	// value set (firmware-matrix.md §3.6).
	FirmwareBand        string
	FirmwareAPIMajor    int    // from firmware_api_major (numeric); 80-83=OFW 0.10x, 85+=OFW 1.x, 77-79=Momentum, 70-72=Xtreme, 86-87=Unleashed/RM
	FirmwareAPIMinor    int    // from firmware_api_minor
	FirmwareCommitDirty bool   // from firmware_commit_dirty ("1" → true); nightly-build signal
	FirmwareOriginGit   string // from firmware_origin_git (upstream repo URL)
	HardwareRegion      string // from hardware_region — string form (EU/US/JP/WW or numeric)
	HardwareVer         int    // from hardware_ver (board revision; F7 production = 13)
	// DeviceInfoKeyStyle indicates which key separator the parser saw.
	// Always "underscore" when populated via device_info (the standard path);
	// set to "dotted" if a future caller uses `info device` output instead.
	DeviceInfoKeyStyle string

	// ===== CLI surface (existing, preserved) =====
	// PowerInfoCmd is the CLI verb that returns power/battery information.
	// All modern forks use "info power"; empty means unavailable.
	PowerInfoCmd           string // "info power" on all modern forks
	HasNFCSubshell         bool   // `nfc` subshell present; false only on Xtreme
	SubGHzNeedsDev         bool   // `subghz tx/rx` requires a trailing `<device>` arg (0=INT, 1=EXT)
	NFCFlaggedArgs         bool   // NFC subshell uses flag-based args (-p, -d, -b) rather than positional
	SubGHzRxRawHasFilePath bool   // `subghz rx_raw` accepts a file-path arg (false on all modern forks — streams to stdout)

	// ===== CLI surface (new — architect additions §C.1) =====
	// JSEngineKind is the CLI verb prefix for the JS engine ("mjs" on all
	// four active forks including archived Xtreme; firmware-matrix.md §4.1
	// found no divergence despite the runbook's earlier claim).
	JSEngineKind           string // "mjs" universally; "" if JS is absent
	HasBLESpam             bool   // BLE Spam FAP present (Momentum/Xtreme in-tree; RM optimistic default)
	HasSubGHzBruteforcer   bool   // Sub-GHz Bruteforcer FAP available on this fork
	HasMouseJackerFAP      bool   // NRF24 Mousejacker FAP (NRF24 add-on required)
	HasSeaderFAP           bool   // HID iCLASS Seader FAP (Momentum/Unleashed/RM)
	HasPicopassFAP         bool   // PicoPass FAP (all custom forks)
	HasNFCMagicFAP         bool   // NFC Magic card-writer FAP (all custom forks)
	HasMFKeyFAP            bool   // MFKey32 FAP (all custom forks; Unleashed ships it in-tree)
	HasMifareNestedFAP     bool   // Mifare Nested attack FAP (all custom forks)
	UniversalIRLibraryName string // SD path for the universal IR library; "assets/infrared/assets" (stock/Unleashed/RM) vs "infrared/assets" (Momentum/Xtreme)

	// ===== CLI surface (new — research additions §4.2) =====
	HasStorageFormatExt    bool // `storage format_ext` verb present (all custom forks; absent on stock OFW)
	HasSubGHzEncryptKeeloq bool // `subghz encrypt_keeloq` verb present (all custom forks)
	HasSubGHzChat          bool // `subghz chat` verb present (universal — all five forks)
	HasPsCmd               bool // `ps` alias for `top` present (Momentum + Xtreme)
	HasClearCmd            bool // `clear` terminal-clear command present (Momentum only)

	// ===== Storage quirks (new) =====
	// StorageExtFatLabel is the FAT volume label of the SD card.
	// Defaults to "Flipper SD"; Momentum freshly formats with "MOMENTUM".
	StorageExtFatLabel string
	// SnapshotPrefix is the root path for pre-write SD snapshots used by /rewind.
	SnapshotPrefix string

	// ===== Marauder-side (probed separately; not set by device_info) =====
	// MarauderDetected and MarauderCompatBand are set by the Marauder
	// connect path, not by DetectCapabilities. Left as zero-value TODOs
	// here for a follow-up v0.5.1 research task (firmware-matrix.md §6 Q6).
	MarauderDetected   bool
	MarauderCompatBand string
}

// FriendlyFork returns a display-ready fork name, falling back to "stock"
// when the fork field is empty (OFW omits firmware_origin_fork entirely).
func (c Capabilities) FriendlyFork() string {
	if c.FirmwareFork == "" {
		return "stock"
	}
	return c.FirmwareFork
}

// ── Band resolution ───────────────────────────────────────────────────────────
//
// Each active fork has a distinct firmware_version format. resolveBand maps
// (fork, version) to a canonical band string that can be stored in
// FirmwareBand and compared by tool handlers without re-parsing.
// See firmware-matrix.md §3 for the full regex set and fixture verification.

var (
	ofwSemverRE       = regexp.MustCompile(`^(\d+)\.(\d+)\.\d+$`)
	unleashedBandRE   = regexp.MustCompile(`^unlshd-(\d+)$`)
	momentumRelRE     = regexp.MustCompile(`^mntm-(\d{3,})$`)
	momentumDevRE     = regexp.MustCompile(`^mntm-dev`)
	momentumLegacyRE  = regexp.MustCompile(`^0\.(\d+)\.(\d+)$`)
	xtremeBandRE      = regexp.MustCompile(`^xfw-(\d{4})_\d{8}$`)
	roguemasterBandRE = regexp.MustCompile(`^rm(\d{4})-\d{4}-`)
)

// resolveBand returns the canonical FirmwareBand string for a given
// (fork, version) pair. Both inputs are lower-cased internally so the
// function is case-insensitive.
func resolveBand(fork, version string) string {
	f := strings.ToLower(fork)
	vl := strings.ToLower(version)

	switch f {
	case "", "flipper", "official":
		// OFW / stock
		if vl == "" {
			return "stock/unknown"
		}
		if vl == "dev" {
			return "stock/dev"
		}
		if m := ofwSemverRE.FindStringSubmatch(vl); m != nil {
			return "stock/" + m[1] + "." + m[2] + ".x"
		}
		return "stock/" + majorMinor(vl)

	case "unleashed":
		if m := unleashedBandRE.FindStringSubmatch(vl); m != nil {
			return "unleashed/unlshd-" + m[1]
		}
		return "unleashed/" + majorMinor(vl)

	case "momentum":
		if momentumDevRE.MatchString(vl) {
			return "momentum/mntm-dev"
		}
		if momentumRelRE.MatchString(vl) {
			return "momentum/mntm-release"
		}
		if momentumLegacyRE.MatchString(vl) {
			return "momentum/mntm-stable-legacy"
		}
		return "momentum/latest"

	case "xtreme":
		if m := xtremeBandRE.FindStringSubmatch(vl); m != nil {
			return "xtreme/xfw-" + m[1]
		}
		return "xtreme/archived"

	case "roguemaster":
		if m := roguemasterBandRE.FindStringSubmatch(vl); m != nil {
			return "roguemaster/rm-" + m[1]
		}
		return "roguemaster/latest"

	default:
		return f + "/" + majorMinor(vl)
	}
}

// majorMinor strips a leading "v"/"V" and collapses the version to
// "<major>.<minor>.x". Used as a fallback bucket in resolveBand when no
// fork-specific regex matches.
func majorMinor(v string) string {
	v = strings.TrimPrefix(strings.TrimPrefix(v, "v"), "V")
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return v
	}
	return parts[0] + "." + parts[1] + ".x"
}

// ── Capability detection ──────────────────────────────────────────────────────

// detectCapabilities parses `device_info` output (newline-separated
// "key: value" pairs) and derives the complete Capabilities bitmap for the
// connected firmware. The function is called by DetectCapabilities (serial.go)
// and in unit tests via hardcoded fixtures.
//
// Correction summary (firmware-matrix.md §6 vs earlier runbook §C defaults):
//
//	Q1 — PowerInfoCmd stock default changed to "info power" (was "power_info").
//	     No modern fork registers power_info; every fork uses info power.
//	Q2 — SubGHzRxRawHasFilePath stock default changed to false (was true).
//	     Every modern fork streams rx_raw to stdout; none accepts a file-path arg.
//	Q3 — NFCFlaggedArgs stock default changed to true (was false).
//	     Modern OFW (API ≥ 80) ships the flagged NFC CLI; only pre-consolidation
//	     OFW (API < 80) used positional args.
//	Q4 — JSEngineKind is "mjs" on all four active forks; no fork diverged.
func detectCapabilities(deviceInfo string) Capabilities {
	c := Capabilities{}

	// ── Parse device_info key:value lines ────────────────────────────────────
	for _, raw := range strings.Split(deviceInfo, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		// Existing identity fields
		case "firmware_origin_fork":
			c.FirmwareFork = val
		case "firmware_version":
			c.FirmwareVersion = val
		case "firmware_commit":
			c.FirmwareCommit = val
		case "firmware_build_date":
			c.FirmwareDate = val
		case "hardware_uid":
			c.HardwareUID = val
		case "hardware_name":
			c.HardwareName = val

		// New identity fields
		case "firmware_api_major":
			if n, err := strconv.Atoi(val); err == nil {
				c.FirmwareAPIMajor = n
			}
		case "firmware_api_minor":
			if n, err := strconv.Atoi(val); err == nil {
				c.FirmwareAPIMinor = n
			}
		case "firmware_commit_dirty":
			c.FirmwareCommitDirty = val == "1"
		case "firmware_origin_git":
			c.FirmwareOriginGit = val
		case "hardware_region":
			c.HardwareRegion = val
		case "hardware_ver":
			if n, err := strconv.Atoi(val); err == nil {
				c.HardwareVer = n
			}
		}
	}

	// ── Stock baseline defaults (applied before per-fork overrides) ───────────
	//
	// These are the "unknown fork" safe defaults. Per-fork cases below override
	// only the fields that actually differ. Corrections Q1-Q4 applied here.
	c.PowerInfoCmd = "info power" // Q1 correction: was "power_info"
	c.HasNFCSubshell = true
	c.SubGHzNeedsDev = false         // base default; overridden per-fork and for OFW ≥ 1.x
	c.SubGHzRxRawHasFilePath = false // Q2 correction: was true; all modern forks stream to stdout
	c.NFCFlaggedArgs = true          // Q3 correction: was false; all modern forks use flagged NFC CLI
	c.JSEngineKind = "mjs"           // Q4 correction: universal; no fork diverged
	c.UniversalIRLibraryName = "assets/infrared/assets"
	c.StorageExtFatLabel = "Flipper SD"
	c.SnapshotPrefix = "/any/.flipperzero_snapshots/"
	c.DeviceInfoKeyStyle = "underscore"
	c.HasSubGHzChat = true // universal — all five forks

	// ── Per-fork overrides ────────────────────────────────────────────────────
	switch strings.ToLower(c.FirmwareFork) {
	case "", "flipper", "official":
		// Stock OFW. SubGHzNeedsDev is version-gated: the dual-arg form
		// (subghz rx <freq> <device>) was added around OFW 1.0 (API ≥ 85).
		// Pre-1.0 OFW (API 80-83) uses single-arg form. Safest fallback for
		// unknown API is false (single-arg — works on old devices).
		if c.FirmwareAPIMajor >= 85 {
			c.SubGHzNeedsDev = true
		}
		// NFCFlaggedArgs gate: OFW with API < 80 (pre-consolidation) or unknown
		// API (== 0, device_info lacks the field) uses positional args.
		// firmware-matrix.md §6 Q3: only OFW with API >= 80 gets flagged.
		if c.FirmwareAPIMajor < 80 {
			c.NFCFlaggedArgs = false
		}

	case "unleashed":
		// Unleashed inherits from OFW but diverges on FAP availability.
		// Conservative FAP defaults per firmware-matrix.md §6 Q8 (Unleashed):
		// assume FAPs absent unless loader list confirms; exception is MFKey
		// which Unleashed ships in-tree.
		c.SubGHzNeedsDev = true
		c.HasMFKeyFAP = true
		c.HasMifareNestedFAP = true
		c.HasNFCMagicFAP = true
		c.HasPicopassFAP = true
		c.HasSeaderFAP = true
		c.HasMouseJackerFAP = true
		c.HasSubGHzBruteforcer = true
		c.HasStorageFormatExt = true
		c.HasSubGHzEncryptKeeloq = true

	case "roguemaster":
		// RogueMaster inherits Unleashed's CLI surface and adds its own
		// plugin bundle. Optimistic FAP defaults per firmware-matrix.md §6 Q8
		// (RogueMaster bundles everything by claim).
		c.SubGHzNeedsDev = true
		c.HasBLESpam = true
		c.HasMFKeyFAP = true
		c.HasMifareNestedFAP = true
		c.HasNFCMagicFAP = true
		c.HasPicopassFAP = true
		c.HasSeaderFAP = true
		c.HasMouseJackerFAP = true
		c.HasSubGHzBruteforcer = true
		c.HasStorageFormatExt = true
		c.HasSubGHzEncryptKeeloq = true

	case "xtreme":
		// Xtreme (archived 2024-11-19). No NFC subshell; drops positional
		// NFC CLI argument so NFCFlaggedArgs is irrelevant.
		// JSEngineKind: research confirmed all XFW-0053 builds ship js_app on
		// mJS (firmware-matrix.md §4.1 Q4 correction — runbook incorrectly
		// said Xtreme dropped JS).
		c.HasNFCSubshell = false
		c.SubGHzNeedsDev = true
		c.HasBLESpam = true
		c.HasSubGHzBruteforcer = true
		c.HasNFCMagicFAP = true
		c.HasMFKeyFAP = true
		c.HasMifareNestedFAP = true
		c.HasPicopassFAP = true
		// Xtreme does NOT ship MouseJacker or Seader by default.
		c.UniversalIRLibraryName = "infrared/assets"
		c.HasStorageFormatExt = true
		c.HasSubGHzEncryptKeeloq = true
		c.HasPsCmd = true

	case "momentum":
		// Momentum is the most feature-complete fork. Streams rx_raw to stdout
		// (SubGHzRxRawHasFilePath stays false from default), uses flagged NFC
		// args, and ships its own label for freshly-formatted SD cards.
		c.SubGHzNeedsDev = true
		c.HasBLESpam = true
		c.HasSeaderFAP = true
		c.HasSubGHzBruteforcer = true
		c.HasMouseJackerFAP = true
		c.HasNFCMagicFAP = true
		c.HasMFKeyFAP = true
		c.HasMifareNestedFAP = true
		c.HasPicopassFAP = true
		c.UniversalIRLibraryName = "infrared/assets"
		c.StorageExtFatLabel = "MOMENTUM"
		c.HasStorageFormatExt = true
		c.HasSubGHzEncryptKeeloq = true
		c.HasPsCmd = true
		c.HasClearCmd = true
	}

	// ── Resolve band ─────────────────────────────────────────────────────────
	c.FirmwareBand = resolveBand(c.FirmwareFork, c.FirmwareVersion)

	return c
}
