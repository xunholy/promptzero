package tools

import (
	"context"
	"encoding/json"

	"github.com/xunholy/promptzero/internal/risk"
)

func init() {
	Register(Spec{
		Name:        "loader_info",
		Description: "Return metadata about the currently running app (name, flags). Read-only; useful to verify a loader_open actually launched something before sending input_send events.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Low,
		Group:       GroupFlipperSystem,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			return d.Flipper.LoaderInfo()
		},
	})

	Register(Spec{
		Name:        "loader_open",
		Description: "Open a Flipper application by name with optional arguments. Use to launch any built-in or FAP app. If you're unsure whether the app is installed, call list_apps first.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"app_name":{"type":"string","description":"Application name, e.g. NFC, SubGHz, iButton, Bad USB, GPIO"},"args":{"type":"string","description":"Optional arguments to pass to the app"}}}`),
		Required:    []string{"app_name"},
		Risk:        risk.High,
		Group:       GroupFlipperSystem,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.LoaderOpen(str(p, "app_name"), str(p, "args"))
		},
	})

	Register(Spec{
		Name:        "loader_close",
		Description: "Close the currently running Flipper application.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Medium,
		Group:       GroupFlipperSystem,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			return d.Flipper.LoaderClose()
		},
	})

	Register(Spec{
		Name:        "loader_signal",
		Description: "Send a numeric signal to the currently running app. Signal meanings are app-specific; many apps document a small set of custom opcodes (pause, toggle, reset).",
		Schema:      json.RawMessage(`{"type":"object","properties":{"signal":{"type":"integer","description":"Signal number to deliver"},"arg_hex":{"type":"string","description":"Optional hex argument passed alongside the signal"}}}`),
		Required:    []string{"signal"},
		Risk:        risk.High,
		Group:       GroupFlipperSystem,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.LoaderSignal(intOr(p, "signal", 0), str(p, "arg_hex"))
		},
	})

	Register(Spec{
		Name:        "list_apps",
		Description: "List every installed Flipper application plus the settings-menu entries. Call this BEFORE loader_open when the target app's availability is uncertain — avoids the silent-failure path where loader_open launches a missing FAP. Returns structured JSON: {apps: [...], settings: [...]}.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Low,
		Group:       GroupFlipperSystem,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			apps, err := d.Flipper.LoaderListParsed()
			if err != nil {
				return "", err
			}
			b, _ := json.Marshal(apps)
			return string(b), nil
		},
	})

	// --- NFC loader FAPs (Wave 2) ---

	Register(Spec{
		Name:        "loader_nfc_magic",
		Description: "Launch the NFC Magic FAP — writes UIDs to 'magic' MIFARE tags that allow cloning of locked blocks. Requires the FAP to be installed on the SD card; call list_apps if unsure.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.High,
		Group:       GroupFlipperNFC,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			return d.Flipper.LoaderNFCMagic()
		},
	})

	Register(Spec{
		Name:        "loader_mfkey",
		Description: "Launch the MFKey32 FAP — recovers MIFARE Classic sector keys from captured reader nonces. Requires the FAP to be installed.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.High,
		Group:       GroupFlipperNFC,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			return d.Flipper.LoaderMFKey()
		},
	})

	Register(Spec{
		Name:        "loader_mifare_nested",
		Description: "Launch the Mifare Nested FAP — nested-attack key recovery for MIFARE Classic once at least one key is known. Requires the FAP to be installed.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.High,
		Group:       GroupFlipperNFC,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			return d.Flipper.LoaderMifareNested()
		},
	})

	Register(Spec{
		Name:        "loader_picopass",
		Description: "Launch the PicoPass FAP — HID iClass / PicoPass tag tooling. Requires the FAP to be installed.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.High,
		Group:       GroupFlipperNFC,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			return d.Flipper.LoaderPicopass()
		},
	})

	Register(Spec{
		Name:        "loader_seader",
		Description: "Launch the SEADER FAP — advanced HID iClass SE attack toolkit. Requires the FAP to be installed.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.High,
		Group:       GroupFlipperNFC,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			return d.Flipper.LoaderSeader()
		},
	})

	// --- SubGHz / misc loader FAPs (Wave 2) ---

	Register(Spec{
		Name:        "loader_subghz_bruteforcer",
		Description: "Launch the Sub-GHz Bruteforcer FAP — performs large code-sweep attacks across known protocols. Critical: emits enormous amounts of RF, likely illegal outside a shielded lab. Requires the FAP to be installed.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Critical,
		Group:       GroupFlipperSubGHz,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			return d.Flipper.LoaderSubGHzBruteforcer()
		},
	})

	Register(Spec{
		Name:        "loader_subghz_playlist",
		Description: "Launch the Sub-GHz Playlist FAP — replays a sequence of .sub captures in order. Active transmission. Requires the FAP to be installed.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.High,
		Group:       GroupFlipperSubGHz,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			return d.Flipper.LoaderSubGHzPlaylist()
		},
	})

	Register(Spec{
		Name:        "loader_protoview",
		Description: "Launch the ProtoView FAP — visualises raw Sub-GHz signals for protocol inspection. Receive-only scanning. Requires the FAP to be installed.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Medium,
		Group:       GroupFlipperSubGHz,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			return d.Flipper.LoaderProtoView()
		},
	})

	Register(Spec{
		Name:        "loader_spectrum_analyzer",
		Description: "Launch the Spectrum Analyzer FAP — shows RF power across a frequency range. Receive-only. Requires the FAP to be installed.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Medium,
		Group:       GroupFlipperSubGHz,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			return d.Flipper.LoaderSpectrumAnalyzer()
		},
	})

	Register(Spec{
		Name:        "loader_signal_generator",
		Description: "Launch the Signal Generator FAP — drives a square wave on a GPIO pin at a configurable frequency. Requires the FAP to be installed.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Medium,
		Group:       GroupFlipperSubGHz,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			return d.Flipper.LoaderSignalGenerator()
		},
	})

	Register(Spec{
		Name:        "loader_nrf24mousejacker",
		Description: "Launch the NRF24 Mousejacker FAP — attack tool against 2.4 GHz wireless mice/keyboards. Requires both an external NRF24 devboard on the GPIO header AND the FAP installed. Critical (arbitrary keystroke injection).",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Critical,
		Group:       GroupFlipperSystem,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			return d.Flipper.LoaderNRF24Mousejacker()
		},
	})

	Register(Spec{
		Name:        "loader_uart_terminal",
		Description: "Launch the UART Terminal FAP — bidirectional serial console on the Flipper's GPIO pins, useful for UART recon on target boards. Requires the FAP to be installed.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Medium,
		Group:       GroupFlipperSystem,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			return d.Flipper.LoaderUARTTerminal()
		},
	})

	Register(Spec{
		Name:        "loader_spi_mem_manager",
		Description: "Launch the SPI Mem Manager FAP — reads and writes SPI flash chips via the GPIO header. Useful for firmware extraction on embedded targets. Requires the FAP to be installed.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Medium,
		Group:       GroupFlipperSystem,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			return d.Flipper.LoaderSPIMemManager()
		},
	})

	Register(Spec{
		Name:        "loader_unitemp",
		Description: "Launch the Unitemp FAP — reads external temperature/humidity sensors (DHT, DS18B20, BMP280, ...) over the GPIO header. Read-only.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Low,
		Group:       GroupFlipperSystem,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			return d.Flipper.LoaderUnitemp()
		},
	})

	// --- New FAP wrappers from gap-analysis top-30 (v0.204 wave) ---

	Register(Spec{
		Name: "loader_sentry_safe",
		Description: "Launch the Sentry Safe FAP (H4ckd4ddy/flipperzero-sentry-safe-plugin) — " +
			"drives the factory-test backdoor sequence on Sentry / Master Lock electronic safes via " +
			"the Flipper GPIO header (TX line into the safe's debug port). Physical pentest primitive — " +
			"the operator must wire the Flipper to the target safe's reset pads before launching. " +
			"Critical: opens any in-scope safe; authorise the engagement before use. " +
			"Requires the FAP to be installed.",
		Schema:    json.RawMessage(`{"type":"object","properties":{}}`),
		Required:  nil,
		Risk:      risk.Critical,
		Group:     GroupFlipperSystem,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			return d.Flipper.LoaderSentrySafe()
		},
	})

	Register(Spec{
		Name: "loader_pocsag_pager",
		Description: "Launch the Pocsag Pager FAP (Next-Flip/Momentum-Apps) — receive-only POCSAG paging " +
			"decoder on the Flipper's CC1101. Common European paging dragnet target. Bundled in Momentum, " +
			"RogueMaster, ATP, and Unleashed firmwares. Read-only.",
		Schema:    json.RawMessage(`{"type":"object","properties":{}}`),
		Required:  nil,
		Risk:      risk.Low,
		Group:     GroupFlipperSubGHz,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			return d.Flipper.LoaderPocsagPager()
		},
	})

	Register(Spec{
		Name: "loader_magspoof",
		Description: "Launch the MagSpoof FAP (zacharyweiss/magspoof_flipper) — Samy Kamkar's wireless " +
			"mag-stripe emulator, GPIO-driven coil over the Flipper's external header. Emits Track 1/2/3 " +
			"data into nearby mag-stripe readers. Critical: high-leverage physical-pentest primitive; " +
			"authorise the engagement before use. Requires the FAP to be installed and (optionally) an " +
			"external coil module for the Electronic Cats fork.",
		Schema:    json.RawMessage(`{"type":"object","properties":{}}`),
		Required:  nil,
		Risk:      risk.Critical,
		Group:     GroupFlipperSystem,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			return d.Flipper.LoaderMagSpoof()
		},
	})
}
