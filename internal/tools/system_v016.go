package tools

import (
	"context"
	"encoding/json"
	"time"

	"github.com/xunholy/promptzero/internal/risk"
)

// v0.16 Flipper additions — closes audit gaps in
// Flipper Crypto enclave, GUI, Power, Storage, Date, Backup primitives.
// All wire commands live on the Flipper client in commands_v016.go.

//nolint:gochecknoinits
func init() {
	// --- Crypto enclave (companion to existing crypto_store_key) ---

	Register(Spec{
		Name:        "crypto_encrypt",
		Description: "Encrypt data using a key stored in the Flipper's HMAC enclave (slot was previously populated via crypto_store_key). Returns hex ciphertext.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"slot":{"type":"string","description":"Key slot identifier (1-based number or named slot per firmware)"},` +
			`"data":{"type":"string","description":"Plaintext as hex (no spaces, no leading 0x)"}}}`),
		Required:  []string{"slot", "data"},
		Risk:      risk.Medium,
		Group:     GroupFlipperSystem,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.CryptoEncrypt(str(p, "slot"), str(p, "data"))
		},
	})

	Register(Spec{
		Name:        "crypto_decrypt",
		Description: "Decrypt hex ciphertext using a key from the Flipper's HMAC enclave.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"slot":{"type":"string","description":"Key slot identifier"},` +
			`"data":{"type":"string","description":"Ciphertext as hex"}}}`),
		Required:  []string{"slot", "data"},
		Risk:      risk.Medium,
		Group:     GroupFlipperSystem,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.CryptoDecrypt(str(p, "slot"), str(p, "data"))
		},
	})

	Register(Spec{
		Name:        "crypto_has_key",
		Description: "Check whether the given enclave slot is populated. Returns the slot's status.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"slot":{"type":"string","description":"Key slot identifier"}}}`),
		Required:  []string{"slot"},
		Risk:      risk.Low,
		Group:     GroupFlipperSystem,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.CryptoHasKey(str(p, "slot"))
		},
	})

	// --- GUI screen stream (RPC) ---

	Register(Spec{
		Name:        "gui_screen_stream",
		Description: "Stream the Flipper's display as PBM frames for the given duration. Returns concatenated frames separated by newlines. Heavy — typical use is the web UI mirror; this tool exposes the same data programmatically.",
		Schema:      json.RawMessage(`{"type":"object","properties":{"duration_seconds":{"type":"number","description":"How long to stream (default 5)"}}}`),
		Required:    nil,
		Risk:        risk.Low,
		Group:       GroupFlipperSystem,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.GuiScreenStream(time.Duration(intOr(p, "duration_seconds", 5)) * time.Second)
		},
	})

	// --- Date / RTC ---

	Register(Spec{
		Name:        "flipper_date_get",
		Description: "Read the Flipper's RTC current time. Returns date + time as the firmware reports it.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.Low,
		Group:       GroupFlipperSystem,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			return d.Flipper.DateGet()
		},
	})

	Register(Spec{
		Name:        "flipper_date_set",
		Description: "Set the Flipper's RTC. Pass a Unix timestamp; host formats to the firmware's expected wire form.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"unix":{"type":"integer","description":"Unix epoch seconds (UTC; firmware applies its local offset)"}}}`),
		Required:  []string{"unix"},
		Risk:      risk.Medium,
		Group:     GroupFlipperSystem,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.DateSet(int64(intOr(p, "unix", 0)))
		},
	})

	// --- Storage extras ---

	Register(Spec{
		Name:        "flipper_storage_extract",
		Description: "Extract a tar archive on the SD card. Use after copying a .tar there via storage_write or sftp-equivalent.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"archive":{"type":"string","description":"Path to the .tar file on SD (e.g. /ext/staged.tar)"},` +
			`"out_dir":{"type":"string","description":"Output directory on SD (e.g. /ext/extracted)"}}}`),
		Required:  []string{"archive", "out_dir"},
		Risk:      risk.Medium,
		Group:     GroupFlipperSystem,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.StorageExtract(str(p, "archive"), str(p, "out_dir"))
		},
	})

	// --- Destructive: format, factory reset, backup restore ---
	// All require an explicit confirm:'YES' literal so the LLM can't trip them
	// by accident even with the risk gate at Critical.

	Register(Spec{
		Name:        "flipper_storage_format",
		Description: "Format the SD card (/ext) to FAT32. ALL DATA WILL BE LOST. Required: confirm must equal exactly 'YES_FORMAT'.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"confirm":{"type":"string","description":"Must equal 'YES_FORMAT' to proceed"}}}`),
		Required:  []string{"confirm"},
		Risk:      risk.Critical,
		Group:     GroupFlipperSystem,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if str(p, "confirm") != "YES_FORMAT" {
				return "", &confirmError{msg: "flipper_storage_format requires confirm='YES_FORMAT'"}
			}
			return d.Flipper.StorageFormat()
		},
	})

	Register(Spec{
		Name:        "flipper_factory_reset",
		Description: "Factory-reset the Flipper. Wipes /int (settings, dolphin level, paired BT, NFC keys, sub-ghz settings). Takes effect on next reboot. Required: confirm must equal exactly 'YES_FACTORY_RESET'.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"confirm":{"type":"string","description":"Must equal 'YES_FACTORY_RESET' to proceed"}}}`),
		Required:  []string{"confirm"},
		Risk:      risk.Critical,
		Group:     GroupFlipperSystem,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if str(p, "confirm") != "YES_FACTORY_RESET" {
				return "", &confirmError{msg: "flipper_factory_reset requires confirm='YES_FACTORY_RESET'"}
			}
			return d.Flipper.FactoryReset()
		},
	})

	// --- Backup create / restore ---

	Register(Spec{
		Name:        "flipper_backup_create",
		Description: "Create a full backup of /int as a tar at the given SD path. Pairs with flipper_backup_restore to revert.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"path":{"type":"string","description":"Destination .tar path on SD (e.g. /ext/backup.tar)"}}}`),
		Required:  []string{"path"},
		Risk:      risk.High,
		Group:     GroupFlipperSystem,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.BackupCreate(str(p, "path"))
		},
	})

	Register(Spec{
		Name:        "flipper_backup_restore",
		Description: "Restore /int from a backup tar. Wipes current /int. Required: confirm must equal exactly 'YES_RESTORE'.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"path":{"type":"string","description":"Source .tar path on SD"},` +
			`"confirm":{"type":"string","description":"Must equal 'YES_RESTORE' to proceed"}}}`),
		Required:  []string{"path", "confirm"},
		Risk:      risk.Critical,
		Group:     GroupFlipperSystem,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if str(p, "confirm") != "YES_RESTORE" {
				return "", &confirmError{msg: "flipper_backup_restore requires confirm='YES_RESTORE'"}
			}
			return d.Flipper.BackupRestore(str(p, "path"))
		},
	})

	// --- Power: off, 5V/3V3 rails ---

	Register(Spec{
		Name:        "flipper_power_off",
		Description: "Power off the Flipper. Connection is lost; user must press the power button to wake.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Required:    nil,
		Risk:        risk.High,
		Group:       GroupFlipperSystem,
		AgentOnly:   false,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			return d.Flipper.PowerOff()
		},
	})

	Register(Spec{
		Name:        "flipper_power_5v",
		Description: "Toggle the 5V rail on the GPIO header. Drives external hardware connected to the Flipper.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"enable":{"type":"boolean","description":"true = 5V on, false = off"}}}`),
		Required:  []string{"enable"},
		Risk:      risk.High,
		Group:     GroupFlipperSystem,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.Power5V(boolOr(p, "enable", false))
		},
	})

	Register(Spec{
		Name:        "flipper_power_3v3",
		Description: "Toggle the 3.3V rail on the GPIO header.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"enable":{"type":"boolean","description":"true = 3.3V on, false = off"}}}`),
		Required:  []string{"enable"},
		Risk:      risk.High,
		Group:     GroupFlipperSystem,
		AgentOnly: false,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			return d.Flipper.Power3V3(boolOr(p, "enable", false))
		},
	})
}

// confirmError is returned by destructive Specs when the literal confirm
// token is missing or wrong. Renders as a plain error to the agent so it
// re-prompts the user with the correct token.
type confirmError struct{ msg string }

func (e *confirmError) Error() string { return e.msg }
