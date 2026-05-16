package flipper

// commands_v016.go — Phase-3/4 new wrapper methods on *Flipper.
//
// Rule: never edit commands.go. All new methods go here. The Spec layer
// (task #3) routes to the device-explicit variants when device != 0.

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/xunholy/promptzero/internal/flipper/rpc"
)

// validateCryptoSlotString mirrors the firmware's crypto_cli slot
// parsing — slot must be a decimal integer in [1, 100]. Slot 0 is
// reserved (device-bound master key) and out-of-range slots get an
// opaque "invalid slot" banner from the firmware. Pre-fix, an LLM
// guessing slot="mySlot" or slot="" would get the opaque reply.
func validateCryptoSlotString(slot string) error {
	trimmed := strings.TrimSpace(slot)
	if trimmed == "" {
		return fmt.Errorf("invalid crypto slot: empty (must be a decimal integer in 1-100)")
	}
	n, err := strconv.Atoi(trimmed)
	if err != nil {
		return fmt.Errorf("invalid crypto slot %q (must be a decimal integer 1-100): %w", slot, err)
	}
	if n < 1 || n > 100 {
		return fmt.Errorf("invalid crypto slot %d (must be in 1-100; slot 0 is reserved)", n)
	}
	return nil
}

// ─── Sub-GHz device-explicit wrappers ────────────────────────────────────────

// SubGHzTxKeyDevice is like SubGHzTxKey but sends the device index
// explicitly via the -d flag rather than relying on the auto-append logic
// in SubGHzTxKey (which only supports device=0). Use this when device != 0
// (i.e. an external CC1101 module is wired to the GPIO header).
//
// Pre-transport validation matches SubGHzTxKey: freq must fall in an
// allowed band, te > 0, repeat >= 1.
// CLI: subghz tx <key_hex> <frequency> <te> <repeat> -d <device>
func (f *Flipper) SubGHzTxKeyDevice(keyHex string, freq uint32, te uint32, repeat int, device int) (string, error) {
	if err := validateSubGHzTxKey(freq, te, repeat); err != nil {
		return "", err
	}
	cmd := fmt.Sprintf("subghz tx %s %d %d %d -d %d",
		sanitizeArg(keyHex), freq, te, repeat, device)
	return f.Exec(cmd)
}

// SubGHzChatDevice is like SubGHzChat but passes the device index
// explicitly. Long-running; the caller bounds it with a duration.
// CLI: subghz chat <frequency> -d <device>
func (f *Flipper) SubGHzChatDevice(frequency uint32, duration time.Duration, device int) (string, error) {
	return f.SubGHzChatDeviceCtx(context.Background(), frequency, duration, device)
}

// SubGHzChatDeviceCtx is the context-aware variant of SubGHzChatDevice.
//
// Validates frequency against the firmware-permitted bands before TX.
// Out-of-band requests come back as "Frequency not allowed!" after a
// slow round-trip — same failure mode as SubGHzTxKey before v0.181.
func (f *Flipper) SubGHzChatDeviceCtx(ctx context.Context, frequency uint32, duration time.Duration, device int) (string, error) {
	if !subGHzFreqAllowed(frequency) {
		return "", fmt.Errorf("invalid Sub-GHz frequency %d Hz (allowed bands: 300-348 MHz, 387-464 MHz, 779-928 MHz)", frequency)
	}
	cmd := fmt.Sprintf("subghz chat %d -d %d", frequency, device)
	return f.ExecLongCtx(ctx, cmd, duration)
}

// ─── Crypto enclave ───────────────────────────────────────────────────────────

// CryptoEncrypt encrypts hex-encoded data using the key in the named slot.
// slot is a decimal-integer string in 1-100 (matches the firmware's
// crypto_cli_encrypt slot parser).
// CLI: crypto encrypt <slot> <hex-data>
func (f *Flipper) CryptoEncrypt(slot string, data string) (string, error) {
	if err := validateCryptoSlotString(slot); err != nil {
		return "", err
	}
	return f.Exec(fmt.Sprintf("crypto encrypt %s %s",
		sanitizeArg(slot), sanitizeArg(data)))
}

// CryptoDecrypt decrypts hex-encoded ciphertext using the key in the named slot.
// slot must be a decimal-integer string in 1-100.
// CLI: crypto decrypt <slot> <hex-data>
func (f *Flipper) CryptoDecrypt(slot string, data string) (string, error) {
	if err := validateCryptoSlotString(slot); err != nil {
		return "", err
	}
	return f.Exec(fmt.Sprintf("crypto decrypt %s %s",
		sanitizeArg(slot), sanitizeArg(data)))
}

// CryptoHasKey reports whether a key is stored in the named slot.
// slot must be a decimal-integer string in 1-100.
// CLI: crypto has_key <slot>
func (f *Flipper) CryptoHasKey(slot string) (string, error) {
	if err := validateCryptoSlotString(slot); err != nil {
		return "", err
	}
	return f.Exec(fmt.Sprintf("crypto has_key %s", sanitizeArg(slot)))
}

// ─── GUI screen stream (RPC) ──────────────────────────────────────────────────

// GuiScreenStream collects display frames from the Flipper for the given
// duration via the Protobuf RPC screen-stream path and returns them as
// base64-encoded PBM (P4 binary, 128×64) frames, one per line.
//
// RPC is available only when the underlying transport is BLE (f.bleClient
// is non-nil). On USB the web-UI mirror owns the screen-stream lifecycle
// via EnterRPC; calling this method on USB returns a descriptive error so
// the caller can surface the correct user prompt.
//
// RPC: Gui.StartScreenStreamRequest → collect frames → StopScreenStreamRequest
func (f *Flipper) GuiScreenStream(duration time.Duration) (string, error) {
	if f.bleClient == nil {
		return "", fmt.Errorf("screen stream RPC not bound; use the web UI mirror instead")
	}

	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	ch, err := f.bleClient.StartScreenStream(ctx)
	if err != nil {
		return "", fmt.Errorf("gui screen stream: start: %w", err)
	}
	// Best-effort stop: send StopScreenStreamRequest even if the context
	// has already expired. The channel drains naturally once ctx is done.
	defer func() { _ = f.bleClient.StopScreenStream(context.Background()) }()

	var sb strings.Builder
	for frame := range ch {
		sb.WriteString(base64.StdEncoding.EncodeToString(screenFrameToPBM(frame)))
		sb.WriteByte('\n')
	}
	return sb.String(), nil
}

// screenFrameToPBM converts a Flipper display frame (column-page packed,
// firmware-native) into a standard PBM P4 binary file (row-major, MSB-first).
//
// PBM layout: "P4\n128 64\n" header followed by 1024 bytes:
//
//	row y, pixels x=0..127 → byte y*16+x/8, bit 7−(x%8)
func screenFrameToPBM(frame rpc.ScreenFrame) []byte {
	const header = "P4\n128 64\n"
	out := make([]byte, len(header)+1024)
	copy(out, header)
	pixels := out[len(header):]
	for y := 0; y < 64; y++ {
		for x := 0; x < 128; x++ {
			if frame.Pixel(x, y) {
				pixels[y*16+x/8] |= 1 << uint(7-(x%8))
			}
		}
	}
	return out
}

// ─── Date / RTC ──────────────────────────────────────────────────────────────

// DateGet returns the current device time as reported by the RTC.
// CLI: date
func (f *Flipper) DateGet() (string, error) {
	return f.Exec("date")
}

// DateSet synchronises the Flipper's RTC to the given Unix timestamp.
// The OFW CLI form is: date YYYY-MM-DD HH:MM:SS WD
// where WD is the ISO-8601 weekday (1=Monday … 7=Sunday).
// The timestamp is interpreted in UTC — the Flipper firmware stores UTC.
// CLI: date <YYYY-MM-DD> <HH:MM:SS> <1-7>
func (f *Flipper) DateSet(unix int64) (string, error) {
	t := time.Unix(unix, 0).UTC()
	wd := int(t.Weekday())
	if wd == 0 {
		wd = 7 // Go: Sunday=0 → ISO 8601: Sunday=7
	}
	cmd := fmt.Sprintf("date %s %d", t.Format("2006-01-02 15:04:05"), wd)
	return f.Exec(cmd)
}

// ─── Storage extras ───────────────────────────────────────────────────────────

// StorageExtract unpacks a tar archive on the Flipper SD card.
//
// Rejects empty/whitespace archive or outdir before transport. Empty
// either side produces `storage extract  /ext/foo` (double-space) or
// `storage extract /ext/x.tar ` (trailing space) which the firmware
// either parses as the wrong shape or rejects with an opaque banner.
// CLI: storage extract <archive.tar> <outdir>
func (f *Flipper) StorageExtract(archive, outdir string) (string, error) {
	if strings.TrimSpace(archive) == "" {
		return "", fmt.Errorf("invalid storage extract archive: empty (expected e.g. /ext/backup.tar)")
	}
	if strings.TrimSpace(outdir) == "" {
		return "", fmt.Errorf("invalid storage extract outdir: empty (expected an SD-card directory path)")
	}
	return f.Exec(fmt.Sprintf("storage extract %s %s",
		sanitizeArg(archive), sanitizeArg(outdir)))
}

// StorageFormat formats the external SD card (/ext).
// Destructive — the Spec risk band enforces confirmation; this method is a
// plain wire wrapper with no guard of its own.
// CLI: storage format /ext
func (f *Flipper) StorageFormat() (string, error) {
	return f.ExecLong("storage format /ext", 5*time.Minute)
}

// ─── Destructive / recovery operations ───────────────────────────────────────

// FactoryReset schedules a factory reset that takes effect on the next reboot.
// Destructive — all user data and settings are erased. The Spec risk band
// enforces confirmation; this method is a plain wire wrapper.
// CLI: factory_reset
func (f *Flipper) FactoryReset() (string, error) {
	return f.Exec("factory_reset")
}

// BackupCreate writes a tar archive of the Flipper's internal flash (/int)
// to the given SD-card path. Uses a 5-minute deadline — same budget as
// UpdateInstall.
//
// Rejects empty/whitespace path before transport. An empty path
// produces `update backup ` which writes to firmware-default location
// on some forks and errors on others; reject up front so the operator
// always knows where the backup landed.
// CLI: update backup <path>
func (f *Flipper) BackupCreate(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("invalid backup path: empty (expected e.g. /ext/backups/flipper-int.tar)")
	}
	return f.ExecLong(fmt.Sprintf("update backup %s", sanitizeArg(path)), 5*time.Minute)
}

// BackupRestore restores a previously created backup archive. Destructive —
// overwrites current /int contents. The Spec risk band enforces confirmation.
//
// Rejects empty/whitespace path before transport. Empty path on the
// destructive restore path is particularly dangerous: some forks treat
// it as "restore from default location" which could surface a stale
// backup. The operator should always name the file explicitly.
// CLI: update restore <path>
func (f *Flipper) BackupRestore(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("invalid backup path: empty (expected the path of a previously-created backup tar)")
	}
	return f.ExecLong(fmt.Sprintf("update restore %s", sanitizeArg(path)), 5*time.Minute)
}

// ─── Power control ────────────────────────────────────────────────────────────

// PowerOff powers off the Flipper. The device will not respond after this
// until the user presses the power button. The Spec risk band enforces
// confirmation.
// CLI: power off
func (f *Flipper) PowerOff() (string, error) {
	return f.Exec("power off")
}

// Power5V enables (enable=true) or disables (enable=false) the 5 V GPIO
// supply rail on the Flipper's external header.
// CLI: power 5v 1  or  power 5v 0
func (f *Flipper) Power5V(enable bool) (string, error) {
	v := 0
	if enable {
		v = 1
	}
	return f.Exec(fmt.Sprintf("power 5v %d", v))
}

// Power3V3 enables (enable=true) or disables (enable=false) the 3.3 V GPIO
// supply rail on the Flipper's external header.
// CLI: power 3v3 1  or  power 3v3 0
func (f *Flipper) Power3V3(enable bool) (string, error) {
	v := 0
	if enable {
		v = 1
	}
	return f.Exec(fmt.Sprintf("power 3v3 %d", v))
}
