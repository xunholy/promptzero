package flipper

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/xunholy/promptzero/internal/clisafe"
)

// sanitizeArg delegates to clisafe.SanitizeArg. Kept as an internal wrapper
// so existing call sites in this file read naturally; the shared helper
// strips the union of bytes any CLI transport cares about (CR, LF, NUL,
// ETX, and the double-quote delimiter).
func sanitizeArg(s string) string { return clisafe.SanitizeArg(s) }

// SanitizeArg is the exported wrapper for callers outside this package
// that build Flipper CLI commands directly (e.g. the agent's inline
// bruteforce dispatch). Prefer the typed wrapper functions when one
// exists. Delegates to clisafe.SanitizeArg.
func SanitizeArg(s string) string { return clisafe.SanitizeArg(s) }

// nfcAllowedSubcommands is the explicit allowlist of `nfc` CLI subcommands
// we permit callers to invoke via NFCSubcommand. Arbitrary subcommands
// could interact with unknown firmware surface; restrict to known-safe
// verbs.
var nfcAllowedSubcommands = map[string]struct{}{
	"scanner": {},
	"emulate": {},
	"dump":    {},
	"field":   {},
	"raw":     {},
	"apdu":    {},
	"mfu":     {},
}

// SetLED sets the RGB LED to the given color + brightness (0-255). Best-effort
// — errors are returned but most callers ignore them. The REPL drives this at
// turn scope so the LED stays steady for the whole prompt, rather than
// flickering on/off per scan.
// Color is one of "r", "g", "b" (or "bl" for backlight).
func (f *Flipper) SetLED(color string, brightness int) error {
	_, err := f.Exec(fmt.Sprintf("led %s %d", sanitizeArg(color), brightness))
	return err
}

// withSuccessBuzz wraps a scan/receive operation with a 120ms vibration on
// successful detection. LED feedback is handled at the turn level (see main's
// REPL loop) so a single long scan doesn't flicker the LED on and off.
// Vibration errors are swallowed — firmware without `vibro` support won't
// break the scan.
func (f *Flipper) withSuccessBuzz(fn func() (string, error)) (string, error) {
	out, err := fn()
	if err == nil {
		_, _ = f.Exec("vibro 1")
		time.Sleep(120 * time.Millisecond)
		_, _ = f.Exec("vibro 0")
	}
	return out, err
}

// --- Sub-GHz ---

// SubGHzTx transmits a Sub-GHz signal from a saved file.
// CLI: subghz tx_from_file <file_path>
func (f *Flipper) SubGHzTx(filePath string) (string, error) {
	return f.Exec(fmt.Sprintf("subghz tx_from_file %s", sanitizeArg(filePath)))
}

// SubGHzRx receives Sub-GHz signals on the given frequency (Hz). Xtreme
// firmware's `subghz rx` requires a trailing <device> arg (0=internal CC1101,
// 1=external); we append "0" when capabilities report that quirk.
func (f *Flipper) SubGHzRx(frequency uint32, duration time.Duration) (string, error) {
	return f.withSuccessBuzz(func() (string, error) {
		cmd := fmt.Sprintf("subghz rx %d", frequency)
		if f.Capabilities().SubGHzNeedsDev {
			cmd += " 0"
		}
		return f.ExecLong(cmd, duration)
	})
}

// SubGHzDecode decodes a previously captured raw Sub-GHz file.
// CLI: subghz decode_raw <file_path>
func (f *Flipper) SubGHzDecode(filePath string) (string, error) {
	return f.Exec(fmt.Sprintf("subghz decode_raw %s", sanitizeArg(filePath)))
}

// SubGHzTxKey transmits a raw Sub-GHz key. Xtreme firmware requires a
// trailing <device> arg (0=internal CC1101, 1=external); appended when the
// detected capability flag is set.
// CLI: subghz tx <key_hex> <frequency> <te> <repeat> [device]
func (f *Flipper) SubGHzTxKey(keyHex string, freq uint32, te uint32, repeat int) (string, error) {
	cmd := fmt.Sprintf("subghz tx %s %d %d %d", sanitizeArg(keyHex), freq, te, repeat)
	if f.Capabilities().SubGHzNeedsDev {
		cmd += " 0"
	}
	return f.Exec(cmd)
}

// --- Infrared ---

// IRTxParsed transmits a decoded infrared signal.
// CLI: ir tx <protocol> <address_hex> <command_hex>
func (f *Flipper) IRTxParsed(protocol string, address string, command string) (string, error) {
	return f.Exec(fmt.Sprintf("ir tx %s %s %s", sanitizeArg(protocol), sanitizeArg(address), sanitizeArg(command)))
}

// IRTxRaw transmits a raw infrared signal.
// CLI: ir tx RAW F:<freq> DC:<duty_cycle> <data>
func (f *Flipper) IRTxRaw(frequency uint32, dutyCycle float64, data string) (string, error) {
	return f.Exec(fmt.Sprintf("ir tx RAW F:%d DC:%g %s", frequency, dutyCycle, sanitizeArg(data)))
}

// IRRx listens for an incoming infrared signal.
// CLI: ir rx
func (f *Flipper) IRRx(timeout time.Duration) (string, error) {
	return f.withSuccessBuzz(func() (string, error) {
		return f.ExecLong("ir rx", timeout)
	})
}

// IRRxRaw listens for a raw infrared signal.
// CLI: ir rx raw
func (f *Flipper) IRRxRaw(timeout time.Duration) (string, error) {
	return f.ExecLong("ir rx raw", timeout)
}

// IRUniversal transmits a signal from a universal remote library entry.
// CLI: ir universal <remote_name> <signal_name>
func (f *Flipper) IRUniversal(remoteName string, signalName string) (string, error) {
	return f.Exec(fmt.Sprintf("ir universal %s %s", sanitizeArg(remoteName), sanitizeArg(signalName)))
}

// --- NFC ---

// NFCDetect enters the NFC subshell, runs the scanner subcommand, and exits.
// The subshell prompt is "[nfc]>: ". Not all firmware forks expose an NFC
// CLI — Xtreme XFW ships an empty `nfc` subsystem — so we surface a clear
// error rather than hanging on a non-responsive subcommand.
func (f *Flipper) NFCDetect(timeout time.Duration) (string, error) {
	if caps := f.Capabilities(); !caps.HasNFCSubshell {
		return "", fmt.Errorf("NFC CLI not available on %s firmware — use the on-device NFC app, or switch to stock/unleashed firmware", caps.FriendlyFork())
	}
	return f.withSuccessBuzz(func() (string, error) {
		f.mu.Lock()
		defer f.mu.Unlock()

		f.drain()

		// Enter the NFC subshell.
		if err := f.sendRaw("nfc\r"); err != nil {
			f.sendRaw("\x03") // force exit
			return "", fmt.Errorf("entering nfc subshell: %w", err)
		}
		if _, err := f.readUntilPrompt(5 * time.Second); err != nil {
			f.sendRaw("\x03") // force exit
			return "", fmt.Errorf("waiting for nfc prompt: %w", err)
		}

		// Run the scanner subcommand.
		if err := f.sendRaw("scanner\r"); err != nil {
			return "", fmt.Errorf("sending scanner command: %w", err)
		}
		result, err := f.readUntilPrompt(timeout)
		if err != nil {
			return "", fmt.Errorf("nfc scanner: %w", err)
		}

		// Exit the NFC subshell.
		if err := f.sendRaw("exit\r"); err != nil {
			f.sendRaw("\x03") // force exit
			return result, fmt.Errorf("exiting nfc subshell: %w", err)
		}
		if _, err := f.readUntilPrompt(5 * time.Second); err != nil {
			f.sendRaw("\x03")  // force exit
			return result, nil // return result despite exit error
		}

		return result, nil
	})
}

// NFCEmulate launches the NFC emulation app via the loader.
// CLI: loader open NFC <file_path>
func (f *Flipper) NFCEmulate(filePath string) (string, error) {
	return f.LoaderOpen("NFC", filePath)
}

// NFCSubcommand enters the NFC subshell, sends an arbitrary subcommand, and exits.
// Valid subcommands include: scanner, emulate, dump, field, raw, apdu, mfu.
// Not available on firmware forks without an NFC CLI subshell (e.g., Xtreme).
func (f *Flipper) NFCSubcommand(subcommand string, timeout time.Duration) (string, error) {
	if caps := f.Capabilities(); !caps.HasNFCSubshell {
		return "", fmt.Errorf("NFC CLI not available on %s firmware", caps.FriendlyFork())
	}

	// Validate against the explicit allowlist. We take the first whitespace
	// token as the verb so callers can still pass arguments (e.g. "emulate
	// Mifare_Classic.nfc"). Belt-and-braces: sanitize the full (possibly
	// argumented) subcommand to strip CR/LF/NUL/ETX injection.
	trimmed := strings.TrimSpace(subcommand)
	verb := trimmed
	if idx := strings.IndexFunc(trimmed, func(r rune) bool { return r == ' ' || r == '\t' }); idx >= 0 {
		verb = trimmed[:idx]
	}
	if _, ok := nfcAllowedSubcommands[verb]; !ok {
		allowed := []string{"scanner", "emulate", "dump", "field", "raw", "apdu", "mfu"}
		return "", fmt.Errorf("nfc subcommand %q not allowed (permitted: %s)", verb, strings.Join(allowed, ", "))
	}
	safeCmd := sanitizeArg(trimmed)

	f.mu.Lock()
	defer f.mu.Unlock()

	f.drain()

	if err := f.sendRaw("nfc\r"); err != nil {
		f.sendRaw("\x03") // force exit
		return "", fmt.Errorf("entering nfc subshell: %w", err)
	}
	if _, err := f.readUntilPrompt(5 * time.Second); err != nil {
		f.sendRaw("\x03") // force exit
		return "", fmt.Errorf("waiting for nfc prompt: %w", err)
	}

	if err := f.sendRaw(safeCmd + "\r"); err != nil {
		return "", fmt.Errorf("sending nfc subcommand: %w", err)
	}
	result, err := f.readUntilPrompt(timeout)
	if err != nil {
		return "", fmt.Errorf("nfc subcommand %q: %w", verb, err)
	}

	if err := f.sendRaw("exit\r"); err != nil {
		f.sendRaw("\x03") // force exit
		return result, fmt.Errorf("exiting nfc subshell: %w", err)
	}
	if _, err := f.readUntilPrompt(5 * time.Second); err != nil {
		f.sendRaw("\x03")  // force exit
		return result, nil // return result despite exit error
	}

	return result, nil
}

// --- RFID (125 kHz LF) ---

// RFIDRead reads a 125kHz RFID tag. mode is optional (normal, indala, ask,
// psk); pass "" for auto. Unlike a plain ExecLong, this streams the Flipper's
// output and returns as soon as a tag is decoded — so a successful scan takes
// ~1-2 seconds instead of waiting out the full timeout. If nothing appears
// within timeout, a helpful "no tag detected" error is returned.
// CLI: rfid read [mode]
func (f *Flipper) RFIDRead(ctx context.Context, mode string, timeout time.Duration) (string, error) {
	return f.withSuccessBuzz(func() (string, error) {
		cmd := "rfid read"
		if mode != "" {
			cmd = fmt.Sprintf("rfid read %s", sanitizeArg(mode))
		}

		scanCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		var lines []string
		detected := false

		err := f.StreamCtx(scanCtx, cmd, func(line string) bool {
			lines = append(lines, line)
			if !detected && rfidDetectionLine(line) {
				detected = true
				// Give the Flipper ~250ms to flush follow-up data lines
				// (e.g. "Data: ..." after "EM4100: ..."), then stop.
				time.AfterFunc(250*time.Millisecond, cancel)
			}
			return false
		})

		if err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
			return strings.Join(lines, "\n"), err
		}

		if !detected {
			return strings.Join(lines, "\n"), fmt.Errorf("no RFID tag detected within %v — hold the fob flat against the BACK of the Flipper (LF antenna) and retry", timeout)
		}
		return strings.Join(lines, "\n"), nil
	})
}

// rfidDetectionLine returns true when a streamed line from `rfid read` looks
// like a tag decode (protocol name + data). The Flipper outputs vary by
// protocol; we match on well-known 125kHz protocol names and common field
// labels. "Reading 125 kHz RFID..." is the startup banner and is excluded.
func rfidDetectionLine(line string) bool {
	l := strings.ToLower(line)
	if strings.Contains(l, "reading") && strings.Contains(l, "rfid") {
		return false
	}
	protocols := []string{
		"em4100", "em410x", "em-410x",
		"hidprox", "hid prox", "h10301",
		"indala", "awid", "fdx-a", "fdx-b",
		"pyramid", "viking", "ioprox", "jablotron",
		"paradox", "nexwatch", "presco", "keri",
	}
	for _, p := range protocols {
		if strings.Contains(l, p) {
			return true
		}
	}
	// Common decoded-field prefixes printed after the protocol name.
	if strings.HasPrefix(l, "data:") || strings.HasPrefix(l, "key:") ||
		strings.HasPrefix(l, "card id:") || strings.HasPrefix(l, "facility:") {
		return true
	}
	return false
}

// RFIDEmulate emulates an RFID tag.
// CLI: rfid emulate <protocol> <hex_data>
func (f *Flipper) RFIDEmulate(protocol string, data string) (string, error) {
	return f.Exec(fmt.Sprintf("rfid emulate %s %s", sanitizeArg(protocol), sanitizeArg(data)))
}

// RFIDWrite writes data to an RFID tag.
// CLI: rfid write <protocol> <hex_data>
func (f *Flipper) RFIDWrite(protocol string, data string) (string, error) {
	return f.ExecLong(fmt.Sprintf("rfid write %s %s", sanitizeArg(protocol), sanitizeArg(data)), 30*time.Second)
}

// --- iButton ---

// IButtonRead reads an iButton key.
// CLI: ikey read
func (f *Flipper) IButtonRead(timeout time.Duration) (string, error) {
	return f.withSuccessBuzz(func() (string, error) {
		return f.ExecLong("ikey read", timeout)
	})
}

// IButtonEmulate emulates an iButton key.
// CLI: ikey emulate <protocol> <hex_data>
// Supported protocols: Dallas, Cyfral, Metakom
func (f *Flipper) IButtonEmulate(protocol string, hexData string) (string, error) {
	return f.Exec(fmt.Sprintf("ikey emulate %s %s", sanitizeArg(protocol), sanitizeArg(hexData)))
}

// IButtonWrite writes an iButton key (Dallas only).
// CLI: ikey write Dallas <hex_data>
func (f *Flipper) IButtonWrite(hexData string) (string, error) {
	return f.ExecLong(fmt.Sprintf("ikey write Dallas %s", sanitizeArg(hexData)), 30*time.Second)
}

// --- GPIO ---

// GPIOSet sets a GPIO pin to a value.
// CLI: gpio set <pin> <value>
func (f *Flipper) GPIOSet(pin string, value int) (string, error) {
	return f.Exec(fmt.Sprintf("gpio set %s %d", sanitizeArg(pin), value))
}

// GPIORead reads the current value of a GPIO pin.
// CLI: gpio read <pin>
func (f *Flipper) GPIORead(pin string) (string, error) {
	return f.Exec(fmt.Sprintf("gpio read %s", sanitizeArg(pin)))
}

// --- BadUSB ---

// BadUSBRun launches a BadUSB script via the app loader.
// CLI: loader open "Bad USB" <script_path>
func (f *Flipper) BadUSBRun(scriptPath string) (string, error) {
	return f.ExecLong(fmt.Sprintf("loader open \"Bad USB\" %s", sanitizeArg(scriptPath)), 2*time.Minute)
}

// --- Loader ---

// LoaderOpen opens a Flipper application by name with optional arguments.
// CLI: loader open <app_name> [args]
func (f *Flipper) LoaderOpen(appName string, args string) (string, error) {
	cmd := fmt.Sprintf("loader open %s", sanitizeArg(appName))
	if args != "" {
		cmd = fmt.Sprintf("loader open %s %s", sanitizeArg(appName), sanitizeArg(args))
	}
	return f.Exec(cmd)
}

// LoaderClose closes the currently running application.
// CLI: loader close
func (f *Flipper) LoaderClose() (string, error) {
	return f.Exec("loader close")
}

// LoaderList lists all available applications.
// CLI: loader list
func (f *Flipper) LoaderList() (string, error) {
	return f.Exec("loader list")
}

// LoaderApps is the parsed shape of `loader list`: user-facing apps plus the
// settings menu entries (which are also launchable via `loader open`).
type LoaderApps struct {
	Apps     []string `json:"apps"`
	Settings []string `json:"settings"`
}

// LoaderListParsed returns the app/settings lists as structured data so the
// agent can decide whether a target app is installed before calling
// loader_open. Returned fields are empty slices (not nil) when a section is
// missing from the output.
func (f *Flipper) LoaderListParsed() (LoaderApps, error) {
	raw, err := f.LoaderList()
	if err != nil {
		return LoaderApps{}, err
	}
	out := LoaderApps{Apps: []string{}, Settings: []string{}}
	// The CLI output is organised as "Apps:\n\t<name>\n..." with an optional
	// "Settings:\n\t..." block. Tab-prefixed lines belong to whichever
	// section was last seen.
	section := ""
	for _, line := range strings.Split(raw, "\n") {
		trim := strings.TrimSpace(line)
		switch {
		case trim == "Apps:":
			section = "apps"
		case trim == "Settings:":
			section = "settings"
		case trim == "":
			// blank line — keep current section
		case strings.HasPrefix(line, "\t") || strings.HasPrefix(line, "    "):
			switch section {
			case "apps":
				out.Apps = append(out.Apps, trim)
			case "settings":
				out.Settings = append(out.Settings, trim)
			}
		}
	}
	return out, nil
}

// --- Input ---

// InputSend sends a synthetic button input event.
// CLI: input send <button> <type>
// button: up, down, left, right, ok, back
// eventType: press, release, short, long, repeat
func (f *Flipper) InputSend(button string, eventType string) (string, error) {
	return f.Exec(fmt.Sprintf("input send %s %s", sanitizeArg(button), sanitizeArg(eventType)))
}

// --- Storage / File Operations ---

// StorageList lists files and directories at the given path.
// CLI: storage list <path>
func (f *Flipper) StorageList(path string) (string, error) {
	return f.Exec(fmt.Sprintf("storage list %s", sanitizeArg(path)))
}

// StorageRead reads the contents of a file.
// CLI: storage read <path>
func (f *Flipper) StorageRead(path string) (string, error) {
	return f.Exec(fmt.Sprintf("storage read %s", sanitizeArg(path)))
}

// StorageWrite writes data to a file using the write_chunk protocol.
func (f *Flipper) StorageWrite(path string, data string) error {
	return f.WriteFile(path, []byte(data))
}

// StorageRemove removes a file or directory.
// CLI: storage remove <path>
func (f *Flipper) StorageRemove(path string) (string, error) {
	return f.Exec(fmt.Sprintf("storage remove %s", sanitizeArg(path)))
}

// StorageMkdir creates a directory.
// CLI: storage mkdir <path>
func (f *Flipper) StorageMkdir(path string) (string, error) {
	return f.Exec(fmt.Sprintf("storage mkdir %s", sanitizeArg(path)))
}

// StorageStat returns metadata about a file or directory.
// CLI: storage stat <path>
func (f *Flipper) StorageStat(path string) (string, error) {
	return f.Exec(fmt.Sprintf("storage stat %s", sanitizeArg(path)))
}

// --- System ---

// DeviceInfo returns device information.
// CLI: device_info
func (f *Flipper) DeviceInfo() (string, error) {
	return f.Exec("device_info")
}

// RawCLI sends an arbitrary CLI command string to the Flipper and returns
// its output. Escape hatch for firmware features we haven't wrapped, or for
// debugging. Callers MUST risk-gate this — it can reboot the device, write
// arbitrary files, jam frequencies, etc. The 30s timeout is a safety cap;
// for long-running commands use ExecLong directly from a wrapper.
func (f *Flipper) RawCLI(command string) (string, error) {
	return f.ExecLong(command, 30*time.Second)
}

// PowerInfo returns power/battery information. The CLI spelling differs by
// fork: Xtreme uses `info power`; stock/Unleashed/RogueMaster use
// `power_info`. The capability map stores the right verb at connect time.
func (f *Flipper) PowerInfo() (string, error) {
	cmd := f.Capabilities().PowerInfoCmd
	if cmd == "" {
		cmd = "power_info" // conservative default
	}
	return f.Exec(cmd)
}

// Reboot reboots the Flipper Zero.
// CLI: power reboot
func (f *Flipper) Reboot() (string, error) {
	return f.Exec("power reboot")
}

// Vibro turns the vibration motor on (true) or off (false).
// CLI: vibro <0|1>
func (f *Flipper) Vibro(on bool) (string, error) {
	val := 0
	if on {
		val = 1
	}
	return f.Exec(fmt.Sprintf("vibro %d", val))
}

// LED sets a single LED channel to a brightness value (0-255).
// CLI: led <r|g|b|bl> <0-255>
// channel: "r" (red), "g" (green), "b" (blue), "bl" (backlight)
func (f *Flipper) LED(channel string, value int) (string, error) {
	return f.Exec(fmt.Sprintf("led %s %d", sanitizeArg(channel), value))
}

// --- Sub-GHz (capability-gap primitives) ---

// SubGHzRxRaw starts a raw Sub-GHz capture that is written to a .sub file.
// Useful for protocol-level reverse engineering when decode_raw isn't enough.
// Xtreme firmware appends a trailing `<device>` arg (0 = internal CC1101,
// 1 = external); honored when the capability flag is set.
// CLI: subghz rx_raw <file_path> [<frequency>] [<device>]
func (f *Flipper) SubGHzRxRaw(filePath string, frequency uint32, duration time.Duration) (string, error) {
	cmd := fmt.Sprintf("subghz rx_raw %s", sanitizeArg(filePath))
	if frequency > 0 {
		cmd += fmt.Sprintf(" %d", frequency)
	}
	if f.Capabilities().SubGHzNeedsDev {
		cmd += " 0"
	}
	return f.ExecLong(cmd, duration)
}

// SubGHzChat joins an interactive Sub-GHz text chat on the given frequency.
// Long-running and actively transmits — the caller bounds it with a duration.
// Xtreme firmware requires the trailing `<device>` arg.
// CLI: subghz chat <frequency> [<device>]
func (f *Flipper) SubGHzChat(frequency uint32, duration time.Duration) (string, error) {
	cmd := fmt.Sprintf("subghz chat %d", frequency)
	if f.Capabilities().SubGHzNeedsDev {
		cmd += " 0"
	}
	return f.ExecLong(cmd, duration)
}

// --- Infrared (capability-gap primitives) ---

// IRDecodeFile parses a saved .ir file and returns the decoded entries.
// Read-only and local to the SD card — no transmit.
// CLI: ir decode <path>
func (f *Flipper) IRDecodeFile(path string) (string, error) {
	return f.Exec(fmt.Sprintf("ir decode %s", sanitizeArg(path)))
}

// IRUniversalList lists entries in a universal remote library file so the
// agent can see which buttons are available before calling IRUniversal.
// CLI: ir universal <library> list
func (f *Flipper) IRUniversalList(library string) (string, error) {
	return f.Exec(fmt.Sprintf("ir universal %s list", sanitizeArg(library)))
}

// --- NFC (capability-gap primitives via subshell) ---

// NFCRawFrame sends a raw ISO14443 frame to a tag via the nfc subshell and
// returns the tag's response. Fork-gated: not available on Xtreme (no NFC CLI
// subshell).
// Subshell verb: raw <hex>
func (f *Flipper) NFCRawFrame(hexData string, timeout time.Duration) (string, error) {
	return f.NFCSubcommand(fmt.Sprintf("raw %s", sanitizeArg(hexData)), timeout)
}

// NFCAPDU sends an APDU command to a contactless smart card (ISO7816) via
// the nfc subshell. Fork-gated.
// Subshell verb: apdu <hex>
func (f *Flipper) NFCAPDU(apduHex string, timeout time.Duration) (string, error) {
	return f.NFCSubcommand(fmt.Sprintf("apdu %s", sanitizeArg(apduHex)), timeout)
}

// NFCMFURead reads a single MIFARE Ultralight page/block. Fork-gated.
// Subshell verb: mfu rdbl <page>
func (f *Flipper) NFCMFURead(page int, timeout time.Duration) (string, error) {
	return f.NFCSubcommand(fmt.Sprintf("mfu rdbl %d", page), timeout)
}

// NFCMFUWrite writes 4 bytes of hex data to a MIFARE Ultralight page/block.
// Destructive — overwrites whatever the tag currently holds. Fork-gated.
// Subshell verb: mfu wrbl <page> <hex>
func (f *Flipper) NFCMFUWrite(page int, hexData string, timeout time.Duration) (string, error) {
	return f.NFCSubcommand(fmt.Sprintf("mfu wrbl %d %s", page, sanitizeArg(hexData)), timeout)
}

// NFCDumpProtocol dumps tag contents for a specific MIFARE protocol via the
// nfc subshell (e.g. "Mifare_Classic", "Mifare_Ultralight"). Fork-gated.
// Subshell verb: dump <protocol>
func (f *Flipper) NFCDumpProtocol(protocol string, timeout time.Duration) (string, error) {
	return f.NFCSubcommand(fmt.Sprintf("dump %s", sanitizeArg(protocol)), timeout)
}

// --- RFID (capability-gap primitives) ---

// RFIDRawRead performs a raw 125 kHz capture to a file for later analysis.
// Mode is "ask" or "psk" (pass "" for auto); filePath is where the raw
// capture is written. Read-only from the RF perspective — no transmit.
// CLI: rfid raw_read [<mode>] <file_path>
func (f *Flipper) RFIDRawRead(mode, filePath string, duration time.Duration) (string, error) {
	return f.withSuccessBuzz(func() (string, error) {
		cmd := "rfid raw_read"
		if mode != "" {
			cmd += " " + sanitizeArg(mode)
		}
		if filePath != "" {
			cmd += " " + sanitizeArg(filePath)
		}
		return f.ExecLong(cmd, duration)
	})
}

// RFIDRawAnalyze post-processes a raw LF capture, attempting to decode the
// contained protocol. Pure local analysis — no RF activity.
// CLI: rfid raw_analyze <file_path>
func (f *Flipper) RFIDRawAnalyze(filePath string) (string, error) {
	return f.Exec(fmt.Sprintf("rfid raw_analyze %s", sanitizeArg(filePath)))
}

// RFIDRawEmulate replays a raw 125 kHz capture against a reader. Active
// transmission — use with authorisation.
// CLI: rfid raw_emulate <file_path>
func (f *Flipper) RFIDRawEmulate(filePath string, duration time.Duration) (string, error) {
	return f.ExecLong(fmt.Sprintf("rfid raw_emulate %s", sanitizeArg(filePath)), duration)
}

// --- OneWire / iButton helpers ---

// OneWireSearch enumerates devices on the 1-Wire bus. Read-only; buzzes on
// success so the user knows something was found.
// CLI: onewire search
func (f *Flipper) OneWireSearch(duration time.Duration) (string, error) {
	return f.withSuccessBuzz(func() (string, error) {
		return f.ExecLong("onewire search", duration)
	})
}

// --- GPIO / hardware recon ---

// looksLikeUnknownCommand reports whether out reads like the Flipper CLI's
// "command not found" error. Keyed on the error strings seen in the firmware
// sources across forks.
func looksLikeUnknownCommand(out string) bool {
	l := strings.ToLower(out)
	return strings.Contains(l, "not a recognized") ||
		strings.Contains(l, "unknown command") ||
		strings.Contains(l, "command not found")
}

// I2CScan scans the I²C bus for connected devices. Tries the built-in `i2c
// scan` CLI first (available on Xtreme and forks that ship it); if the
// firmware rejects the command, falls back to launching the "I2C Scanner"
// FAP via loader_open. Buzzes on success.
// CLI: i2c scan  →  loader open "I2C Scanner"
func (f *Flipper) I2CScan() (string, error) {
	return f.withSuccessBuzz(func() (string, error) {
		out, err := f.RawCLI("i2c scan")
		if err == nil && !looksLikeUnknownCommand(out) {
			return out, nil
		}
		return f.Exec(`loader open "I2C Scanner"`)
	})
}

// --- Scripting ---

// JSRun executes a saved JavaScript file on the Flipper's JS runtime.
// Fork-gated: only the Xtreme, Momentum, and RogueMaster forks ship a JS
// engine. On stock the call returns a friendly-fork error rather than
// issuing a no-op CLI command that hangs.
// CLI: js <path>
func (f *Flipper) JSRun(path string, duration time.Duration) (string, error) {
	caps := f.Capabilities()
	switch strings.ToLower(caps.FirmwareFork) {
	case "xtreme", "momentum", "roguemaster":
		// supported
	default:
		return "", fmt.Errorf("JS runtime not available on %s firmware — switch to Xtreme/Momentum/RogueMaster or run the script from the on-device JS Runner app", caps.FriendlyFork())
	}
	return f.ExecLong(fmt.Sprintf("js %s", sanitizeArg(path)), duration)
}

// --- Storage (capability-gap primitives) ---

// StorageCopy copies a file or directory on the Flipper SD card.
// CLI: storage copy <src> <dst>
func (f *Flipper) StorageCopy(src, dst string) (string, error) {
	return f.Exec(fmt.Sprintf("storage copy %s %s", sanitizeArg(src), sanitizeArg(dst)))
}

// StorageRename renames/moves a file or directory on the SD card.
// CLI: storage rename <src> <dst>
func (f *Flipper) StorageRename(src, dst string) (string, error) {
	return f.Exec(fmt.Sprintf("storage rename %s %s", sanitizeArg(src), sanitizeArg(dst)))
}

// StorageMD5 returns the MD5 hash of a file on the SD card.
// CLI: storage md5 <path>
func (f *Flipper) StorageMD5(path string) (string, error) {
	return f.Exec(fmt.Sprintf("storage md5 %s", sanitizeArg(path)))
}

// StorageTree walks a directory recursively and returns its tree listing.
// CLI: storage tree <path>
func (f *Flipper) StorageTree(path string) (string, error) {
	return f.Exec(fmt.Sprintf("storage tree %s", sanitizeArg(path)))
}

// --- Loader FAP shortcuts ---
//
// These thin wrappers launch a specific FAP via `loader open`. They quote
// multi-word app names explicitly so the CLI parses them as a single
// argument. If the FAP is not installed the Flipper surfaces a "Not
// found" error through the returned string.

// LoaderNFCMagic launches the "NFC Magic" FAP used to write MIFARE magic tags.
func (f *Flipper) LoaderNFCMagic() (string, error) { return f.Exec(`loader open "NFC Magic"`) }

// LoaderMFKey launches the "MFKey32" FAP for MIFARE Classic key recovery.
func (f *Flipper) LoaderMFKey() (string, error) { return f.Exec(`loader open MFKey32`) }

// LoaderMifareNested launches the "Mifare Nested" FAP (nested attack recovery).
func (f *Flipper) LoaderMifareNested() (string, error) { return f.Exec(`loader open "Mifare Nested"`) }

// LoaderPicopass launches the "PicoPass" FAP (HID iClass/Picopass tooling).
func (f *Flipper) LoaderPicopass() (string, error) { return f.Exec(`loader open PicoPass`) }

// LoaderSeader launches the "SEADER" FAP (HID iClass SE advanced tooling).
func (f *Flipper) LoaderSeader() (string, error) { return f.Exec(`loader open SEADER`) }

// LoaderT5577MultiWriter launches the "T5577 Multiwriter" FAP for batch
// writing of 125 kHz T5577 tags.
func (f *Flipper) LoaderT5577MultiWriter() (string, error) {
	return f.Exec(`loader open "T5577 Multiwriter"`)
}

// LoaderSubGHzBruteforcer launches the "Sub-GHz BF" brute-force FAP.
// Destructive by design — runs enormous code sweeps.
func (f *Flipper) LoaderSubGHzBruteforcer() (string, error) {
	return f.Exec(`loader open "Sub-GHz BF"`)
}

// LoaderSubGHzPlaylist launches the "Playlist" FAP that replays a sequence of
// .sub captures.
func (f *Flipper) LoaderSubGHzPlaylist() (string, error) { return f.Exec(`loader open Playlist`) }

// LoaderProtoView launches the "ProtoView" FAP for raw Sub-GHz signal visualisation.
func (f *Flipper) LoaderProtoView() (string, error) { return f.Exec(`loader open ProtoView`) }

// LoaderSpectrumAnalyzer launches the "Spectrum Analyzer" FAP.
func (f *Flipper) LoaderSpectrumAnalyzer() (string, error) {
	return f.Exec(`loader open "Spectrum Analyzer"`)
}

// LoaderSignalGenerator launches the "Signal Generator" FAP.
func (f *Flipper) LoaderSignalGenerator() (string, error) {
	return f.Exec(`loader open "Signal Generator"`)
}

// LoaderNRF24Mousejacker launches the "NRF24 Mousejacker" FAP. Requires an
// external NRF24 devboard on the GPIO header.
func (f *Flipper) LoaderNRF24Mousejacker() (string, error) {
	return f.Exec(`loader open "NRF24 Mousejacker"`)
}

// LoaderUARTTerminal launches the "UART Terminal" FAP for serial comms on the
// Flipper's GPIO header.
func (f *Flipper) LoaderUARTTerminal() (string, error) {
	return f.Exec(`loader open "UART Terminal"`)
}

// LoaderSPIMemManager launches the "SPI Mem Manager" FAP for reading and
// writing SPI flash chips via the GPIO header.
func (f *Flipper) LoaderSPIMemManager() (string, error) {
	return f.Exec(`loader open "SPI Mem Manager"`)
}

// LoaderUnitemp launches the "Unitemp" FAP for reading external temperature
// sensors over the GPIO header.
func (f *Flipper) LoaderUnitemp() (string, error) { return f.Exec(`loader open Unitemp`) }

// --- System (capability-gap primitives) ---

// LoaderInfo returns metadata about the currently running app (name, flags).
// CLI: loader info
func (f *Flipper) LoaderInfo() (string, error) {
	return f.Exec("loader info")
}

// LoaderSignal sends a numeric signal to the currently running app. The
// signal number's meaning is app-specific (many apps document a few custom
// opcodes).
// CLI: loader signal <n>
func (f *Flipper) LoaderSignal(signal int) (string, error) {
	return f.Exec(fmt.Sprintf("loader signal %d", signal))
}

// LogStream opens a live log stream from the Flipper for the supplied
// duration, returning the captured text. Read-only; the Flipper keeps
// running after the stream ends.
// CLI: log
func (f *Flipper) LogStream(duration time.Duration) (string, error) {
	return f.ExecLong("log", duration)
}

// PowerRebootDFU reboots the Flipper into the STM32 DFU bootloader. Leaves
// the device without a running firmware until a host reflashes or the user
// power-cycles — recovery is physical. Guarded as Critical at the risk layer.
// CLI: power reboot2dfu
func (f *Flipper) PowerRebootDFU() (string, error) {
	return f.Exec("power reboot2dfu")
}

// UpdateInstall applies a firmware update from an already-staged manifest on
// the SD card. Long-running — uses a 5-minute deadline. Critical.
// CLI: update install <manifest_path>
func (f *Flipper) UpdateInstall(manifestPath string) (string, error) {
	return f.ExecLong(fmt.Sprintf("update install %s", sanitizeArg(manifestPath)), 5*time.Minute)
}

// CryptoStoreKey stores a key in one of the Flipper's secure-storage slots.
// Overwrites whatever was in that slot.
// CLI: crypto store_key <slot> <hex>
func (f *Flipper) CryptoStoreKey(slot int, keyHex string) (string, error) {
	return f.Exec(fmt.Sprintf("crypto store_key %d %s", slot, sanitizeArg(keyHex)))
}

// BTHCIInfo returns local Bluetooth controller info (chip, firmware version,
// MAC). Read-only; does not bring up a BLE stack — native BLE operations
// still require an external devboard.
// CLI: bt hci_info
func (f *Flipper) BTHCIInfo() (string, error) {
	return f.Exec("bt hci_info")
}
