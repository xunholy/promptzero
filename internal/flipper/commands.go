package flipper

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// sanitizeArg removes bytes that would break out of a single CLI command
// when interpolated into a Flipper serial command string: \r (command
// terminator), \n, \x00, and \x03 (ETX / Ctrl+C). Keep everything else.
func sanitizeArg(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '\r', '\n', '\x00', '\x03':
			return -1
		}
		return r
	}, s)
}

// SanitizeArg is the exported wrapper around sanitizeArg for callers outside
// this package that build Flipper CLI commands directly (e.g. the agent's
// inline bruteforce dispatch). Prefer the typed wrapper functions when one
// exists.
func SanitizeArg(s string) string { return sanitizeArg(s) }

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
			f.sendRaw("\x03") // force exit
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
		f.sendRaw("\x03") // force exit
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
