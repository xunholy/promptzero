package flipper

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/xunholy/promptzero/internal/clisafe"
	pb "github.com/xunholy/promptzero/internal/flipper/rpc/pb"
)

// Infrared carrier bounds mirror the Flipper firmware
// (lib/infrared/encoder_decoder/infrared_common.h):
// INFRARED_MIN_FREQUENCY..INFRARED_MAX_FREQUENCY. Out-of-range values
// either silently no-op or are rejected with an opaque firmware error,
// so we reject up front and give the caller a useful diagnostic.
const (
	irMinFrequencyHz uint32 = 10000
	irMaxFrequencyHz uint32 = 56000
)

// subGHzFreqAllowed reports whether freq falls inside the bands the
// Flipper firmware permits for TX. Out-of-band requests come back as
// an opaque "Frequency not allowed!" banner after a slow round-trip.
// Bands mirror firmware furi_hal_subghz.c regional-table defaults.
func subGHzFreqAllowed(freq uint32) bool {
	switch {
	case freq >= 300_000_000 && freq <= 348_000_000,
		freq >= 387_000_000 && freq <= 464_000_000,
		freq >= 779_000_000 && freq <= 928_000_000:
		return true
	}
	return false
}

// validateSubGHzTxKey checks freq/te/repeat fall in firmware-permitted
// ranges. te=0 means no signal; repeat<=0 means no transmission.
// Frequency out-of-band fails fast with a band-list diagnostic.
func validateSubGHzTxKey(freq uint32, te uint32, repeat int) error {
	if !subGHzFreqAllowed(freq) {
		return fmt.Errorf("invalid Sub-GHz frequency %d Hz (allowed bands: 300-348 MHz, 387-464 MHz, 779-928 MHz)", freq)
	}
	if te == 0 {
		return fmt.Errorf("invalid Sub-GHz te=0 (timing element must be > 0 µs; typical 100-50000)")
	}
	if repeat <= 0 {
		return fmt.Errorf("invalid Sub-GHz repeat count %d (must be >= 1)", repeat)
	}
	return nil
}

// pbStorageDirType is a local alias for the pb.File DIR type so the
// dispatch helpers in this file can compare GetType() without taking a
// dependency on the pb constant from every call site. Mirrors the
// firmware enum (FILE=0, DIR=1).
const pbStorageDirType = pb.File_DIR

// storageErrorBanner formats a wrapped rpc-storage error into the CLI's
// "Storage error: <msg>" shape so ParseStorageStat (parse.go) and
// downstream string parsers see the same banner regardless of transport.
// The wrapped error message includes the firmware status name; map the
// common ERROR_STORAGE_NOT_EXIST case to the human-readable "not found"
// the CLI emits, and pass everything else through verbatim.
func storageErrorBanner(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "ERROR_STORAGE_NOT_EXIST"):
		return "Storage error: not exist\n"
	case strings.Contains(msg, "ERROR_STORAGE_NOT_READY"):
		return "Storage error: not ready\n"
	case strings.Contains(msg, "ERROR_STORAGE_DENIED"):
		return "Storage error: denied\n"
	case strings.Contains(msg, "ERROR_STORAGE_INVALID_NAME"):
		return "Storage error: invalid name\n"
	case strings.Contains(msg, "ERROR_STORAGE_INVALID_PARAMETER"):
		return "Storage error: invalid parameter\n"
	case strings.Contains(msg, "ERROR_STORAGE_EXIST"):
		return "Storage error: already exist\n"
	case strings.Contains(msg, "ERROR_STORAGE_INTERNAL"):
		return "Storage error: internal\n"
	case strings.Contains(msg, "ERROR_STORAGE_NOT_IMPLEMENTED"):
		return "Storage error: not implemented\n"
	case strings.Contains(msg, "ERROR_STORAGE_ALREADY_OPEN"):
		return "Storage error: already open\n"
	case strings.Contains(msg, "ERROR_STORAGE_DIR_NOT_EMPTY"):
		return "Storage error: dir not empty\n"
	}
	return "Storage error: " + msg + "\n"
}

// ansiRE strips ANSI CSI sequences used by Flipper firmware to colour CLI
// output (e.g. `\x1b[31mError: …\x1b[0m`). Applied when pattern-matching
// output text, so matches are colour-agnostic.
var ansiRE = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)

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

// validLEDChannels mirrors the firmware notification module — anything
// else is silently no-op'd or comes back as an opaque "unknown channel"
// banner depending on fork.
var validLEDChannels = map[string]struct{}{
	"r":  {},
	"g":  {},
	"b":  {},
	"bl": {},
}

// validateLEDArgs centralises channel + brightness checks for SetLED
// and LED.
func validateLEDArgs(channel string, value int) error {
	if _, ok := validLEDChannels[channel]; !ok {
		return fmt.Errorf("invalid LED channel %q (valid: r, g, b, bl)", channel)
	}
	if value < 0 || value > 255 {
		return fmt.Errorf("invalid LED value %d (must be 0-255)", value)
	}
	return nil
}

// SetLED sets the RGB LED to the given color + brightness (0-255). Best-effort
// — errors are returned but most callers ignore them. The REPL drives this at
// turn scope so the LED stays steady for the whole prompt, rather than
// flickering on/off per scan.
// Color is one of "r", "g", "b" (or "bl" for backlight).
func (f *Flipper) SetLED(color string, brightness int) error {
	if err := validateLEDArgs(color, brightness); err != nil {
		return err
	}
	_, err := f.Exec(fmt.Sprintf("led %s %d", sanitizeArg(color), brightness))
	return err
}

// withSuccessBuzz wraps a scan/receive operation with a 120ms vibration on
// successful detection. LED feedback is handled at the turn level (see main's
// REPL loop) so a single long scan doesn't flicker the LED on and off.
// Vibration errors are swallowed — firmware without `vibro` support won't
// break the scan. Note: the inner `vibro 1` exec is sent directly (not via
// Vibro()), so stealth-mode / vibro-disabled banners from Momentum are not
// detected here; the buzz is best-effort and silent failure is acceptable.
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
//
// Note: withSuccessBuzz is intentionally omitted here. ExecLong returns nil
// on timeout (streaming semantics), so the buzz would always fire. On
// firmware that does not honour Ctrl+C (e.g. Momentum's subghz rx), the
// device may still be executing the command when the vibro Exec is sent,
// causing the buzz Exec calls to hang for their full safety-net deadline.
func (f *Flipper) SubGHzRx(frequency uint32, duration time.Duration) (string, error) {
	return f.SubGHzRxCtx(context.Background(), frequency, duration)
}

// SubGHzRxCtx is the context-aware variant of SubGHzRx. ctx
// cancellation propagates via ExecLongCtx so a turn-level Ctrl+C
// aborts the in-flight capture without waiting for the duration
// timer.
func (f *Flipper) SubGHzRxCtx(ctx context.Context, frequency uint32, duration time.Duration) (string, error) {
	cmd := fmt.Sprintf("subghz rx %d", frequency)
	if f.Capabilities().SubGHzNeedsDev {
		cmd += " 0"
	}
	return f.ExecLongCtx(ctx, cmd, duration)
}

// SubGHzRxStream is the streaming variant of SubGHzRx. Each line emitted
// by firmware while `subghz rx` is running is delivered to onLine as it
// arrives; the callback can return stop=true to terminate the capture
// early (e.g. once a candidate signal lands). duration bounds the call
// like SubGHzRx; ctx cancel also terminates early. The accumulated raw
// output is returned so callers can feed it to ParseSubGHzReceive on
// the streaming path the same way they would on the blocking path.
func (f *Flipper) SubGHzRxStream(ctx context.Context, frequency uint32, duration time.Duration, onLine func(line string) (stop bool)) (string, error) {
	cmd := fmt.Sprintf("subghz rx %d", frequency)
	if f.Capabilities().SubGHzNeedsDev {
		cmd += " 0"
	}
	return f.streamLines(ctx, cmd, duration, onLine)
}

// streamLines is the shared shape used by streaming wrappers around a
// long-running firmware command (SubGHzRxStream, LogStreamLines,
// SubGHzRxRawStream). Each non-echo line emitted by the firmware is
// delivered to onLine as it arrives and accumulated into the returned
// raw string; onLine returning stop=true ends the capture early.
//
// The serial protocol echoes commands back as their first "line", so
// the wrapper drops the line that exactly matches the dispatched
// command before forwarding to onLine. Otherwise every streaming
// caller would see one frame of noise per call.
//
// duration is enforced via context.WithTimeout. Budget/cancel are
// treated as normal stream-end (no error returned), matching ExecLong
// semantics — the partial accumulated output is the caller's result.
// All other errors propagate.
func (f *Flipper) streamLines(ctx context.Context, cmd string, duration time.Duration, onLine func(line string) (stop bool)) (string, error) {
	streamCtx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()

	var sb strings.Builder
	echoSeen := false
	err := f.StreamCtx(streamCtx, cmd, func(line string) (stop bool) {
		if !echoSeen && strings.TrimSpace(line) == cmd {
			echoSeen = true
			return false
		}
		sb.WriteString(line)
		sb.WriteByte('\n')
		if onLine != nil {
			return onLine(line)
		}
		return false
	})
	if err != nil && (errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)) {
		return sb.String(), nil
	}
	return sb.String(), err
}

// SubGHzDecode decodes a previously captured raw Sub-GHz file.
// CLI: subghz decode_raw <file_path>
func (f *Flipper) SubGHzDecode(filePath string) (string, error) {
	return f.Exec(fmt.Sprintf("subghz decode_raw %s", sanitizeArg(filePath)))
}

// SubGHzTxKey transmits a raw Sub-GHz key. Xtreme firmware requires a
// trailing <device> arg (0=internal CC1101, 1=external); appended when the
// detected capability flag is set.
//
// Validates freq/te/repeat before transport: out-of-band frequency
// either no-ops or returns an opaque firmware banner; te=0 produces
// a broken signal; repeat<=0 means no TX. Reject up front so the
// LLM gets a useful diagnostic on its next turn.
// CLI: subghz tx <key_hex> <frequency> <te> <repeat> [device]
func (f *Flipper) SubGHzTxKey(keyHex string, freq uint32, te uint32, repeat int) (string, error) {
	if err := validateSubGHzTxKey(freq, te, repeat); err != nil {
		return "", err
	}
	cmd := fmt.Sprintf("subghz tx %s %d %d %d", sanitizeArg(keyHex), freq, te, repeat)
	if f.Capabilities().SubGHzNeedsDev {
		cmd += " 0"
	}
	return f.Exec(cmd)
}

// --- Infrared ---

// validIRProtocols mirrors the protocol table from the Flipper firmware
// (lib/infrared/encoder_decoder/). Names are case-sensitive on the wire.
// Stable across stock, Momentum, Unleashed, and Xtreme — the IR protocol
// parser lives in the shared libinfrared and isn't fork-customised.
var validIRProtocols = map[string]struct{}{
	"NEC":       {},
	"NECext":    {},
	"NEC42":     {},
	"NEC42ext":  {},
	"Samsung32": {},
	"RC5":       {},
	"RC5X":      {},
	"RC6":       {},
	"SIRC":      {},
	"SIRC15":    {},
	"SIRC20":    {},
	"Kaseikyo":  {},
	"RCA":       {},
	"Pioneer":   {},
}

// IRProtocolNames returns the sorted list of valid IR protocols. Used in
// the validation error message and exposed for any caller that wants to
// enumerate the firmware-supported set (e.g. spec schema generators).
func IRProtocolNames() []string {
	names := make([]string, 0, len(validIRProtocols))
	for k := range validIRProtocols {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// IRTxParsed transmits a decoded infrared signal.
//
// Validates protocol against the firmware allowlist before transport.
// Common LLM hallucinations ("Sony" instead of SIRC, "Panasonic"
// instead of Kaseikyo, lower-case "nec") otherwise reach the firmware
// as an opaque "unknown protocol" banner with a usage dump.
// CLI: ir tx <protocol> <address_hex> <command_hex>
func (f *Flipper) IRTxParsed(protocol string, address string, command string) (string, error) {
	if _, ok := validIRProtocols[protocol]; !ok {
		return "", fmt.Errorf("invalid IR protocol %q (valid: %s)", protocol, strings.Join(IRProtocolNames(), ", "))
	}
	if strings.TrimSpace(address) == "" {
		return "", fmt.Errorf("invalid IR address: empty")
	}
	if strings.TrimSpace(command) == "" {
		return "", fmt.Errorf("invalid IR command: empty")
	}
	return f.Exec(fmt.Sprintf("ir tx %s %s %s", sanitizeArg(protocol), sanitizeArg(address), sanitizeArg(command)))
}

// IRTxRaw transmits a raw infrared signal.
//
// Validates frequency and duty cycle before transport: out-of-range
// values either silently no-op on the firmware or come back as an
// opaque "invalid frequency" error several seconds later. Reject
// up front so the LLM gets a useful diagnostic on its next turn.
// CLI: ir tx RAW F:<freq> DC:<duty_cycle> <data>
func (f *Flipper) IRTxRaw(frequency uint32, dutyCycle float64, data string) (string, error) {
	if frequency < irMinFrequencyHz || frequency > irMaxFrequencyHz {
		return "", fmt.Errorf("invalid IR carrier frequency %d Hz (valid: %d-%d)", frequency, irMinFrequencyHz, irMaxFrequencyHz)
	}
	if math.IsNaN(dutyCycle) || math.IsInf(dutyCycle, 0) || dutyCycle <= 0 || dutyCycle > 1 {
		return "", fmt.Errorf("invalid IR duty cycle %v (valid: 0 < dc <= 1; typical 0.33)", dutyCycle)
	}
	if strings.TrimSpace(data) == "" {
		return "", fmt.Errorf("invalid IR raw data: empty timing list")
	}
	return f.Exec(fmt.Sprintf("ir tx RAW F:%d DC:%g %s", frequency, dutyCycle, sanitizeArg(data)))
}

// IRRx listens for an incoming infrared signal.
// CLI: ir rx
func (f *Flipper) IRRx(timeout time.Duration) (string, error) {
	return f.IRRxCtx(context.Background(), timeout)
}

// IRRxCtx is the context-aware variant of IRRx. Preserves the
// 120 ms success-buzz wrapper.
func (f *Flipper) IRRxCtx(ctx context.Context, timeout time.Duration) (string, error) {
	return f.withSuccessBuzz(func() (string, error) {
		return f.ExecLongCtx(ctx, "ir rx", timeout)
	})
}

// IRRxStream is the line-streaming variant of IRRx. Each line emitted
// by `ir rx` (typically the decoded signal once a remote button is
// pressed) lands at onLine; stop=true ends the capture. Wraps the
// streaming call in withSuccessBuzz so a successful capture still
// triggers the 120 ms vibration on completion — operators rely on
// the buzz to confirm the IR signal was caught without looking at
// the screen.
// CLI: ir rx
func (f *Flipper) IRRxStream(ctx context.Context, timeout time.Duration, onLine func(line string) (stop bool)) (string, error) {
	return f.withSuccessBuzz(func() (string, error) {
		return f.streamLines(ctx, "ir rx", timeout, onLine)
	})
}

// IRRxRaw listens for a raw infrared signal.
// CLI: ir rx raw
func (f *Flipper) IRRxRaw(timeout time.Duration) (string, error) {
	return f.IRRxRawCtx(context.Background(), timeout)
}

// IRRxRawCtx is the context-aware variant of IRRxRaw.
func (f *Flipper) IRRxRawCtx(ctx context.Context, timeout time.Duration) (string, error) {
	return f.ExecLongCtx(ctx, "ir rx raw", timeout)
}

// IRRxRawStream is the line-streaming variant of IRRxRaw. Each pulse
// line emitted while `ir rx raw` is running lands at onLine; stop=true
// ends the capture early. No success buzz — the raw stream typically
// runs to completion via a duration budget rather than a discrete
// "captured" moment.
// CLI: ir rx raw
func (f *Flipper) IRRxRawStream(ctx context.Context, timeout time.Duration, onLine func(line string) (stop bool)) (string, error) {
	return f.streamLines(ctx, "ir rx raw", timeout, onLine)
}

// IRUniversal brute-forces every variant of the named signal category across
// all manufacturer codes in the specified universal remote library. It is NOT
// a single-shot transmission — the firmware sweeps all frames of that signal
// type (e.g. "Power" fires every known power-off frame).
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
		return "", fmt.Errorf("NFC CLI not available on %s firmware — use the on-device NFC app, or switch to stock, Momentum, or Unleashed firmware", caps.FriendlyFork())
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

		// Momentum's `nfc scanner` is a ONE-SHOT poll — it runs a single
		// PCD cycle (~0.8-1.2s), prints "Target lost" when nothing is
		// in the field, and returns to the prompt. To match the on-
		// device "Read" button's UX (wait up to N seconds for the
		// operator to place the card), we loop the subcommand until
		// detection or the overall timeout is exhausted.
		//
		// Keep the last non-empty scanner transcript so callers that
		// inspect Raw output still see something useful even if the
		// final iteration returned a bare prompt.
		deadline := time.Now().Add(timeout)
		var lastResult string
		const perScanBudget = 4 * time.Second // generous per-iteration cap vs the ~1s typical

		detected := false
		for {
			// Send the scanner subcommand.
			if err := f.sendRaw("scanner\r"); err != nil {
				_ = f.sendRaw("exit\r")
				return lastResult, fmt.Errorf("sending scanner command: %w", err)
			}
			budget := time.Until(deadline)
			if budget > perScanBudget {
				budget = perScanBudget
			}
			if budget <= 0 {
				// Overall timeout already expired; treat as no-detect.
				break
			}
			result, err := f.readUntilPrompt(budget)
			if err != nil {
				// Single iteration didn't return to the prompt in
				// time — stop the firmware and drain. Usually means
				// the scanner is running long (card being read).
				_ = f.sendRaw("\x03")
				drainCtx, drainCancel := context.WithTimeout(context.Background(), 2*time.Second)
				drained, _ := f.readUntilPromptCtx(drainCtx)
				drainCancel()
				// Union the interrupted read and the drained bytes so
				// a detection mid-read isn't lost.
				combined := result + drained
				if combined != "" {
					lastResult = combined
				}
			} else if result != "" {
				lastResult = result
			}

			// Did this iteration detect a tag?
			if looksLikeNFCDetection(lastResult) {
				detected = true
				break
			}

			// Not detected — check the overall budget before retrying.
			// Short sleep keeps the CPU polite and gives the operator
			// a moment to reposition the card. Cap the sleep at the
			// remaining budget so the loop exits promptly on timeout.
			remaining := time.Until(deadline)
			if remaining <= 0 {
				break
			}
			sleep := 200 * time.Millisecond
			if remaining < sleep {
				sleep = remaining
			}
			time.Sleep(sleep)
		}

		// Note on UID harvest: Momentum's scanner subcommand
		// identifies the protocol family ("Protocols detected:
		// Mifare Classic") but does NOT emit UID/ATQA/SAK. The
		// scanner's internal ISO14443-A poll halts the card after
		// SELECT, so a raw WUPA+ANTICOLL follow-up from here hits
		// the card in HALT with no field active and returns Timeout.
		// Real UID capture requires the protocol-specific dump
		// subcommand (`dump -p <proto> <path>`) which runs its own
		// field-management and anticol sequence. See the handler
		// layer: nfc_read_save chains to nfc_dump_protocol when the
		// scanner didn't produce a UID.

		// Exit the NFC subshell — robust to firmware variants that
		// consume the first prompt during the transition back to the
		// main shell. Field experience (use-case run after a no-detect
		// iteration): downstream commands like "subghz rx" / "ir rx"
		// failed with "could not find command" because we were still
		// in the nfc subshell. A single exit+read is not enough; we
		// send exit, drain, then send a bare carriage return which
		// the main shell answers with a fresh prompt. If we're still
		// in the subshell after exit, the bare CR is a no-op there
		// and the next round will detect the mismatch — but we've
		// also sent an extra Ctrl+C as belt-and-braces before exit
		// to cancel any in-flight scanner iteration.
		_ = f.sendRaw("\x03")
		ctrlCCtx, ctrlCCancel := context.WithTimeout(context.Background(), 1*time.Second)
		_, _ = f.readUntilPromptCtx(ctrlCCtx)
		ctrlCCancel()

		_ = f.sendRaw("exit\r")
		exitCtx, exitCancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, _ = f.readUntilPromptCtx(exitCtx)
		exitCancel()

		// Confirm the main shell is responsive: send a bare CR and
		// wait briefly for a prompt. If this doesn't land, one more
		// exit+CR gets us out of a surprise nested state.
		_ = f.sendRaw("\r")
		confirmCtx, confirmCancel := context.WithTimeout(context.Background(), 1*time.Second)
		if _, err := f.readUntilPromptCtx(confirmCtx); err != nil {
			_ = f.sendRaw("exit\r")
			_ = f.sendRaw("\r")
		}
		confirmCancel()

		if !detected && lastResult == "" {
			lastResult = "Target lost."
		}
		return lastResult, nil
	})
}

// looksLikeNFCDetection is a cheap pre-check used by the scanner loop
// to decide whether another poll cycle is needed. Full structured
// parsing happens in flipper.ParseNFCDetect at the caller layer; this
// just needs a reliable "card present" signal so NFCDetect can stop
// iterating the moment something lands on the reader.
//
// Two firmware shapes to cover:
//
//   - Older stock/Unleashed: emits a "UID: ..." line + ATQA/SAK/Type
//     block. A real detection always has "UID:".
//   - Momentum (and later Unleashed rebases): scanner outputs
//     "Protocols detected: Mifare Classic" and omits UID entirely.
//     UID harvest requires a follow-up command the loop doesn't own.
//
// Both shapes imply a card in range. The loop breaks on either so
// the caller doesn't wait out the full timeout budget on a firmware
// that uses the newer output.
func looksLikeNFCDetection(raw string) bool {
	lower := strings.ToLower(raw)
	if strings.Contains(lower, "target lost") {
		return false
	}
	return strings.Contains(lower, "uid:") ||
		strings.Contains(lower, "uid =") ||
		strings.Contains(lower, "protocols detected:") ||
		strings.Contains(lower, "protocol detected:")
}

// NFCEmulate launches the NFC emulation app via the loader, waits for the
// app to exit, then verifies the loader is free before returning. This
// ensures subsequent Exec calls are not blocked by "application is open"
// errors. Returns an error if the loader does not free within ~1 second.
// CLI: loader open NFC <file_path>  →  loader close  →  poll loader info
func (f *Flipper) NFCEmulate(filePath string) (string, error) {
	out, err := f.LoaderOpen("NFC", filePath)
	if err != nil {
		return out, err
	}
	// Let the NFC app complete initialisation — closing mid-init leaves
	// the app in an abnormal teardown state.
	time.Sleep(500 * time.Millisecond)
	// The NFC app does not handle FuriSignalExit, so `loader close`
	// returns "has to be closed manually" and leaves the app running.
	// Simulate the back button to trigger the app's normal shutdown
	// path, which is what the user would do on-device. Send it twice
	// (short press + long press) to cover both "exit current screen"
	// and "exit app entirely" cases — the app is idempotent against
	// back presses at its root screen.
	_, _ = f.InputSend("back", "short")
	time.Sleep(100 * time.Millisecond)
	_, _ = f.InputSend("back", "short")
	// 20 s budget: live validation on Momentum showed NFC app teardown can
	// still hold the loader lock past 10 s — the app's "cannot load key
	// file" modal (or similar error dialogs) delays the shutdown path and
	// the post-teardown housekeeping window adds another ~3 s on top. The
	// extra margin eliminates the cascading "application is open" failures
	// in downstream emulation commands without materially slowing the
	// happy path (the poll returns as soon as the lock is acquirable).
	if closeErr := f.waitLoaderClosed(20 * time.Second); closeErr != nil {
		return out, closeErr
	}
	return out, nil
}

// waitLoaderClosed sends `loader close` then polls until the CLI shell's
// loader_lock is actually acquirable — the condition that gates every
// non-parallel-safe command with "cannot be run while an application is
// open".
//
// We can't just poll `loader info` because it reports the cleared app
// name before the loader lock is released. Instead we probe with
// `uptime` (CliCommandFlagDefault = lock-taking, no-arg, read-only) and
// check the response: any "cannot be run while an application is open"
// substring means the lock is still held; an "Uptime:" prefix means
// we're clear. Required for NFCEmulate (and siblings) to guarantee the
// very next app-launching command will actually succeed.
func (f *Flipper) waitLoaderClosed(budget time.Duration) error {
	_, _ = f.Exec("loader close")
	deadline := time.Now().Add(budget)
	// Probe until we see the first successful `uptime` (lock acquirable)
	// as a rough signal that the app's primary thread has exited, then
	// hard-sleep past Momentum's delayed async housekeeping window
	// before a final confirm. Consecutive-success gating was tried at
	// 3/5/N intervals and always raced the ~1 s post-teardown re-lock;
	// the loader's async message queue makes the "not locked" state
	// observable for a moment even though a new app can't yet launch.
	// A simple hard sleep past the housekeeping is the only reliable
	// signal available to us from outside the firmware.
	const postTeardownSettle = 3 * time.Second
	for time.Now().Before(deadline) {
		out, err := f.Exec("uptime")
		if err != nil {
			return fmt.Errorf("flipper: uptime probe: %w", err)
		}
		if strings.Contains(out, "cannot be run while an application is open") {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if strings.Contains(out, "Uptime:") {
			time.Sleep(postTeardownSettle)
			confirm, cerr := f.Exec("uptime")
			if cerr != nil {
				return fmt.Errorf("flipper: uptime confirm: %w", cerr)
			}
			if strings.Contains(confirm, "Uptime:") {
				return nil
			}
			// Housekeeping re-took the lock; keep waiting.
			time.Sleep(100 * time.Millisecond)
			continue
		}
		// Unexpected response — retry until deadline.
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("flipper: loader still locked after close (budget %v)", budget)
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
		// Subcommand timed out — stop firmware, drain to restore subshell prompt,
		// then exit cleanly so the next call starts from a known-good state.
		_ = f.sendRaw("\x03")
		drainCtx, drainCancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, drainErr := f.readUntilPromptCtx(drainCtx)
		drainCancel()
		if drainErr != nil && !errors.Is(drainErr, context.DeadlineExceeded) && !errors.Is(drainErr, context.Canceled) {
			return result, fmt.Errorf("nfc subcommand %q drain: %w", verb, drainErr)
		}
		_ = f.sendRaw("exit\r")
		exitCtx, exitCancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, _ = f.readUntilPromptCtx(exitCtx)
		exitCancel()
		return result, fmt.Errorf("nfc subcommand %q: %w", verb, err)
	}

	if err := f.sendRaw("exit\r"); err != nil {
		f.sendRaw("\x03") // force exit
		return result, fmt.Errorf("exiting nfc subshell: %w", err)
	}
	if _, err := f.readUntilPrompt(5 * time.Second); err != nil {
		f.sendRaw("\x03")  // force exit
		return result, nil // return result despite exit error
	}

	// Momentum's NFC subshell prints "Error: <msg>" (with ANSI colour) when
	// the subcommand fails at the firmware layer — e.g. `mfu rdbl` with no
	// tag present emits "Error: Timeout". Without a physical card or when
	// the tag type doesn't match the subcommand, this is a normal outcome
	// rather than a wrapper bug. Surface it as a Go error so callers can
	// distinguish firmware-reported failure from success; rxTolerant test
	// cases classify "no card" / "timeout" style errors as expected.
	if msg, ok := nfcErrorFromOutput(result); ok {
		return result, fmt.Errorf("nfc %s: %s", verb, msg)
	}

	return result, nil
}

// nfcErrorFromOutput extracts a firmware error message from an NFC subshell
// response. Momentum prints `\x1b[31mError: <msg>\x1b[0m` (ANSI colour-wrapped)
// when a subcommand fails at the firmware layer. Returns the stripped message
// and true if one is found; "" and false otherwise.
func nfcErrorFromOutput(out string) (string, bool) {
	// Strip ANSI CSI sequences (\x1b[<params>m) so pattern matching is
	// colour-agnostic. Accept Momentum's default foreground-colour wrap.
	stripped := ansiRE.ReplaceAllString(out, "")
	for _, line := range strings.Split(stripped, "\n") {
		trim := strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(trim, "Error:"); ok {
			rest = strings.TrimSpace(rest)
			if rest != "" {
				return rest, true
			}
		}
	}
	return "", false
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

// RFIDEmulate emulates an RFID tag for the given duration. The firmware
// command is streaming (prints "Emulating RFID..." then waits for Ctrl+C),
// so the wrapper uses ExecLong with streaming semantics: on deadline the
// lower layer sends \x03 to abort and returns the accumulated output
// with nil error. Pass a reasonable duration (typical: 2–10 s) — a reader
// needs to be pointed at the Flipper during the window.
// CLI: rfid emulate <protocol> <hex_data>
func (f *Flipper) RFIDEmulate(protocol string, data string, duration time.Duration) (string, error) {
	return f.RFIDEmulateCtx(context.Background(), protocol, data, duration)
}

// validateRFIDArgs catches the two failure modes most likely to come
// from an LLM: an empty protocol name, and data that isn't valid hex
// (or has the wrong shape because the model converted to decimal).
//
// We deliberately do NOT allowlist the protocol name. The firmware
// table varies across stock/Momentum/Unleashed/Xtreme — short names
// like "HIDProx" map to "H10301" on some forks, niche names like
// "Pyramid"/"Viking"/"Jablotron" only exist on some. A wrong protocol
// produces a clear firmware error already; a malformed hex payload
// can silently write a corrupted tag, which is the high-cost outcome
// worth catching.
func validateRFIDArgs(protocol string, data string) error {
	if strings.TrimSpace(protocol) == "" {
		return fmt.Errorf("invalid RFID protocol: empty (e.g. EM4100, HIDProx, Indala, AWID, FDX-A, FDX-B)")
	}
	if strings.TrimSpace(data) == "" {
		return fmt.Errorf("invalid RFID data: empty")
	}
	compact := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, data)
	if len(compact)%2 != 0 {
		return fmt.Errorf("invalid RFID data %q: odd length %d", data, len(compact))
	}
	if _, err := hex.DecodeString(compact); err != nil {
		return fmt.Errorf("invalid RFID data: %w", err)
	}
	return nil
}

// RFIDEmulateCtx is the context-aware variant of RFIDEmulate.
//
// Validates protocol non-empty and data as valid hex before the
// emulation window opens. Malformed hex would otherwise silently
// emulate a corrupted card for the full duration.
func (f *Flipper) RFIDEmulateCtx(ctx context.Context, protocol string, data string, duration time.Duration) (string, error) {
	if err := validateRFIDArgs(protocol, data); err != nil {
		return "", err
	}
	return f.ExecLongCtx(ctx, fmt.Sprintf("rfid emulate %s %s", sanitizeArg(protocol), sanitizeArg(data)), duration)
}

// RFIDWrite writes data to an RFID tag.
//
// Same up-front validation as RFIDEmulateCtx — malformed data
// silently writes a corrupted T5577 blank, which is much harder
// to spot than a clean error before TX.
// CLI: rfid write <protocol> <hex_data>
func (f *Flipper) RFIDWrite(protocol string, data string) (string, error) {
	if err := validateRFIDArgs(protocol, data); err != nil {
		return "", err
	}
	return f.ExecLong(fmt.Sprintf("rfid write %s %s", sanitizeArg(protocol), sanitizeArg(data)), 30*time.Second)
}

// --- iButton ---

// IButtonRead reads an iButton key.
// CLI: ikey read
func (f *Flipper) IButtonRead(timeout time.Duration) (string, error) {
	return f.IButtonReadCtx(context.Background(), timeout)
}

// IButtonReadCtx is the context-aware variant of IButtonRead.
// Preserves the 120 ms success-buzz wrapper.
func (f *Flipper) IButtonReadCtx(ctx context.Context, timeout time.Duration) (string, error) {
	return f.withSuccessBuzz(func() (string, error) {
		return f.ExecLongCtx(ctx, "ikey read", timeout)
	})
}

// validIButtonProtocols mirrors the three protocols the Flipper iButton
// stack supports (lib/ibutton/protocols/). Case-sensitive on the wire —
// an LLM hallucinating "dallas" or "Maxim" gets back an opaque
// "unknown protocol" banner otherwise.
var validIButtonProtocols = map[string]struct{}{
	"Dallas":  {},
	"Cyfral":  {},
	"Metakom": {},
}

// validateIButtonHex strips whitespace separators and confirms the
// remaining input decodes as hex. Used by both IButtonEmulate and
// IButtonWrite.
func validateIButtonHex(hexData string) error {
	if strings.TrimSpace(hexData) == "" {
		return fmt.Errorf("invalid iButton hex_data: empty")
	}
	compact := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, hexData)
	if len(compact)%2 != 0 {
		return fmt.Errorf("invalid iButton hex_data %q: odd length %d", hexData, len(compact))
	}
	if _, err := hex.DecodeString(compact); err != nil {
		return fmt.Errorf("invalid iButton hex_data: %w", err)
	}
	return nil
}

// IButtonEmulate emulates an iButton key for the given duration. The
// firmware command is streaming (prints "Emulating key ..." then waits
// for Ctrl+C), so the wrapper uses ExecLong with streaming semantics.
// Supported protocols: Dallas, Cyfral, Metakom. A reader must be in
// contact with the iButton contacts during the emulation window.
// CLI: ikey emulate <protocol> <hex_data>
func (f *Flipper) IButtonEmulate(protocol string, hexData string, duration time.Duration) (string, error) {
	return f.IButtonEmulateCtx(context.Background(), protocol, hexData, duration)
}

// IButtonEmulateCtx is the context-aware variant of IButtonEmulate.
//
// Validates protocol against the three-entry firmware allowlist and
// hexData as valid hex before transport. Bad protocol names otherwise
// reach the firmware as opaque "unknown protocol" banners; malformed
// hex gets rejected mid-stream after the emulation window has already
// burned wall-clock.
func (f *Flipper) IButtonEmulateCtx(ctx context.Context, protocol string, hexData string, duration time.Duration) (string, error) {
	if _, ok := validIButtonProtocols[protocol]; !ok {
		return "", fmt.Errorf("invalid iButton protocol %q (valid: Dallas, Cyfral, Metakom)", protocol)
	}
	if err := validateIButtonHex(hexData); err != nil {
		return "", err
	}
	return f.ExecLongCtx(ctx, fmt.Sprintf("ikey emulate %s %s", sanitizeArg(protocol), sanitizeArg(hexData)), duration)
}

// IButtonWrite writes an iButton key (Dallas only).
//
// Dallas keys are exactly 8 bytes (16 hex chars including family code
// + serial + CRC); shorter / longer input or non-hex characters are
// rejected up front rather than handed to the firmware writer.
// CLI: ikey write Dallas <hex_data>
func (f *Flipper) IButtonWrite(hexData string) (string, error) {
	if err := validateIButtonHex(hexData); err != nil {
		return "", err
	}
	return f.ExecLong(fmt.Sprintf("ikey write Dallas %s", sanitizeArg(hexData)), 30*time.Second)
}

// --- GPIO ---

// GPIOSet sets a GPIO pin to a value.
//
// CLI transport: `gpio set <pin> <value>` text command.
// RPC transport (BLE — text CLI is not available there): selected on
// the value:
//   - 0 or 1: gpio_write_pin (output mode + drive level).
//   - anything else: gpio_set_pin_mode with mode=INPUT, treated as
//     "switch this pin to read mode before a subsequent gpio_read".
//     The CLI has no in-band equivalent for this — it's a transport-
//     specific hook for callers who need to flip a pin to input via
//     RPC before reading.
//
// CLI emits no output on success, so the RPC branch returns an empty
// string to match.
// CLI: gpio set <pin> <value>
func (f *Flipper) GPIOSet(pin string, value int) (string, error) {
	// Pre-dispatch pin allowlist (v0.180). Pre-fix only the RPC path
	// validated the pin name via gpioPinByName — the CLI path
	// forwarded any string through sanitizeArg. A typo like "PA77"
	// reached the firmware as an opaque "unknown pin" error or, on
	// some forks, silently no-op'd. Same allowlist used by both
	// transports now.
	if _, ok := gpioPinByName(pin); !ok {
		return "", fmt.Errorf("invalid GPIO pin %q (valid: PA4, PA6, PA7, PB2, PB3, PC0, PC1, PC3 — case-insensitive)", pin)
	}
	return f.dispatch(
		"gpio_set",
		CommandSupport{HasRPCVerb: true, HasCLI: true},
		func() (string, error) {
			return f.Exec(fmt.Sprintf("gpio set %s %d", sanitizeArg(pin), value))
		},
		func() (string, error) { return f.gpioSetViaRPC(context.Background(), pin, value) },
	)
}

// gpioSetViaRPC drives the BLE-only RPC dispatch for GPIOSet.
// Maps value 0/1 → gpio_set_pin_mode OUTPUT followed by gpio_write_pin
// (the CLI does both atomically on the firmware side; over RPC the two
// verbs are explicit). Any other value → gpio_set_pin_mode INPUT
// (read-mode prep, used by callers about to GPIORead the pin). Output
// format matches the CLI: empty string on success.
func (f *Flipper) gpioSetViaRPC(ctx context.Context, pin string, value int) (string, error) {
	if f.bleClient == nil {
		return "", ErrCommandRequiresUSB
	}
	pinEnum, ok := gpioPinByName(pin)
	if !ok {
		return "", fmt.Errorf("rpc gpio set: unknown pin %q", pin)
	}
	switch value {
	case 0, 1:
		if err := f.bleClient.GPIOSetPinMode(ctx, pinEnum, pb.GpioPinMode_OUTPUT); err != nil {
			return "", fmt.Errorf("rpc gpio_set_pin_mode: %w", err)
		}
		if err := f.bleClient.GPIOWritePin(ctx, pinEnum, uint32(value)); err != nil {
			return "", fmt.Errorf("rpc gpio_write_pin: %w", err)
		}
	default:
		if err := f.bleClient.GPIOSetPinMode(ctx, pinEnum, pb.GpioPinMode_INPUT); err != nil {
			return "", fmt.Errorf("rpc gpio_set_pin_mode: %w", err)
		}
	}
	return "", nil
}

// GPIORead reads the current value of a GPIO pin.
//
// CLI transport: `gpio read <pin>` text command. Output format from
// firmware is "Pin <name> = <0|1>" (with mild fork-to-fork variation).
// RPC transport (BLE): gpio_read_pin streamed via the persistent
// rpc.Client. The numeric value is reformatted as the same single-line
// "Pin <name> = <0|1>\n" string the CLI emits so downstream parsers
// (workflows.gpioValueFromOutput) work without knowing which transport
// produced the output.
// CLI: gpio read <pin>
func (f *Flipper) GPIORead(pin string) (string, error) {
	if _, ok := gpioPinByName(pin); !ok {
		return "", fmt.Errorf("invalid GPIO pin %q (valid: PA4, PA6, PA7, PB2, PB3, PC0, PC1, PC3 — case-insensitive)", pin)
	}
	return f.dispatch(
		"gpio_read",
		CommandSupport{HasRPCVerb: true, HasCLI: true},
		func() (string, error) {
			return f.Exec(fmt.Sprintf("gpio read %s", sanitizeArg(pin)))
		},
		func() (string, error) { return f.gpioReadViaRPC(context.Background(), pin) },
	)
}

// gpioReadViaRPC drives the BLE-only RPC dispatch for GPIORead.
// Switches the pin to INPUT mode first (matching what the CLI's
// `gpio read` does implicitly on the firmware side), then issues
// gpio_read_pin and re-emits the value as the single-line CLI shape so
// transport-agnostic parsers continue to work.
func (f *Flipper) gpioReadViaRPC(ctx context.Context, pin string) (string, error) {
	if f.bleClient == nil {
		return "", ErrCommandRequiresUSB
	}
	pinEnum, ok := gpioPinByName(pin)
	if !ok {
		return "", fmt.Errorf("rpc gpio read: unknown pin %q", pin)
	}
	if err := f.bleClient.GPIOSetPinMode(ctx, pinEnum, pb.GpioPinMode_INPUT); err != nil {
		return "", fmt.Errorf("rpc gpio_set_pin_mode: %w", err)
	}
	v, err := f.bleClient.GPIOReadPin(ctx, pinEnum)
	if err != nil {
		return "", fmt.Errorf("rpc gpio_read_pin: %w", err)
	}
	// Match the firmware CLI's "Pin <name> = <0|1>" output. Use the
	// canonical pin name (uppercased) so case-insensitive callers see
	// the same string regardless of input casing.
	return fmt.Sprintf("Pin %s = %d\n", strings.ToUpper(pin), v), nil
}

// gpioPinByName resolves a pin name (PA7, pa7, PC0, …) to the protobuf
// enum. Case-insensitive. Returns the enum and true on a match,
// otherwise the zero value and false.
func gpioPinByName(name string) (pb.GpioPin, bool) {
	v, ok := pb.GpioPin_value[strings.ToUpper(strings.TrimSpace(name))]
	if !ok {
		return 0, false
	}
	return pb.GpioPin(v), true
}

// --- BadUSB ---

// BadUSBRun launches a BadUSB script via the app loader.
//
// Rejects empty/whitespace scriptPath before transport: an empty path
// produces `loader open "Bad USB" ` (trailing space) which either
// crashes the loader or launches BadUSB with no script — the operator
// then sees the app idle on the Flipper screen with no diagnostic.
// CLI: loader open "Bad USB" <script_path>
func (f *Flipper) BadUSBRun(scriptPath string) (string, error) {
	if strings.TrimSpace(scriptPath) == "" {
		return "", fmt.Errorf("invalid BadUSB script path: empty (expected e.g. /ext/badusb/payload.txt)")
	}
	return f.ExecLong(fmt.Sprintf("loader open \"Bad USB\" %s", sanitizeArg(scriptPath)), 2*time.Minute)
}

// --- Loader ---

// LoaderOpen opens a Flipper application by name with optional arguments.
// The app name is always double-quoted so multi-word names (e.g. "Bad USB",
// "Sub-GHz BF") are parsed as a single token by the firmware's
// args_read_probably_quoted_string_and_trim.
//
// CLI transport: `loader open "<app_name>" [args]`. RPC transport (BLE):
// an AppStartRequest dispatched via the persistent rpc.Client. Both paths
// return an empty success string on success — `loader open` produces no
// CLI output when the launch succeeds, and the RPC ack carries no body
// either, so the (string, error) contract is identical across transports.
//
// CLI: loader open "<app_name>" [args]
//
// Rejects empty/whitespace appName before transport. Empty names
// produce `loader open ""` which the firmware rejects with an
// opaque parse error.
func (f *Flipper) LoaderOpen(appName string, args string) (string, error) {
	if strings.TrimSpace(appName) == "" {
		return "", fmt.Errorf("invalid app name: empty (expected e.g. \"Bad USB\", \"NFC\", \"Sub-GHz\")")
	}
	return f.dispatch(
		"loader_open",
		CommandSupport{HasRPCVerb: true, HasCLI: true},
		func() (string, error) {
			cmd := fmt.Sprintf(`loader open "%s"`, sanitizeArg(appName))
			if args != "" {
				cmd += " " + sanitizeArg(args)
			}
			return f.Exec(cmd)
		},
		func() (string, error) { return f.loaderOpenViaRPC(context.Background(), appName, args) },
	)
}

// loaderOpenViaRPC drives the BLE-only RPC dispatch for LoaderOpen. The
// firmware's app_start_request takes a single args string — multi-token
// CLI argument lists are joined by the caller before invocation; the
// RPC verb forwards the string verbatim into the app's args hook.
func (f *Flipper) loaderOpenViaRPC(ctx context.Context, appName, args string) (string, error) {
	if f.bleClient == nil {
		return "", ErrCommandRequiresUSB
	}
	if err := f.bleClient.AppStart(ctx, appName, args); err != nil {
		return "", fmt.Errorf("rpc loader open: %w", err)
	}
	return "", nil
}

// LoaderClose closes the currently running application.
//
// CLI transport: `loader close`. RPC transport (BLE): an AppExitRequest
// dispatched via the persistent rpc.Client. Both paths return an empty
// success string on the happy path; non-OK firmware status (e.g.
// ERROR_APP_NOT_RUNNING when no app is open) surfaces via the wrapped
// error.
//
// CLI: loader close
func (f *Flipper) LoaderClose() (string, error) {
	return f.dispatch(
		"loader_close",
		CommandSupport{HasRPCVerb: true, HasCLI: true},
		func() (string, error) { return f.Exec("loader close") },
		func() (string, error) { return f.loaderCloseViaRPC(context.Background()) },
	)
}

// loaderCloseViaRPC drives the BLE-only RPC dispatch for LoaderClose.
func (f *Flipper) loaderCloseViaRPC(ctx context.Context) (string, error) {
	if f.bleClient == nil {
		return "", ErrCommandRequiresUSB
	}
	if err := f.bleClient.AppExit(ctx); err != nil {
		return "", fmt.Errorf("rpc loader close: %w", err)
	}
	return "", nil
}

// LoaderList lists all available applications.
// CLI: loader list
//
// USB-only: the Flipper firmware exposes no RPC verb for enumerating the
// FAP registry. On BLE this returns ErrCommandRequiresUSB so callers can
// surface a clear "connect via USB" message instead of an opaque
// transport-mode error from Exec.
func (f *Flipper) LoaderList() (string, error) {
	if f.IsBLE() {
		return "", usbOnlyError("loader_list")
	}
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
//
// USB-only: depends on `loader list`, which has no firmware RPC verb. On
// BLE this returns ErrCommandRequiresUSB directly so callers see a
// clear error from the parser layer rather than a transport-level one.
func (f *Flipper) LoaderListParsed() (LoaderApps, error) {
	if f.IsBLE() {
		return LoaderApps{}, usbOnlyError("loader_list_parsed")
	}
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

// validInputEventTypes is the allowlist accepted by all supported firmware
// forks (Momentum input_cli.c:input_cli_send; "repeat" is not handled).
var validInputEventTypes = map[string]struct{}{
	"press": {}, "release": {}, "short": {}, "long": {},
}

// validInputButtons is the allowlist of buttons accepted by `input send`
// on all supported firmware forks (Momentum / Xtreme / OFW share the same
// six d-pad/action keys). Pre-v0.179 the button arg was forwarded to the
// firmware with no host-side check, so a typo like "OK " or "back\t"
// (after sanitizeArg strips control bytes) reached the firmware as an
// unrecognised arg — the LLM then saw an opaque firmware error instead
// of "invalid input button" up front.
var validInputButtons = map[string]struct{}{
	"up": {}, "down": {}, "left": {}, "right": {}, "ok": {}, "back": {},
}

// InputSend sends a synthetic button input event.
//
// CLI transport: `input send <button> <type>`. RPC transport (BLE): a
// gui_send_input_event_request dispatched via the persistent rpc.Client.
// The RPC produces no response body, so on success both transports return
// an empty string — preserving the (string, error) contract.
//
// CLI: input send <button> <type>
// button: up, down, left, right, ok, back
// eventType: press, release, short, long
func (f *Flipper) InputSend(button string, eventType string) (string, error) {
	if _, ok := validInputButtons[button]; !ok {
		return "", fmt.Errorf("invalid input button %q: must be one of up, down, left, right, ok, back", button)
	}
	if _, ok := validInputEventTypes[eventType]; !ok {
		return "", fmt.Errorf("invalid input eventType %q: must be one of press, release, short, long", eventType)
	}
	return f.dispatch(
		"input_send",
		CommandSupport{HasRPCVerb: true, HasCLI: true},
		func() (string, error) {
			return f.Exec(fmt.Sprintf("input send %s %s", sanitizeArg(button), sanitizeArg(eventType)))
		},
		func() (string, error) { return f.inputSendViaRPC(context.Background(), button, eventType) },
	)
}

// inputSendViaRPC drives the BLE-only RPC dispatch for InputSend. The
// firmware ack carries no body; on the happy path we return an empty
// string to mirror the CLI's silent success.
func (f *Flipper) inputSendViaRPC(ctx context.Context, button, eventType string) (string, error) {
	if f.bleClient == nil {
		return "", ErrCommandRequiresUSB
	}
	if err := f.bleClient.SendInput(ctx, button, eventType); err != nil {
		return "", fmt.Errorf("rpc input send: %w", err)
	}
	return "", nil
}

// --- Storage / File Operations ---

// StorageList lists files and directories at the given path.
// CLI: storage list <path>
//
// On BLE the CLI is unavailable and the equivalent RPC verb
// (storage_list_request) is dispatched via the persistent rpc.Client;
// the response is reformatted into the same `\t[D] name\n` /
// `\t[F] name <size>b\n` block the firmware emits over USB so
// downstream parsers (parseStorageList in internal/web) work without
// knowing which transport produced it.
func (f *Flipper) StorageList(path string) (string, error) {
	return f.dispatch(
		"storage_list",
		CommandSupport{HasRPCVerb: true, HasCLI: true},
		func() (string, error) {
			return f.Exec(fmt.Sprintf("storage list %s", sanitizeArg(path)))
		},
		func() (string, error) { return f.storageListViaRPC(context.Background(), path) },
	)
}

// storageListViaRPC drives the BLE-only RPC dispatch for StorageList.
// Output format mirrors the CLI block exactly: each entry is
// "\t[D] <name>" for directories or "\t[F] <name> <size>b" for files.
// Empty directories produce an empty string, matching the CLI.
func (f *Flipper) storageListViaRPC(ctx context.Context, path string) (string, error) {
	if f.bleClient == nil {
		return "", ErrCommandRequiresUSB
	}
	files, err := f.bleClient.StorageList(ctx, path, false)
	if err != nil {
		return "", fmt.Errorf("rpc storage list: %w", err)
	}
	var sb strings.Builder
	for _, file := range files {
		if file == nil {
			continue
		}
		sb.WriteByte('\t')
		if file.GetType() == pbStorageDirType {
			sb.WriteString("[D] ")
			sb.WriteString(file.GetName())
		} else {
			sb.WriteString("[F] ")
			sb.WriteString(file.GetName())
			sb.WriteByte(' ')
			sb.WriteString(strconv.FormatUint(uint64(file.GetSize()), 10))
			sb.WriteByte('b')
		}
		sb.WriteByte('\n')
	}
	return sb.String(), nil
}

// StorageRead reads the contents of a file.
// CLI: storage read <path>
//
// Over USB the firmware emits "Size: <N>\n" then the raw bytes.
// stripStorageReadHeader and similar callers parse that shape. On BLE
// the RPC verb returns just the bytes; we reformat to match.
func (f *Flipper) StorageRead(path string) (string, error) {
	return f.dispatch(
		"storage_read",
		CommandSupport{HasRPCVerb: true, HasCLI: true},
		func() (string, error) {
			return f.Exec(fmt.Sprintf("storage read %s", sanitizeArg(path)))
		},
		func() (string, error) { return f.storageReadViaRPC(context.Background(), path) },
	)
}

// storageReadViaRPC mirrors the CLI's "Size: N\n<bytes>" output shape.
// Tools downstream (cmd/mifaretest's stripStorageReadHeader) strip the
// header line if present, so emitting it preserves transport-agnostic
// parsing.
func (f *Flipper) storageReadViaRPC(ctx context.Context, path string) (string, error) {
	if f.bleClient == nil {
		return "", ErrCommandRequiresUSB
	}
	data, err := f.bleClient.StorageRead(ctx, path)
	if err != nil {
		return "", fmt.Errorf("rpc storage read: %w", err)
	}
	var sb strings.Builder
	sb.WriteString("Size: ")
	sb.WriteString(strconv.Itoa(len(data)))
	sb.WriteByte('\n')
	sb.Write(data)
	return sb.String(), nil
}

// StorageWrite writes data to a file using the write_chunk protocol.
func (f *Flipper) StorageWrite(path string, data string) error {
	return f.StorageWriteCtx(context.Background(), path, data)
}

// StorageWriteCtx is the context-aware variant of StorageWrite. On BLE
// the firmware exposes only RPC, so we dispatch via the persistent
// rpc.Client (storage_write_request, multi-Main with has_next) instead
// of the USB-only write_chunk text protocol that WriteFileCtx uses.
func (f *Flipper) StorageWriteCtx(ctx context.Context, path string, data string) error {
	if f.IsBLE() {
		return f.storageWriteViaRPC(ctx, path, []byte(data))
	}
	return f.WriteFileCtx(ctx, path, []byte(data))
}

// storageWriteViaRPC drives the BLE-only RPC dispatch for StorageWrite.
// Returns a wrapped error on transport failure or non-OK CommandStatus.
func (f *Flipper) storageWriteViaRPC(ctx context.Context, path string, data []byte) error {
	if f.bleClient == nil {
		return ErrCommandRequiresUSB
	}
	if err := f.bleClient.StorageWrite(ctx, path, data); err != nil {
		return fmt.Errorf("rpc storage write: %w", err)
	}
	return nil
}

// StorageRemove removes a file or directory.
// CLI: storage remove <path>
func (f *Flipper) StorageRemove(path string) (string, error) {
	return f.dispatch(
		"storage_remove",
		CommandSupport{HasRPCVerb: true, HasCLI: true},
		func() (string, error) {
			return f.Exec(fmt.Sprintf("storage remove %s", sanitizeArg(path)))
		},
		func() (string, error) { return f.storageRemoveViaRPC(context.Background(), path) },
	)
}

// storageRemoveViaRPC drives the BLE-only RPC dispatch for StorageRemove.
// The CLI's `storage remove` succeeds silently and emits an empty body;
// we return "" on success to match. Non-OK CommandStatus surfaces as an
// error so callers don't silently treat a missing file as removed.
func (f *Flipper) storageRemoveViaRPC(ctx context.Context, path string) (string, error) {
	if f.bleClient == nil {
		return "", ErrCommandRequiresUSB
	}
	// Default to non-recursive: the CLI's `storage remove` is non-
	// recursive on every firmware fork. Callers wanting recursive
	// semantics use a higher-level workflow that walks first.
	if err := f.bleClient.StorageDelete(ctx, path, false); err != nil {
		return "", fmt.Errorf("rpc storage remove: %w", err)
	}
	return "", nil
}

// StorageMkdir creates a directory.
// CLI: storage mkdir <path>
func (f *Flipper) StorageMkdir(path string) (string, error) {
	return f.dispatch(
		"storage_mkdir",
		CommandSupport{HasRPCVerb: true, HasCLI: true},
		func() (string, error) {
			return f.Exec(fmt.Sprintf("storage mkdir %s", sanitizeArg(path)))
		},
		func() (string, error) { return f.storageMkdirViaRPC(context.Background(), path) },
	)
}

// storageMkdirViaRPC drives the BLE-only RPC dispatch for StorageMkdir.
// CLI emits an empty body on success; we return "" to match.
func (f *Flipper) storageMkdirViaRPC(ctx context.Context, path string) (string, error) {
	if f.bleClient == nil {
		return "", ErrCommandRequiresUSB
	}
	if err := f.bleClient.StorageMkdir(ctx, path); err != nil {
		return "", fmt.Errorf("rpc storage mkdir: %w", err)
	}
	return "", nil
}

// StorageStat returns metadata about a file or directory.
// CLI: storage stat <path>
//
// On BLE the RPC response is reformatted to match the CLI's two
// canonical shapes that ParseStorageStat recognises:
//
//	Directory
//	File, size: <N>
//
// Storage errors map to "Storage error: <msg>" so the parser's error
// branch fires.
func (f *Flipper) StorageStat(path string) (string, error) {
	return f.dispatch(
		"storage_stat",
		CommandSupport{HasRPCVerb: true, HasCLI: true},
		func() (string, error) {
			return f.Exec(fmt.Sprintf("storage stat %s", sanitizeArg(path)))
		},
		func() (string, error) { return f.storageStatViaRPC(context.Background(), path) },
	)
}

// storageStatViaRPC drives the BLE-only RPC dispatch for StorageStat.
// Output mirrors the CLI exactly so ParseStorageStat (parse.go) works
// without conditional branches.
func (f *Flipper) storageStatViaRPC(ctx context.Context, path string) (string, error) {
	if f.bleClient == nil {
		return "", ErrCommandRequiresUSB
	}
	file, err := f.bleClient.StorageStat(ctx, path)
	if err != nil {
		// Surface storage errors in the CLI's "Storage error: <msg>"
		// shape so ParseStorageStat lights up the error path. The
		// rpc.Client wraps the firmware status name into the error
		// (e.g. "ERROR_STORAGE_NOT_EXIST"); humanise the common case.
		msg := storageErrorBanner(err)
		return msg, nil
	}
	if file == nil {
		return "Storage error: empty response", nil
	}
	if file.GetType() == pbStorageDirType {
		return "Directory\n", nil
	}
	return fmt.Sprintf("File, size: %d\n", file.GetSize()), nil
}

// StorageFSInfo returns filesystem info for a storage root.
// CLI: storage info <path>
//
// A real Flipper emits a multi-line block like:
//
//	Label: Flipper SD
//	Type: FAT32
//	60194KiB total
//	42088KiB free
//
// Or, when the filesystem isn't ready (no SD card inserted):
//
//	Storage error: not ready
func (f *Flipper) StorageFSInfo(path string) (string, error) {
	return f.dispatch(
		"storage_info",
		CommandSupport{HasRPCVerb: true, HasCLI: true},
		func() (string, error) {
			return f.Exec(fmt.Sprintf("storage info %s", sanitizeArg(path)))
		},
		func() (string, error) { return f.storageFSInfoViaRPC(context.Background(), path) },
	)
}

// storageFSInfoViaRPC drives the BLE-only RPC dispatch for StorageFSInfo.
// The RPC verb returns total/free uint64 byte counts; the CLI block
// emits "<KiB> total" / "<KiB> free" lines that StorageFSInfoMap
// (parseKiBLine) decodes back to bytes. Reformat to match.
//
// Label/Type are NOT carried in the InfoResponse; the firmware's CLI
// reads those from the storage subsystem in a separate path. We omit
// them here, matching the firmware's behaviour when the underlying
// storage_cli build doesn't print them. parseKiBLine is the only
// canonical consumer downstream of this output.
func (f *Flipper) storageFSInfoViaRPC(ctx context.Context, path string) (string, error) {
	if f.bleClient == nil {
		return "", ErrCommandRequiresUSB
	}
	total, free, err := f.bleClient.StorageInfo(ctx, path)
	if err != nil {
		// Surface a "Storage error: not ready" banner so StorageFSInfoMap's
		// present=false branch lights up — the parser keys off the
		// "Storage error:" prefix exactly.
		return storageErrorBanner(err), nil
	}
	// Round to KiB the same way the CLI does ("%lluKiB total"), so
	// parseKiBLine recovers the byte count by multiplying by 1024.
	totalKiB := total / 1024
	freeKiB := free / 1024
	var sb strings.Builder
	fmt.Fprintf(&sb, "%dKiB total\n", totalKiB)
	fmt.Fprintf(&sb, "%dKiB free\n", freeKiB)
	return sb.String(), nil
}

// StorageFSInfoMap runs `storage info <path>` and parses it into a flat
// key→value map. Known keys:
//
//	present     — "true" / "false"
//	error       — error text when present=false
//	label       — filesystem label (ext) or device name (int)
//	type        — filesystem type ("FAT32", "exFAT", "Virtual", ...)
//	totalSpace  — total bytes (decimal)
//	freeSpace   — free bytes (decimal)
//
// device_info does NOT carry storage fields on any fork; this CLI is
// the canonical source both for the mobile app and /status.
func (f *Flipper) StorageFSInfoMap(path string) (map[string]string, error) {
	raw, err := f.StorageFSInfo(path)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, 6)
	trimmed := strings.TrimSpace(raw)
	if strings.HasPrefix(trimmed, "Storage error:") {
		out["present"] = "false"
		msg := strings.TrimSpace(strings.TrimPrefix(trimmed, "Storage error:"))
		if msg != "" {
			out["error"] = msg
		}
		return out, nil
	}
	out["present"] = "true"
	for _, line := range strings.Split(trimmed, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "Label:"):
			out["label"] = strings.TrimSpace(strings.TrimPrefix(line, "Label:"))
		case strings.HasPrefix(line, "Type:"):
			out["type"] = strings.TrimSpace(strings.TrimPrefix(line, "Type:"))
		case strings.HasPrefix(line, "SN:"):
			// Momentum's storage_cli_info for /ext emits:
			//   SN:<serial_hex> <month>/<year>
			// Parse into individual keys (storage_cli.c printf format).
			rest := strings.TrimSpace(strings.TrimPrefix(line, "SN:"))
			if fields := strings.Fields(rest); len(fields) == 2 {
				out["sd_serial"] = fields[0]
				if parts := strings.SplitN(fields[1], "/", 2); len(parts) == 2 {
					out["sd_manufacturing_month"] = parts[0]
					out["sd_manufacturing_year"] = parts[1]
				}
			} else {
				out["sd_serial"] = rest
			}
		default:
			// "<N>KiB total" / "<N>KiB free" lines.
			if n, suffix, ok := parseKiBLine(line); ok {
				switch suffix {
				case "total":
					out["totalSpace"] = n
				case "free":
					out["freeSpace"] = n
				}
				continue
			}
			// SD-card product-descriptor line: "<manuf_2hex><oem_id> <product> v<maj>.<min>"
			// (storage_cli.c: printf "%02x%s %s v%i.%i"). The first two hex chars are
			// the manufacturer_id; the full line is stored verbatim as sd_product.
			if isSDProductLine(line) {
				out["sd_product"] = line
				out["sd_manufacturer"] = strings.ToUpper(line[:2])
			}
		}
	}
	return out, nil
}

// isSDProductLine heuristically matches Momentum's SD product-descriptor
// line: starts with two hex digits (manufacturer id), continues with an
// OEM string, product name, and a version token like "v1.0". We gate on
// shape rather than regex to keep the parser allocation-free.
func isSDProductLine(line string) bool {
	if len(line) < 6 {
		return false
	}
	hex := func(c byte) bool {
		return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
	}
	if !hex(line[0]) || !hex(line[1]) {
		return false
	}
	return strings.Contains(line, " v") || strings.Contains(line, " V")
}

// parseKiBLine parses "<N>KiB total" or "<N>KiB free" (with optional
// whitespace between the digits and "KiB") into a byte-count string (decimal)
// and the trailing kind ("total" or "free").
func parseKiBLine(line string) (bytes, kind string, ok bool) {
	i := strings.Index(line, "KiB")
	if i <= 0 {
		return "", "", false
	}
	numStr := strings.TrimSpace(line[:i])
	rest := strings.TrimSpace(line[i+len("KiB"):])
	if rest != "total" && rest != "free" {
		return "", "", false
	}
	if numStr == "" {
		return "", "", false
	}
	n, err := strconv.ParseUint(numStr, 10, 64)
	if err != nil {
		return "", "", false
	}
	return fmt.Sprintf("%d", n*1024), rest, true
}

// --- System ---

// DeviceInfo returns device information.
//
// CLI transport: `device_info` text command, response parsed by the
// caller. RPC transport (BLE — text CLI is not available there): a
// SystemDeviceInfoRequest streamed via the persistent rpc.Client; the
// (key, value) pairs are reformatted as the same `key: value\n` block
// the CLI emits so downstream parsing in DeviceInfoMap / parseKVBlock
// is transport-agnostic.
//
// Migrated to the compat-layer dispatch (Phase A). The viaCLI/viaRPC
// closures wrap the same code paths the old inline `if f.IsBLE()`
// branch used, so the public behaviour is identical.
func (f *Flipper) DeviceInfo() (string, error) {
	return f.dispatch(
		"device_info",
		CommandSupport{HasRPCVerb: true, HasCLI: true},
		func() (string, error) { return f.Exec("device_info") },
		func() (string, error) { return f.deviceInfoViaRPC(context.Background()) },
	)
}

// deviceInfoViaRPC drives the BLE-only RPC dispatch for DeviceInfo.
// Output format mirrors the CLI block exactly so callers (DeviceInfoMap,
// detectCapabilities) work without knowing which transport produced it.
func (f *Flipper) deviceInfoViaRPC(ctx context.Context) (string, error) {
	if f.bleClient == nil {
		return "", ErrCommandRequiresUSB
	}
	pairs, err := f.bleClient.DeviceInfo(ctx)
	if err != nil {
		return "", fmt.Errorf("rpc device_info: %w", err)
	}
	var sb strings.Builder
	for _, p := range pairs {
		sb.WriteString(p.Key)
		sb.WriteString(": ")
		sb.WriteString(p.Value)
		sb.WriteByte('\n')
	}
	return sb.String(), nil
}

// DeviceInfoMap runs device_info and parses the output into a flat
// key→value map. Blank lines and lines missing a colon are skipped.
// The full surface is preserved — callers wanting one field (e.g. the
// dolphin name) should look up the key directly. Numeric-looking
// values stay as strings so consumers decide the typing (some fields
// like storage_sdcard_totalSpace are huge int64s that don't survive
// JavaScript number coercion without care).
func (f *Flipper) DeviceInfoMap() (map[string]string, error) {
	raw, err := f.DeviceInfo()
	if err != nil {
		return nil, err
	}
	return parseKVBlock(raw), nil
}

// PowerInfoMap runs the fork-appropriate power_info command and
// returns the parsed key→value map (charge_level, battery_voltage,
// capacity_*, etc.).
//
// Separate from DeviceInfoMap because none of the forks expose power
// fields via device_info: Xtreme and Momentum serve them via
// `info power` (dot-separated keys — normalised to underscore here),
// stock/Unleashed/RogueMaster via the legacy `power_info` (already
// underscore-separated).
func (f *Flipper) PowerInfoMap() (map[string]string, error) {
	raw, err := f.PowerInfo()
	if err != nil {
		return nil, err
	}
	kv := parseKVBlock(raw)
	out := make(map[string]string, len(kv))
	for k, v := range kv {
		// "." → "_" normalisation can collide if firmware ever emits both
		// "foo.bar" and "foo_bar" forms; not currently observed in the wild.
		out[strings.ReplaceAll(k, ".", "_")] = v
	}
	return out, nil
}

// parseKVBlock is the shared parser for Flipper "key: value" line
// blocks (device_info, power_info, storage info). Whitespace around
// the colon and on either side of the value is stripped; the returned
// map preserves the exact key and trimmed string value.
func parseKVBlock(raw string) map[string]string {
	out := make(map[string]string)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		if key == "" {
			continue
		}
		out[key] = val
	}
	return out
}

// RawCLI sends an arbitrary CLI command string to the Flipper and returns
// its output. Escape hatch for firmware features we haven't wrapped, or for
// debugging. Callers MUST risk-gate this — it can reboot the device, write
// arbitrary files, jam frequencies, etc. The 30s timeout is a safety cap;
// for long-running commands use ExecLong directly from a wrapper.
func (f *Flipper) RawCLI(command string) (string, error) {
	return f.ExecLong(command, 30*time.Second)
}

// PowerInfo returns power/battery information. The CLI spelling differs
// by fork: Xtreme uses `info power`; stock/Unleashed/RogueMaster use
// `power_info`. The capability map stores the right verb at connect
// time. On BLE the firmware exposes a single SystemPowerInfoRequest
// regardless of fork — fork-specific CLI spelling is not relevant —
// and the (key, value) pairs are reformatted to the same `key: value`
// block the CLI emits.
//
// Migrated to the compat-layer dispatch (Phase A). Fork-specific CLI
// verb selection still happens inside the viaCLI closure — the
// compat layer doesn't know about per-fork verb spellings, only
// about transport-level routing.
func (f *Flipper) PowerInfo() (string, error) {
	return f.dispatch(
		"power_info",
		CommandSupport{HasRPCVerb: true, HasCLI: true},
		func() (string, error) {
			cmd := f.Capabilities().PowerInfoCmd
			if cmd == "" {
				cmd = "power_info" // conservative default
			}
			return f.Exec(cmd)
		},
		func() (string, error) { return f.powerInfoViaRPC(context.Background()) },
	)
}

// powerInfoViaRPC drives the BLE-only RPC dispatch for PowerInfo.
// Same shape and contract as deviceInfoViaRPC.
func (f *Flipper) powerInfoViaRPC(ctx context.Context) (string, error) {
	if f.bleClient == nil {
		return "", ErrCommandRequiresUSB
	}
	pairs, err := f.bleClient.PowerInfo(ctx)
	if err != nil {
		return "", fmt.Errorf("rpc power_info: %w", err)
	}
	var sb strings.Builder
	for _, p := range pairs {
		sb.WriteString(p.Key)
		sb.WriteString(": ")
		sb.WriteString(p.Value)
		sb.WriteByte('\n')
	}
	return sb.String(), nil
}

// Reboot reboots the Flipper Zero.
//
// CLI transport: `power reboot` text command. The firmware reboots
// immediately so Exec returns whatever bytes (if any) the CLI emitted
// before the device dropped off the bus. RPC transport (BLE — text CLI
// is not available there): SystemRebootRequest with mode=OS streamed
// via the persistent rpc.Client. The firmware does not emit a response
// for reboot requests; the BLE link drops as soon as the bytes are
// flushed. Both branches return an empty string on success to match
// the CLI's typical short/empty output.
// CLI: power reboot
//
// Migrated to the compat-layer dispatch (Phase A).
func (f *Flipper) Reboot() (string, error) {
	return f.dispatch(
		"power reboot",
		CommandSupport{HasRPCVerb: true, HasCLI: true},
		func() (string, error) { return f.Exec("power reboot") },
		func() (string, error) { return f.rebootViaRPC(context.Background(), pb.RebootRequest_OS) },
	)
}

// rebootViaRPC drives the BLE-only RPC dispatch for Reboot /
// PowerRebootDFU. The firmware does not respond to a reboot request —
// the link drops as soon as the request is processed — so we only
// need to write the request and return. The empty-string return mirrors
// the CLI's effectively-empty output before the device disconnects.
func (f *Flipper) rebootViaRPC(ctx context.Context, mode pb.RebootRequest_RebootMode) (string, error) {
	if f.bleClient == nil {
		return "", ErrCommandRequiresUSB
	}
	if err := f.bleClient.Reboot(ctx, mode); err != nil {
		return "", fmt.Errorf("rpc system_reboot: %w", err)
	}
	return "", nil
}

// Vibro turns the vibration motor on (true) or off (false).
// On Momentum, vibro 1 is silently suppressed in two cases:
//   - stealth mode (FuriHalRtcFlagStealthMode): "Flipper is in stealth mode…"
//   - vibro disabled in settings: "Vibro is disabled in settings…"
//
// Both return success at the firmware layer, so we detect the banner and
// return an error so callers know the motor was never activated.
// CLI: vibro <0|1>
func (f *Flipper) Vibro(on bool) (string, error) {
	val := 0
	if on {
		val = 1
	}
	out, err := f.Exec(fmt.Sprintf("vibro %d", val))
	if err == nil && on {
		clean := ansiRE.ReplaceAllString(out, "")
		switch {
		case strings.Contains(clean, "stealth mode"):
			return out, fmt.Errorf("vibro suppressed: Flipper is in stealth mode")
		case strings.Contains(clean, "Vibro is disabled"):
			return out, fmt.Errorf("vibro suppressed: vibro is disabled in settings")
		}
	}
	return out, err
}

// LED sets a single LED channel to a brightness value (0-255).
//
// Validates channel against the four-entry firmware allowlist and
// value to [0, 255] before transport. Unknown channels are silently
// no-op'd on stock firmware; out-of-range values either clamp or
// trigger an opaque firmware banner depending on fork.
// CLI: led <r|g|b|bl> <0-255>
// channel: "r" (red), "g" (green), "b" (blue), "bl" (backlight)
func (f *Flipper) LED(channel string, value int) (string, error) {
	if err := validateLEDArgs(channel, value); err != nil {
		return "", err
	}
	return f.Exec(fmt.Sprintf("led %s %d", sanitizeArg(channel), value))
}

// --- Sub-GHz (capability-gap primitives) ---

// SubGHzRxRaw streams raw Sub-GHz pulse data to the caller's return value.
// Available on Momentum firmware (subghz_cli.c:subghz_cli_command_rx_raw
// streams pulses to stdout with no file-path argument). On stock/Unleashed/
// Xtreme firmware, the rx_raw verb requires a file-path argument that this
// API no longer accepts — those callers should use SubGHzRx for time-bounded
// capture, or construct a .sub capture manually via StorageWrite.
// CLI (Momentum): subghz rx_raw [<frequency>]
func (f *Flipper) SubGHzRxRaw(frequency uint32, duration time.Duration) (string, error) {
	return f.SubGHzRxRawCtx(context.Background(), frequency, duration)
}

// SubGHzRxRawCtx is the context-aware variant of SubGHzRxRaw. The
// same Momentum-only capability gate as the blocking variant
// applies — non-Momentum forks return the file-path-required
// error before any wire traffic.
func (f *Flipper) SubGHzRxRawCtx(ctx context.Context, frequency uint32, duration time.Duration) (string, error) {
	caps := f.Capabilities()
	if caps.SubGHzRxRawHasFilePath {
		return "", fmt.Errorf("subghz rx_raw on %s firmware requires a file-path argument; use SubGHzRx for capture or StorageWrite to build a .sub file", caps.FriendlyFork())
	}
	cmd := "subghz rx_raw"
	if frequency > 0 {
		cmd += fmt.Sprintf(" %d", frequency)
	}
	if caps.SubGHzNeedsDev {
		cmd += " 0"
	}
	return f.ExecLongCtx(ctx, cmd, duration)
}

// SubGHzRxRawStream is the line-streaming variant of SubGHzRxRaw.
// Each pulse line emitted while `subghz rx_raw` is running is
// delivered to onLine; stop=true ends the capture early. The same
// firmware-fork capability check as SubGHzRxRaw applies — non-Momentum
// forks return the file-path-required error before any streaming
// starts.
// CLI (Momentum): subghz rx_raw [<frequency>]
func (f *Flipper) SubGHzRxRawStream(ctx context.Context, frequency uint32, duration time.Duration, onLine func(line string) (stop bool)) (string, error) {
	caps := f.Capabilities()
	if caps.SubGHzRxRawHasFilePath {
		return "", fmt.Errorf("subghz rx_raw on %s firmware requires a file-path argument; use SubGHzRx for capture or StorageWrite to build a .sub file", caps.FriendlyFork())
	}
	cmd := "subghz rx_raw"
	if frequency > 0 {
		cmd += fmt.Sprintf(" %d", frequency)
	}
	if caps.SubGHzNeedsDev {
		cmd += " 0"
	}
	return f.streamLines(ctx, cmd, duration, onLine)
}

// SubGHzChat joins an interactive Sub-GHz text chat on the given frequency.
// Long-running and actively transmits — the caller bounds it with a duration.
// Xtreme firmware requires the trailing `<device>` arg.
// CLI: subghz chat <frequency> [<device>]
func (f *Flipper) SubGHzChat(frequency uint32, duration time.Duration) (string, error) {
	return f.SubGHzChatCtx(context.Background(), frequency, duration)
}

// SubGHzChatCtx is the context-aware variant of SubGHzChat.
func (f *Flipper) SubGHzChatCtx(ctx context.Context, frequency uint32, duration time.Duration) (string, error) {
	cmd := fmt.Sprintf("subghz chat %d", frequency)
	if f.Capabilities().SubGHzNeedsDev {
		cmd += " 0"
	}
	return f.ExecLongCtx(ctx, cmd, duration)
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
// CLI: ir universal list <library>
func (f *Flipper) IRUniversalList(library string) (string, error) {
	return f.Exec(fmt.Sprintf("ir universal list %s", sanitizeArg(library)))
}

// --- NFC (capability-gap primitives via subshell) ---

// NFCRawFrame sends a raw ISO14443 frame to a tag via the nfc subshell and
// returns the tag's response. Fork-gated: not available on Xtreme (no NFC CLI
// subshell).
// Subshell verb (stock/Unleashed): raw <hex>
// Subshell verb (Momentum): raw -p iso14a -d <hex>
// Momentum's NFC CLI uses a flag-based parser; positional args are rejected.
// Protocol defaults to iso14a (ISO 14443-3A), the most common NFC protocol.
func (f *Flipper) NFCRawFrame(hexData string, timeout time.Duration) (string, error) {
	safe := sanitizeArg(hexData)
	if f.Capabilities().NFCFlaggedArgs {
		return f.NFCSubcommand(fmt.Sprintf("raw -p iso14a -d %s", safe), timeout)
	}
	return f.NFCSubcommand(fmt.Sprintf("raw %s", safe), timeout)
}

// NFCAPDU sends an APDU command to a contactless smart card (ISO7816) via
// the nfc subshell. Fork-gated.
// Subshell verb (stock/Unleashed): apdu <hex>
// Subshell verb (Momentum): apdu -d <hex>
func (f *Flipper) NFCAPDU(apduHex string, timeout time.Duration) (string, error) {
	safe := sanitizeArg(apduHex)
	if f.Capabilities().NFCFlaggedArgs {
		return f.NFCSubcommand(fmt.Sprintf("apdu -d %s", safe), timeout)
	}
	return f.NFCSubcommand(fmt.Sprintf("apdu %s", safe), timeout)
}

// NFCMFURead reads a single MIFARE Ultralight page/block. Fork-gated.
// Subshell verb (stock/Unleashed): mfu rdbl <page>
// Subshell verb (Momentum): mfu rdbl -b <page>
func (f *Flipper) NFCMFURead(page int, timeout time.Duration) (string, error) {
	if f.Capabilities().NFCFlaggedArgs {
		return f.NFCSubcommand(fmt.Sprintf("mfu rdbl -b %d", page), timeout)
	}
	return f.NFCSubcommand(fmt.Sprintf("mfu rdbl %d", page), timeout)
}

// NFCMFUWrite writes 4 bytes of hex data to a MIFARE Ultralight page/block.
// Destructive — overwrites whatever the tag currently holds. Fork-gated.
// Subshell verb (stock): mfu wrbl <page> <hex>
// Subshell verb (Momentum/Unleashed): mfu wrbl -b <page> -d <hex>
func (f *Flipper) NFCMFUWrite(page int, hexData string, timeout time.Duration) (string, error) {
	safe := sanitizeArg(hexData)
	if f.Capabilities().NFCFlaggedArgs {
		return f.NFCSubcommand(fmt.Sprintf("mfu wrbl -b %d -d %s", page, safe), timeout)
	}
	return f.NFCSubcommand(fmt.Sprintf("mfu wrbl %d %s", page, safe), timeout)
}

// NFCDumpProtocol dumps tag contents for a specific NFC protocol via the
// nfc subshell. Callers pass the canonical friendly name
// ("Mifare_Classic", "Mifare_Ultralight", "Mifare_Plus", "FeliCa"); the
// wrapper translates to the firmware's accepted token.
//
// Subshell verb (stock/Unleashed): dump <protocol>
// Subshell verb (Momentum):        dump -p <token>   (token is mfc/mfu/mfp/felica)
//
// Pass an empty string to skip the protocol arg entirely — Momentum's
// `dump` (no -p) auto-detects the protocol and writes a .nfc file in
// /ext/nfc/dump-YYYYMMDD-HHMMSS.nfc. That auto-save shape is the real
// "scan and save" workflow on Momentum and is preferred when the
// caller doesn't already know the protocol.
func (f *Flipper) NFCDumpProtocol(protocol string, timeout time.Duration) (string, error) {
	if strings.TrimSpace(protocol) == "" {
		return f.NFCSubcommand("dump", timeout)
	}
	safe := sanitizeArg(protocol)
	if f.Capabilities().NFCFlaggedArgs {
		token := momentumDumpProtocolToken(safe)
		return f.NFCSubcommand(fmt.Sprintf("dump -p %s", token), timeout)
	}
	return f.NFCSubcommand(fmt.Sprintf("dump %s", safe), timeout)
}

// momentumDumpProtocolToken maps the canonical friendly name to the short
// token Momentum's `dump -p` parser accepts. Anything unrecognised is
// passed through unchanged so callers that already know the token aren't
// surprised by a silent rewrite.
func momentumDumpProtocolToken(canonical string) string {
	switch strings.ToLower(strings.ReplaceAll(canonical, " ", "_")) {
	case "mifare_classic", "mfclassic", "classic":
		return "mfc"
	case "mifare_ultralight", "ultralight", "ntag", "ntag213", "ntag215", "ntag216":
		return "mfu"
	case "mifare_plus", "mf_plus":
		return "mfp"
	case "felica":
		return "felica"
	default:
		return canonical
	}
}

// --- RFID (capability-gap primitives) ---

// RFIDRawRead performs a raw 125 kHz capture to a file for later analysis.
// Mode is "ask" or "psk" (pass "" for auto); filePath is where the raw
// capture is written. Read-only from the RF perspective — no transmit.
// CLI: rfid raw_read [<mode>] <file_path>
//
// Momentum firmware (confirmed via Next-Flip/Momentum-Firmware lfrfid_cli.c)
// uses the same `rfid raw_read` verb with the same arg shape as stock.
// Firmware-side arg errors are reported as a usage banner (no error code),
// which callers would otherwise see as a silent success. Output-scanning
// converts the banner to an explicit error.
func (f *Flipper) RFIDRawRead(mode, filePath string, duration time.Duration) (string, error) {
	return f.withSuccessBuzz(func() (string, error) {
		cmd := "rfid raw_read"
		if mode != "" {
			cmd += " " + sanitizeArg(mode)
		}
		if filePath != "" {
			cmd += " " + sanitizeArg(filePath)
		}
		out, err := f.ExecLong(cmd, duration)
		if err != nil {
			return out, err
		}
		// The LFRFID CLI prints a usage banner (no exit code) when args are
		// rejected. Detect it so callers receive an explicit error rather
		// than a silent-success nil.
		if strings.Contains(out, "Usage:") && strings.Contains(out, "rfid raw_read") {
			return out, fmt.Errorf("flipper CLI: rfid raw_read: %s", firstLine(out))
		}
		return out, nil
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
	return f.RFIDRawEmulateCtx(context.Background(), filePath, duration)
}

// RFIDRawEmulateCtx is the context-aware variant of RFIDRawEmulate.
func (f *Flipper) RFIDRawEmulateCtx(ctx context.Context, filePath string, duration time.Duration) (string, error) {
	return f.ExecLongCtx(ctx, fmt.Sprintf("rfid raw_emulate %s", sanitizeArg(filePath)), duration)
}

// --- OneWire / iButton helpers ---

// OneWireSearch enumerates devices on the 1-Wire bus. Read-only; buzzes on
// success so the user knows something was found.
// CLI: onewire search
func (f *Flipper) OneWireSearch(duration time.Duration) (string, error) {
	return f.OneWireSearchCtx(context.Background(), duration)
}

// OneWireSearchCtx is the context-aware variant of OneWireSearch.
// Preserves the 120 ms success-buzz wrapper.
func (f *Flipper) OneWireSearchCtx(ctx context.Context, duration time.Duration) (string, error) {
	return f.withSuccessBuzz(func() (string, error) {
		return f.ExecLongCtx(ctx, "onewire search", duration)
	})
}

// --- GPIO / hardware recon ---

// firstLine returns the first non-empty line of s, stripped of whitespace.
// Used by output-scanning checks to surface the leading firmware error text.
func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			return t
		}
	}
	return strings.TrimSpace(s)
}

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
		return f.LoaderOpen("I2C Scanner", "")
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
//
// USB-only: there is no storage_copy_request RPC verb on any firmware
// fork (the protobuf surface lacks it — see flipperdevices/flipperzero-
// protobuf storage.proto). On BLE we surface a descriptive error rather
// than hang; agent callers gate on errors.Is(err, ErrCommandRequiresUSB)
// to suggest the operator attach the Flipper via USB.
func (f *Flipper) StorageCopy(src, dst string) (string, error) {
	if f.IsBLE() {
		return "", usbOnlyError("storage_copy")
	}
	return f.Exec(fmt.Sprintf("storage copy %s %s", sanitizeArg(src), sanitizeArg(dst)))
}

// StorageRename renames/moves a file or directory on the SD card.
// CLI: storage rename <src> <dst>
func (f *Flipper) StorageRename(src, dst string) (string, error) {
	return f.dispatch(
		"storage_rename",
		CommandSupport{HasRPCVerb: true, HasCLI: true},
		func() (string, error) {
			return f.Exec(fmt.Sprintf("storage rename %s %s", sanitizeArg(src), sanitizeArg(dst)))
		},
		func() (string, error) { return f.storageRenameViaRPC(context.Background(), src, dst) },
	)
}

// storageRenameViaRPC drives the BLE-only RPC dispatch for StorageRename.
// CLI emits an empty body on success.
func (f *Flipper) storageRenameViaRPC(ctx context.Context, src, dst string) (string, error) {
	if f.bleClient == nil {
		return "", ErrCommandRequiresUSB
	}
	if err := f.bleClient.StorageRename(ctx, src, dst); err != nil {
		return "", fmt.Errorf("rpc storage rename: %w", err)
	}
	return "", nil
}

// StorageMD5 returns the MD5 hash of a file on the SD card.
// CLI: storage md5 <path>
//
// CLI emits the 32-character lowercase-hex digest followed by a newline;
// the RPC variant returns the same string and we append the newline so
// downstream parsers (which trim whitespace) see identical output.
func (f *Flipper) StorageMD5(path string) (string, error) {
	return f.dispatch(
		"storage_md5",
		CommandSupport{HasRPCVerb: true, HasCLI: true},
		func() (string, error) {
			return f.Exec(fmt.Sprintf("storage md5 %s", sanitizeArg(path)))
		},
		func() (string, error) { return f.storageMD5ViaRPC(context.Background(), path) },
	)
}

// storageMD5ViaRPC drives the BLE-only RPC dispatch for StorageMD5.
func (f *Flipper) storageMD5ViaRPC(ctx context.Context, path string) (string, error) {
	if f.bleClient == nil {
		return "", ErrCommandRequiresUSB
	}
	digest, err := f.bleClient.StorageMD5(ctx, path)
	if err != nil {
		return "", fmt.Errorf("rpc storage md5: %w", err)
	}
	return digest + "\n", nil
}

// StorageTree walks a directory recursively and returns its tree listing.
// CLI: storage tree <path>
//
// On BLE the firmware exposes no `tree` RPC verb; we recreate the CLI's
// recursive `storage list` walk by issuing storage_list_request once
// per directory, depth-first. The CLI emits paths absolute to root
// (e.g. "\t[D] /ext/subghz/Tesla\n") rather than relative names — so do
// we, joining the directory path with the entry name and emitting one
// `\t[D|F] <path> [<size>b]` line per entry.
func (f *Flipper) StorageTree(path string) (string, error) {
	return f.dispatch(
		"storage_tree",
		CommandSupport{HasRPCVerb: true, HasCLI: true},
		func() (string, error) {
			return f.Exec(fmt.Sprintf("storage tree %s", sanitizeArg(path)))
		},
		func() (string, error) { return f.storageTreeViaRPC(context.Background(), path) },
	)
}

// storageTreeViaRPC walks the directory tree rooted at path using
// storage_list_request, emitting one CLI-shaped line per entry.
//
// Recursion is iterative against an explicit stack so a deeply nested
// directory tree doesn't blow the goroutine stack. The walk is depth-
// first to match the CLI's emission order: each directory is printed,
// then its descendants, then the next sibling.
//
// Errors on a single sub-directory list are NOT fatal — the CLI's
// `storage tree` continues past unreadable directories. We mirror that
// behaviour by appending a "Storage error: …" banner under the offending
// directory and continuing the walk.
func (f *Flipper) storageTreeViaRPC(ctx context.Context, path string) (string, error) {
	if f.bleClient == nil {
		return "", ErrCommandRequiresUSB
	}
	var sb strings.Builder
	// Stack of directories pending visit. Pop from the back; push
	// children in reverse so emission order matches a left-to-right walk.
	stack := []string{path}
	for len(stack) > 0 {
		dir := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		entries, err := f.bleClient.StorageList(ctx, dir, false)
		if err != nil {
			// Surface the error inline (matches the CLI's tolerant walk)
			// and continue with siblings. Wrapping in "Storage error:"
			// keeps downstream parsers consistent.
			sb.WriteString(storageErrorBanner(err))
			continue
		}
		// Walk entries in firmware order. Collect sub-directories and
		// push them in reverse so the next pop is the first child.
		dirs := make([]string, 0, len(entries))
		for _, file := range entries {
			if file == nil {
				continue
			}
			full := joinStoragePath(dir, file.GetName())
			sb.WriteByte('\t')
			if file.GetType() == pbStorageDirType {
				sb.WriteString("[D] ")
				sb.WriteString(full)
				sb.WriteByte('\n')
				dirs = append(dirs, full)
			} else {
				sb.WriteString("[F] ")
				sb.WriteString(full)
				sb.WriteByte(' ')
				sb.WriteString(strconv.FormatUint(uint64(file.GetSize()), 10))
				sb.WriteString("b\n")
			}
		}
		// Push children in reverse for depth-first, left-to-right.
		for i := len(dirs) - 1; i >= 0; i-- {
			stack = append(stack, dirs[i])
		}
	}
	return sb.String(), nil
}

// joinStoragePath concatenates a directory path and an entry name with a
// single forward slash, collapsing duplicate slashes when the directory
// already ends in one (e.g. root "/").
func joinStoragePath(dir, name string) string {
	if dir == "" {
		return name
	}
	if strings.HasSuffix(dir, "/") {
		return dir + name
	}
	return dir + "/" + name
}

// --- Loader FAP shortcuts ---
//
// These thin wrappers launch a specific FAP via `loader open`. They quote
// multi-word app names explicitly so the CLI parses them as a single
// argument. If the FAP is not installed the Flipper surfaces a "Not
// found" error through the returned string.

// FAP shortcut wrappers below all delegate to LoaderOpen so they pick
// up its transport-aware dispatcher: USB sends `loader open "Name"`
// CLI text; BLE sends an app_start_request RPC. Without going through
// LoaderOpen, BLE callers would hit the rpcMode guard in Exec and get
// ErrCommandRequiresUSB even though app_start is a perfectly valid
// RPC verb. The CLI text shape stays `loader open "<name>"` (quotes
// always — the firmware accepts them on both single and multi-word
// names) so each wrapper is a single LoaderOpen call.

// LoaderNFCMagic launches the "NFC Magic" FAP used to write MIFARE magic tags.
func (f *Flipper) LoaderNFCMagic() (string, error) { return f.LoaderOpen("NFC Magic", "") }

// LoaderMFKey launches the "MFKey32" FAP for MIFARE Classic key recovery.
func (f *Flipper) LoaderMFKey() (string, error) { return f.LoaderOpen("MFKey32", "") }

// LoaderMifareNested launches the "Mifare Nested" FAP (nested attack recovery).
func (f *Flipper) LoaderMifareNested() (string, error) { return f.LoaderOpen("Mifare Nested", "") }

// LoaderPicopass launches the "PicoPass" FAP (HID iClass/Picopass tooling).
func (f *Flipper) LoaderPicopass() (string, error) { return f.LoaderOpen("PicoPass", "") }

// LoaderSeader launches the "SEADER" FAP (HID iClass SE advanced tooling).
func (f *Flipper) LoaderSeader() (string, error) { return f.LoaderOpen("SEADER", "") }

// LoaderT5577MultiWriter launches the "T5577 Multiwriter" FAP for batch
// writing of 125 kHz T5577 tags.
func (f *Flipper) LoaderT5577MultiWriter() (string, error) {
	return f.LoaderOpen("T5577 Multiwriter", "")
}

// LoaderSubGHzBruteforcer launches the "Sub-GHz BF" brute-force FAP.
// Destructive by design — runs enormous code sweeps.
func (f *Flipper) LoaderSubGHzBruteforcer() (string, error) {
	return f.LoaderOpen("Sub-GHz BF", "")
}

// LoaderSubGHzPlaylist launches the "Playlist" FAP that replays a sequence of
// .sub captures.
func (f *Flipper) LoaderSubGHzPlaylist() (string, error) { return f.LoaderOpen("Playlist", "") }

// LoaderProtoView launches the "ProtoView" FAP for raw Sub-GHz signal visualisation.
func (f *Flipper) LoaderProtoView() (string, error) { return f.LoaderOpen("ProtoView", "") }

// LoaderSpectrumAnalyzer launches the "Spectrum Analyzer" FAP.
func (f *Flipper) LoaderSpectrumAnalyzer() (string, error) {
	return f.LoaderOpen("Spectrum Analyzer", "")
}

// LoaderSignalGenerator launches the "Signal Generator" FAP.
func (f *Flipper) LoaderSignalGenerator() (string, error) {
	return f.LoaderOpen("Signal Generator", "")
}

// LoaderNRF24Mousejacker launches the "NRF24 Mousejacker" FAP. Requires an
// external NRF24L01+ devboard wired to the Flipper's GPIO header. The FAP
// takes over the screen and reads target addresses from
// /ext/apps_data/nrfsniff/addresses.txt plus DuckyScript payloads from
// /ext/mousejacker/*.txt. Momentum firmware exposes no nrf24 CLI, so all
// run-time interaction happens through the FAP UI (navigate via
// input_send; back-button to exit).
func (f *Flipper) LoaderNRF24Mousejacker() (string, error) {
	return f.LoaderOpen("NRF24 Mousejacker", "")
}

// LoaderNRF24Sniffer launches the companion "NRF24 Sniffer" FAP. The FAP
// scans 2.4 GHz bands for active wireless-peripheral addresses and writes
// hits to /ext/apps_data/nrfsniff/addresses.txt (comma-separated
// address,rate lines). Prerequisite for any Mousejack flow — the FAP UI
// is operator-driven; there is no CLI equivalent.
func (f *Flipper) LoaderNRF24Sniffer() (string, error) {
	return f.LoaderOpen("NRF24 Sniffer", "")
}

// LoaderUARTTerminal launches the "UART Terminal" FAP for serial comms on the
// Flipper's GPIO header.
func (f *Flipper) LoaderUARTTerminal() (string, error) {
	return f.LoaderOpen("UART Terminal", "")
}

// LoaderSPIMemManager launches the "SPI Mem Manager" FAP for reading and
// writing SPI flash chips via the GPIO header.
func (f *Flipper) LoaderSPIMemManager() (string, error) {
	return f.LoaderOpen("SPI Mem Manager", "")
}

// LoaderUnitemp launches the "Unitemp" FAP for reading external temperature
// sensors over the GPIO header.
func (f *Flipper) LoaderUnitemp() (string, error) { return f.LoaderOpen("Unitemp", "") }

// --- System (capability-gap primitives) ---

// LoaderInfo returns metadata about the currently running app (name, flags).
// CLI: loader info
//
// USB-only: the Flipper firmware exposes no RPC verb that returns the
// currently-running app's metadata. (app_lock_status_request only reports
// a boolean lock state.) On BLE this returns ErrCommandRequiresUSB.
func (f *Flipper) LoaderInfo() (string, error) {
	if f.IsBLE() {
		return "", usbOnlyError("loader_info")
	}
	return f.Exec("loader info")
}

// LoaderSignal sends a numeric signal to the currently running app with an
// optional hex argument (many apps document custom opcodes that consume
// argHex). Pass "" to omit the argument.
// CLI: loader signal <n> [<hex>]
//
// USB-only: the firmware exposes app_button_press / app_button_release /
// app_data_exchange RPC verbs but no generic "send numeric signal"
// equivalent that matches the CLI's free-form (signal, hex) shape, so
// this remains CLI-only. On BLE returns ErrCommandRequiresUSB.
func (f *Flipper) LoaderSignal(signal int, argHex string) (string, error) {
	if f.IsBLE() {
		return "", usbOnlyError("loader_signal")
	}
	cmd := fmt.Sprintf("loader signal %d", signal)
	if argHex != "" {
		cmd += " " + sanitizeArg(argHex)
	}
	return f.Exec(cmd)
}

// LogStream opens a live log stream from the Flipper for the supplied
// duration, returning the captured text. Read-only; the Flipper keeps
// running after the stream ends. level filters the minimum severity —
// empty string means the firmware's default; recognised values are
// "default", "error", "warn", "info", "debug", "trace".
// CLI: log [<level>]
func (f *Flipper) LogStream(duration time.Duration, level string) (string, error) {
	return f.LogStreamCtx(context.Background(), duration, level)
}

// LogStreamCtx is the context-aware variant of LogStream.
func (f *Flipper) LogStreamCtx(ctx context.Context, duration time.Duration, level string) (string, error) {
	cmd := "log"
	if level != "" {
		cmd += " " + sanitizeArg(level)
	}
	return f.ExecLongCtx(ctx, cmd, duration)
}

// LogStreamLines is the line-streaming variant of LogStream. Each log
// line emitted by firmware is delivered to onLine as it arrives;
// returning stop=true ends the capture early.
//
// Empty level uses the firmware default. Recognised values match
// LogStream.
// CLI: log [<level>]
func (f *Flipper) LogStreamLines(ctx context.Context, duration time.Duration, level string, onLine func(line string) (stop bool)) (string, error) {
	cmd := "log"
	if level != "" {
		cmd += " " + sanitizeArg(level)
	}
	return f.streamLines(ctx, cmd, duration, onLine)
}

// PowerRebootDFU reboots the Flipper into the STM32 DFU bootloader. Leaves
// the device without a running firmware until a host reflashes or the user
// power-cycles — recovery is physical. Guarded as Critical at the risk layer.
//
// CLI transport: `power reboot2dfu` text command. RPC transport (BLE):
// SystemRebootRequest with mode=DFU streamed via the persistent
// rpc.Client. As with Reboot, the firmware does not emit a response —
// the link drops immediately. Both branches return an empty string on
// success.
// CLI: power reboot2dfu
func (f *Flipper) PowerRebootDFU() (string, error) {
	return f.dispatch(
		"power reboot2dfu",
		CommandSupport{HasRPCVerb: true, HasCLI: true},
		func() (string, error) { return f.Exec("power reboot2dfu") },
		func() (string, error) { return f.rebootViaRPC(context.Background(), pb.RebootRequest_DFU) },
	)
}

// UpdateInstall applies a firmware update from an already-staged manifest on
// the SD card. Long-running — uses a 5-minute deadline. Critical.
//
// Rejects empty/whitespace manifestPath before transport: the firmware
// command form is `update install <path>` and an empty path produces
// `update install ` which the loader may treat as either a no-op or
// a parse error (fork-dependent). On a real update path that took
// minutes to set up via Updater Builder, sending an empty manifest
// path is a high-cost LLM mistake; reject up front with a clear nudge.
// CLI: update install <manifest_path>
func (f *Flipper) UpdateInstall(manifestPath string) (string, error) {
	if strings.TrimSpace(manifestPath) == "" {
		return "", fmt.Errorf("invalid firmware manifest path: empty (expected e.g. /ext/update/momentum/update.fuf)")
	}
	return f.ExecLong(fmt.Sprintf("update install %s", sanitizeArg(manifestPath)), 5*time.Minute)
}

// validCryptoKeyTypes mirrors the firmware's crypto_cli_key_types
// table (master/simple/encrypted). Anything else is rejected by the
// firmware with an opaque "wrong key type" banner.
var validCryptoKeyTypes = map[string]struct{}{
	"master":    {},
	"simple":    {},
	"encrypted": {},
}

// validateCryptoStoreKey rejects malformed args before the wire dispatch
// runs. Wrong key types or hex/size mismatches either silently corrupt
// the slot or come back as opaque firmware errors several seconds later.
func validateCryptoStoreKey(slot int, keyType string, keySize int, keyHex string) error {
	if slot < 1 {
		return fmt.Errorf("invalid crypto slot %d (must be >= 1; slot 0 is reserved)", slot)
	}
	if _, ok := validCryptoKeyTypes[keyType]; !ok {
		return fmt.Errorf("invalid crypto key type %q (valid: master, simple, encrypted)", keyType)
	}
	if keySize != 128 && keySize != 256 {
		return fmt.Errorf("invalid crypto key size %d (must be 128 or 256 bits)", keySize)
	}
	expectedHexLen := keySize / 4
	if len(keyHex) != expectedHexLen {
		return fmt.Errorf("invalid crypto key hex length %d (want %d chars for %d-bit key)", len(keyHex), expectedHexLen, keySize)
	}
	if _, err := hex.DecodeString(keyHex); err != nil {
		return fmt.Errorf("invalid crypto key hex: %w", err)
	}
	return nil
}

// CryptoStoreKey stores a key in one of the Flipper's secure-storage slots.
// Overwrites whatever was in that slot.
// keyType: "master", "simple", or "encrypted"
// keySize: 128 or 256 (bits); keyHex must be exactly keySize/8 bytes as hex.
//
// Validates slot/keyType/keySize/keyHex before transport. Wrong key types
// or hex/size mismatches surface as opaque firmware errors otherwise.
// CLI: crypto store_key <slot> <keyType> <keySize> <keyHex>
func (f *Flipper) CryptoStoreKey(slot int, keyType string, keySize int, keyHex string) (string, error) {
	if err := validateCryptoStoreKey(slot, keyType, keySize, keyHex); err != nil {
		return "", err
	}
	return f.Exec(fmt.Sprintf("crypto store_key %d %s %d %s", slot, sanitizeArg(keyType), keySize, sanitizeArg(keyHex)))
}

// BTHCIInfo returns local Bluetooth controller info (chip, firmware version,
// MAC). Read-only; does not bring up a BLE stack — native BLE operations
// still require an external devboard.
// CLI: bt hci_info
func (f *Flipper) BTHCIInfo() (string, error) {
	return f.Exec("bt hci_info")
}

// --- Desktop (BLE-only) ---
//
// The Flipper firmware does NOT expose the Desktop subsystem on its
// text CLI on any current fork (stock, Momentum, Unleashed, Xtreme,
// RogueMaster). It is reachable only via Protobuf RPC — applications/
// services/desktop only registers RPC handlers. The methods below
// therefore route through f.bleClient on BLE and surface a clear
// USB-not-supported error otherwise.

// DesktopIsLocked reports whether the device's home screen is currently
// pin-locked. Returns (true, nil) when locked, (false, nil) when
// unlocked. Errors are reserved for transport / protocol failures —
// "unlocked" is a legitimate state the firmware signals via
// CommandStatus_ERROR on the response Empty, which DesktopIsLocked
// translates to (false, nil).
//
// USB transports: returns ErrCommandRequiresUSB-wrapped error. The
// firmware exposes no equivalent CLI verb, so this is structurally a
// BLE-only operation today.
func (f *Flipper) DesktopIsLocked() (bool, error) {
	if !f.IsBLE() {
		return false, usbOnlyError("desktop_is_locked")
	}
	if f.bleClient == nil {
		return false, ErrCommandRequiresUSB
	}
	locked, err := f.bleClient.DesktopIsLocked(context.Background())
	if err != nil {
		return false, fmt.Errorf("rpc desktop_is_locked: %w", err)
	}
	return locked, nil
}

// DesktopUnlock dismisses the pin-lock screen if one is active. Safe
// to call when the device is already unlocked — the firmware returns
// success either way.
//
// USB transports: returns ErrCommandRequiresUSB-wrapped error (no
// equivalent CLI verb on any current firmware fork).
func (f *Flipper) DesktopUnlock() error {
	if !f.IsBLE() {
		return usbOnlyError("desktop_unlock")
	}
	if f.bleClient == nil {
		return ErrCommandRequiresUSB
	}
	if err := f.bleClient.DesktopUnlock(context.Background()); err != nil {
		return fmt.Errorf("rpc desktop_unlock: %w", err)
	}
	return nil
}

// --- Property (BLE-only) ---
//
// Like Desktop, the Property subsystem is RPC-only on the firmware
// (applications/services/property registers no CLI commands on any
// current fork). PropertyGet routes through f.bleClient on BLE and
// surfaces a clear USB-not-supported error otherwise.

// PropertyGet retrieves the (key, value) pairs the firmware exposes
// under the supplied key prefix. An empty prefix returns every
// exposed property. The returned slice preserves the firmware's
// emission order — useful for callers that want to keep keys grouped
// by namespace (e.g. "devinfo.").
//
// USB transports: returns ErrCommandRequiresUSB-wrapped error.
func (f *Flipper) PropertyGet(key string) ([]struct{ Key, Value string }, error) {
	if !f.IsBLE() {
		return nil, usbOnlyError("property_get")
	}
	if f.bleClient == nil {
		return nil, ErrCommandRequiresUSB
	}
	pairs, err := f.bleClient.PropertyGet(context.Background(), key)
	if err != nil {
		return nil, fmt.Errorf("rpc property_get: %w", err)
	}
	return pairs, nil
}
