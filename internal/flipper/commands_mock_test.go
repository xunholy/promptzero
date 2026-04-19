//go:build linux

package flipper_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/xunholy/promptzero/internal/flipper/mock"
)

// momentumDeviceInfo is a device_info blob advertising the Momentum fork,
// so detectCapabilities returns NFCFlaggedArgs=true and SubGHzNeedsDev=true.
const momentumDeviceInfo = `hardware_model                : Flipper Zero
hardware_uid                  : 4521480226E18000
hardware_name                 : MockDolphin
firmware_commit               : abc12345
firmware_origin_fork          : Momentum
firmware_version              : MNTM-MOCK
firmware_build_date           : 01-01-2025`

// TestStorageFSInfoMapHappy verifies that the happy-path block (Label / Type /
// NKiB total / NKiB free) is parsed into the expected map keys and byte counts.
func TestStorageFSInfoMapHappy(t *testing.T) {
	m := mock.Spawn(t, mock.WithHandler("storage", func(args []string) string {
		if len(args) >= 2 && args[0] == "info" {
			return "Label: TestFS\nType: FAT32\n2048KiB total\n1024KiB free"
		}
		return ""
	}))
	flip := connectAndDetect(t, m)

	got, err := flip.StorageFSInfoMap("/ext")
	if err != nil {
		t.Fatalf("StorageFSInfoMap: %v", err)
	}
	if got["present"] != "true" {
		t.Errorf("present = %q, want \"true\"", got["present"])
	}
	if got["label"] != "TestFS" {
		t.Errorf("label = %q, want \"TestFS\"", got["label"])
	}
	if got["type"] != "FAT32" {
		t.Errorf("type = %q, want \"FAT32\"", got["type"])
	}
	// 2048 KiB = 2097152 bytes
	if got["totalSpace"] != "2097152" {
		t.Errorf("totalSpace = %q, want \"2097152\"", got["totalSpace"])
	}
	// 1024 KiB = 1048576 bytes
	if got["freeSpace"] != "1048576" {
		t.Errorf("freeSpace = %q, want \"1048576\"", got["freeSpace"])
	}
}

// TestStorageFSInfoMapError verifies that "Storage error: not ready" maps to
// present=false with the error message captured in the "error" key.
func TestStorageFSInfoMapError(t *testing.T) {
	m := mock.Spawn(t, mock.WithHandler("storage", func(args []string) string {
		if len(args) >= 2 && args[0] == "info" {
			return "Storage error: not ready"
		}
		return ""
	}))
	flip := connectAndDetect(t, m)

	got, err := flip.StorageFSInfoMap("/ext")
	if err != nil {
		t.Fatalf("StorageFSInfoMap: %v", err)
	}
	if got["present"] != "false" {
		t.Errorf("present = %q, want \"false\"", got["present"])
	}
	if got["error"] != "not ready" {
		t.Errorf("error = %q, want \"not ready\"", got["error"])
	}
}

// TestStorageFSInfoMapCRLF verifies that CRLF line endings (as emitted by the
// real Flipper serial port) are tolerated: TrimSpace strips the trailing \r so
// label and type are returned clean.
func TestStorageFSInfoMapCRLF(t *testing.T) {
	m := mock.Spawn(t, mock.WithHandler("storage", func(args []string) string {
		if len(args) >= 2 && args[0] == "info" {
			return "Label: SDCARD\r\nType: EXFAT\r\n4096KiB total\r\n2048KiB free"
		}
		return ""
	}))
	flip := connectAndDetect(t, m)

	got, err := flip.StorageFSInfoMap("/ext")
	if err != nil {
		t.Fatalf("StorageFSInfoMap: %v", err)
	}
	if got["present"] != "true" {
		t.Errorf("present = %q, want \"true\"", got["present"])
	}
	if strings.Contains(got["label"], "\r") {
		t.Errorf("label contains carriage return: %q", got["label"])
	}
	if strings.Contains(got["type"], "\r") {
		t.Errorf("type contains carriage return: %q", got["type"])
	}
	// 4096 KiB = 4194304 bytes, 2048 KiB = 2097152 bytes
	if got["totalSpace"] != "4194304" {
		t.Errorf("totalSpace = %q, want \"4194304\"", got["totalSpace"])
	}
	if got["freeSpace"] != "2097152" {
		t.Errorf("freeSpace = %q, want \"2097152\"", got["freeSpace"])
	}
}

// TestPowerInfoMapDotNormalisation verifies that dot-separated keys from the
// Xtreme/Momentum `info power` response (e.g. "charge.level") are normalised
// to underscore form ("charge_level"). The mock default is Xtreme, so
// PowerInfo() issues "info power" which the handler answers.
func TestPowerInfoMapDotNormalisation(t *testing.T) {
	// Sample output mirrors real Momentum firmware: the "capacity" group
	// emits `remain` (not `remaining`) per furi_hal_power_info_get.
	m := mock.Spawn(t, mock.WithHandler("info", func(args []string) string {
		if len(args) >= 1 && args[0] == "power" {
			return "charge.level                  : 75\nbattery.voltage               : 4050\ncapacity.remain               : 1800"
		}
		return ""
	}))
	flip := connectAndDetect(t, m)

	got, err := flip.PowerInfoMap()
	if err != nil {
		t.Fatalf("PowerInfoMap: %v", err)
	}

	// Dot-form keys must not appear in the output map.
	for _, dotKey := range []string{"charge.level", "battery.voltage", "capacity.remain"} {
		if _, ok := got[dotKey]; ok {
			t.Errorf("dot key %q was not normalised to underscore form", dotKey)
		}
	}
	// Underscore-form keys must be present with correct values.
	want := map[string]string{
		"charge_level":    "75",
		"battery_voltage": "4050",
		"capacity_remain": "1800",
	}
	for k, wantV := range want {
		if got[k] != wantV {
			t.Errorf("%s = %q, want %q", k, got[k], wantV)
		}
	}
}

// TestExecLongTimeoutSendsCtrlC verifies three properties when ExecLong's
// caller budget fires on a command that never emits a closing prompt:
//  1. ExecLong returns within ≤500 ms for a 300 ms timeout (no hang).
//  2. The mock observes a \x03 (Ctrl+C) byte after the command bytes.
//  3. A subsequent Exec on the same flipper succeeds — no leftover prompt
//     state poisons the next transaction.
func TestExecLongTimeoutSendsCtrlC(t *testing.T) {
	// "freeze" is a command that never emits a closing prompt, simulating
	// indefinitely-streaming firmware commands like `subghz rx` or `log`.
	m := mock.Spawn(t,
		mock.WithSuppressPrompt("freeze"),
		mock.WithHandler("freeze", func(args []string) string {
			return "" // body only; prompt suppressed so the read never terminates
		}),
	)
	flip := connectAndDetect(t, m)

	const budget = 300 * time.Millisecond
	start := time.Now()
	out, err := flip.ExecLong("freeze", budget)
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("ExecLong: expected nil error on timeout, got %v", err)
	}
	if elapsed > 600*time.Millisecond {
		t.Errorf("ExecLong took %v, want ≤600 ms", elapsed)
	}
	_ = out // partial accumulated output is fine

	// The mock must have received a Ctrl+C byte after the command.
	rx := m.BytesReceived()
	if !bytes.Contains(rx, []byte{'\x03'}) {
		t.Errorf("mock did not receive Ctrl+C (\\x03) after freeze timeout; bytes: %q", rx)
	}

	// A subsequent Exec must succeed — proves no stale prompt state remains.
	info, execErr := flip.DeviceInfo()
	if execErr != nil {
		t.Errorf("DeviceInfo after ExecLong timeout: %v", execErr)
	}
	if !strings.Contains(info, "hardware_model") {
		t.Errorf("DeviceInfo output missing expected content after timeout: %q", info)
	}
}

// TestSubGHzRxTimeoutSendsCtrlC verifies hypothesis (a) for SubGHzRx: Ctrl+C
// IS sent when the duration budget fires. The test also validates that the
// call completes within a reasonable total bound (no hang from buzz follow-ups
// since withSuccessBuzz was removed from SubGHzRx).
func TestSubGHzRxTimeoutSendsCtrlC(t *testing.T) {
	m := mock.Spawn(t,
		mock.WithSuppressPrompt("subghz"),
		mock.WithHandler("subghz", func(args []string) string {
			if len(args) >= 1 && args[0] == "rx" {
				return "Receiving at 433.92 MHz..."
			}
			return ""
		}),
	)
	flip := connectAndDetect(t, m)

	const budget = 300 * time.Millisecond
	start := time.Now()
	_, err := flip.SubGHzRx(433920000, budget)
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("SubGHzRx: expected nil error on timeout, got %v", err)
	}
	// Without withSuccessBuzz there are no trailing vibro Exec calls, so total
	// is: drain(~100ms) + budget(300ms) + poll overshoot(≤100ms) + instant drain.
	if elapsed > 700*time.Millisecond {
		t.Errorf("SubGHzRx took %v, want ≤700ms", elapsed)
	}

	rx := m.BytesReceived()
	if !bytes.Contains(rx, []byte{'\x03'}) {
		t.Errorf("mock did not receive Ctrl+C (\\x03) after SubGHzRx timeout; bytes: %q", rx)
	}

	// Subsequent call must succeed — no poison left on the session.
	if _, execErr := flip.DeviceInfo(); execErr != nil {
		t.Errorf("DeviceInfo after SubGHzRx timeout: %v", execErr)
	}
}

// TestNFCDetectTimeoutReturnsNilError verifies that when the scanner budget
// expires inside the NFC subshell:
//   - NFCDetect returns nil error (streaming-success semantics)
//   - The mock observed a Ctrl+C byte (scanner was stopped)
//   - A subsequent DeviceInfo call succeeds (session is clean)
func TestNFCDetectTimeoutReturnsNilError(t *testing.T) {
	// stockDeviceInfo (defined in primitives_mock_test.go) omits
	// firmware_origin_fork, so DetectCapabilities returns HasNFCSubshell=true.
	m := mock.Spawn(t,
		mock.WithHandler("device_info", func(_ []string) string { return stockDeviceInfo }),
		// "nfc" enters the subshell: mock emits regular >: prompt which
		// readUntilPrompt accepts (">: " is a substring of "[nfc]>: " match target).
		mock.WithHandler("nfc", func(_ []string) string { return "" }),
		// "scanner" streams forever — no prompt emitted.
		mock.WithSuppressPrompt("scanner"),
		mock.WithHandler("scanner", func(_ []string) string { return "" }),
		mock.WithHandler("exit", func(_ []string) string { return "" }),
	)
	flip := connectAndDetect(t, m)

	const budget = 300 * time.Millisecond
	start := time.Now()
	_, err := flip.NFCDetect(budget)
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("NFCDetect: expected nil error on scanner timeout, got %v", err)
	}
	// Budget fires at ~300ms. Overhead: drain(100ms) + nfc subshell(instant) +
	// scanner poll overshoot(≤100ms) + Ctrl+C drain + exit + vibro buzz.
	if elapsed > 1500*time.Millisecond {
		t.Errorf("NFCDetect took %v, want ≤1500ms", elapsed)
	}

	rx := m.BytesReceived()
	if !bytes.Contains(rx, []byte{'\x03'}) {
		t.Errorf("mock did not receive Ctrl+C (\\x03) after NFCDetect scanner timeout; bytes: %q", rx)
	}

	if _, execErr := flip.DeviceInfo(); execErr != nil {
		t.Errorf("DeviceInfo after NFCDetect timeout: %v", execErr)
	}
}

// --- Task #1: NFC flagged args on Momentum ---

// TestNFCMFURead_MomentumFlaggedArgs verifies that on a Momentum-fork mock,
// NFCMFURead emits `mfu rdbl -b <n>` instead of the legacy positional form.
func TestNFCMFURead_MomentumFlaggedArgs(t *testing.T) {
	m := mock.Spawn(t,
		mock.WithHandler("device_info", func(_ []string) string { return momentumDeviceInfo }),
		mock.WithHandler("nfc", func(_ []string) string { return "" }),
		mock.WithHandler("mfu", func(args []string) string {
			if len(args) >= 3 && args[0] == "rdbl" && args[1] == "-b" && args[2] == "4" {
				return "Block: 4 Data: 01 02 03 04"
			}
			return ""
		}),
		mock.WithHandler("exit", func(_ []string) string { return "" }),
	)
	flip := connectAndDetect(t, m)

	out, err := flip.NFCMFURead(4, 5*time.Second)
	if err != nil {
		t.Fatalf("NFCMFURead (Momentum): %v (out=%q)", err, out)
	}

	seen := map[string]bool{}
	for _, l := range m.Lines() {
		seen[strings.TrimSpace(l)] = true
	}
	if !seen["mfu rdbl -b 4"] {
		t.Errorf("expected flagged form 'mfu rdbl -b 4'; lines=%v", m.Lines())
	}
	if seen["mfu rdbl 4"] {
		t.Errorf("positional form 'mfu rdbl 4' sent on Momentum — should use flagged form; lines=%v", m.Lines())
	}
}

// TestNFCAPDU_MomentumFlaggedArgs verifies that on Momentum, NFCAPDU emits
// `apdu -d <hex>` instead of the legacy positional `apdu <hex>`.
func TestNFCAPDU_MomentumFlaggedArgs(t *testing.T) {
	const apdu = "00A4040007A000000003101000"
	m := mock.Spawn(t,
		mock.WithHandler("device_info", func(_ []string) string { return momentumDeviceInfo }),
		mock.WithHandler("nfc", func(_ []string) string { return "" }),
		mock.WithHandler("apdu", func(args []string) string {
			if len(args) >= 2 && args[0] == "-d" {
				return "Response: 9000"
			}
			return ""
		}),
		mock.WithHandler("exit", func(_ []string) string { return "" }),
	)
	flip := connectAndDetect(t, m)

	out, err := flip.NFCAPDU(apdu, 5*time.Second)
	if err != nil {
		t.Fatalf("NFCAPDU (Momentum): %v (out=%q)", err, out)
	}

	wantLine := "apdu -d " + apdu
	found := false
	for _, l := range m.Lines() {
		if strings.TrimSpace(l) == wantLine {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected flagged form %q; lines=%v", wantLine, m.Lines())
	}
}

// TestNFCRawFrame_MomentumFlaggedArgs verifies that on Momentum, NFCRawFrame
// emits `raw -p iso14a -d <hex>` (required -p protocol + -d data flags).
func TestNFCRawFrame_MomentumFlaggedArgs(t *testing.T) {
	const frame = "3000"
	m := mock.Spawn(t,
		mock.WithHandler("device_info", func(_ []string) string { return momentumDeviceInfo }),
		mock.WithHandler("nfc", func(_ []string) string { return "" }),
		mock.WithHandler("raw", func(args []string) string {
			if len(args) >= 4 && args[0] == "-p" && args[1] == "iso14a" && args[2] == "-d" {
				return "RX: AABB"
			}
			return ""
		}),
		mock.WithHandler("exit", func(_ []string) string { return "" }),
	)
	flip := connectAndDetect(t, m)

	out, err := flip.NFCRawFrame(frame, 5*time.Second)
	if err != nil {
		t.Fatalf("NFCRawFrame (Momentum): %v (out=%q)", err, out)
	}

	wantLine := "raw -p iso14a -d " + frame
	found := false
	for _, l := range m.Lines() {
		if strings.TrimSpace(l) == wantLine {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected flagged form %q; lines=%v", wantLine, m.Lines())
	}
}

// TestNFCDumpProtocol_MomentumFlaggedArgs verifies that on Momentum,
// NFCDumpProtocol emits `dump -p <protocol>` instead of `dump <protocol>`.
func TestNFCDumpProtocol_MomentumFlaggedArgs(t *testing.T) {
	const proto = "Mifare_Classic"
	m := mock.Spawn(t,
		mock.WithHandler("device_info", func(_ []string) string { return momentumDeviceInfo }),
		mock.WithHandler("nfc", func(_ []string) string { return "" }),
		mock.WithHandler("dump", func(args []string) string {
			if len(args) >= 2 && args[0] == "-p" && args[1] == proto {
				return "Dump complete"
			}
			return ""
		}),
		mock.WithHandler("exit", func(_ []string) string { return "" }),
	)
	flip := connectAndDetect(t, m)

	out, err := flip.NFCDumpProtocol(proto, 5*time.Second)
	if err != nil {
		t.Fatalf("NFCDumpProtocol (Momentum): %v (out=%q)", err, out)
	}

	wantLine := "dump -p " + proto
	found := false
	for _, l := range m.Lines() {
		if strings.TrimSpace(l) == wantLine {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected flagged form %q; lines=%v", wantLine, m.Lines())
	}
}

// TestNFCMFURead_StockPositionalRegression confirms stock firmware still
// receives the legacy positional `mfu rdbl <n>` form (not the flagged form).
// The handler-level regression is already covered by TestNFCMFURead_StockSubshell
// in primitives_mock_test.go; this test focuses on the bytes-received level.
func TestNFCMFURead_StockPositionalRegression(t *testing.T) {
	m := mock.Spawn(t,
		mock.WithHandler("device_info", func(_ []string) string { return stockDeviceInfo }),
		mock.WithHandler("nfc", func(_ []string) string { return "" }),
		mock.WithHandler("mfu", func(args []string) string { return "" }),
		mock.WithHandler("exit", func(_ []string) string { return "" }),
	)
	flip := connectAndDetect(t, m)

	_, _ = flip.NFCMFURead(7, 5*time.Second)

	rx := string(m.BytesReceived())
	if !strings.Contains(rx, "mfu rdbl 7") {
		t.Errorf("stock should use positional 'mfu rdbl 7'; bytes=%q", rx)
	}
	if strings.Contains(rx, "mfu rdbl -b 7") {
		t.Errorf("stock should NOT use flagged form 'mfu rdbl -b 7'; bytes=%q", rx)
	}
}

// --- Task #2: RFID raw_read usage-banner error detection ---

// TestRFIDRawRead_BannerDetectedAsError verifies that when the firmware
// returns the LFRFID usage banner (indicating arg rejection), RFIDRawRead
// returns a non-nil error rather than a silent nil.
func TestRFIDRawRead_BannerDetectedAsError(t *testing.T) {
	rfidBanner := "Usage:\r\nrfid read <optional: normal | indala>         - read in ASK/PSK mode\r\n" +
		"rfid <write | emulate> <key_type> <key_data>  - write or emulate a card\r\n" +
		"rfid raw_read <ask | psk> <filename>          - read and save raw data to a file\r\n"

	m := mock.Spawn(t,
		mock.WithHandler("device_info", func(_ []string) string { return momentumDeviceInfo }),
		mock.WithHandler("rfid", func(args []string) string {
			// Simulate firmware rejecting the args and printing the usage banner.
			return rfidBanner
		}),
		mock.WithHandler("led", func(_ []string) string { return "" }),
		mock.WithHandler("vibro", func(_ []string) string { return "" }),
	)
	flip := connectAndDetect(t, m)

	_, err := flip.RFIDRawRead("ask", "/ext/test.rfid", 3*time.Second)
	if err == nil {
		t.Fatal("RFIDRawRead should return an error when firmware emits usage banner")
	}
	if !strings.Contains(err.Error(), "rfid raw_read") {
		t.Errorf("error should mention rfid raw_read, got: %v", err)
	}
}

// TestRFIDRawRead_StockSuccessPath confirms the stock happy path: correct
// verb is emitted and success output does not trigger the banner scanner.
func TestRFIDRawRead_StockSuccessPath(t *testing.T) {
	m := mock.Spawn(t,
		mock.WithHandler("device_info", func(_ []string) string { return stockDeviceInfo }),
		mock.WithHandler("rfid", func(args []string) string {
			if len(args) >= 1 && args[0] == "raw_read" {
				return "Reading raw RFID...\nDone"
			}
			return ""
		}),
		mock.WithHandler("led", func(_ []string) string { return "" }),
		mock.WithHandler("vibro", func(_ []string) string { return "" }),
	)
	flip := connectAndDetect(t, m)

	out, err := flip.RFIDRawRead("ask", "/ext/test.rfid", 3*time.Second)
	if err != nil {
		t.Fatalf("RFIDRawRead (stock happy path): %v (out=%q)", err, out)
	}

	found := false
	for _, l := range m.Lines() {
		if strings.HasPrefix(strings.TrimSpace(l), "rfid raw_read") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected rfid raw_read to be emitted; lines=%v", m.Lines())
	}
}

// --- Task #3: NFCEmulate restores CLI after loader close ---

// TestNFCEmulateClosesLoader verifies that NFCEmulate sends `loader close`
// after opening the NFC app, and that a subsequent DeviceInfo call succeeds
// (no "application is open" poison left on the session).
func TestNFCEmulateClosesLoader(t *testing.T) {
	m := mock.Spawn(t,
		mock.WithHandler("device_info", func(_ []string) string { return stockDeviceInfo }),
		mock.WithHandler("loader", func(args []string) string {
			if len(args) >= 1 {
				switch args[0] {
				case "open":
					return ""
				case "close":
					return "Application was closed"
				case "info":
					// Report no app running so waitLoaderClosed exits on first poll.
					return "No application is running"
				}
			}
			return ""
		}),
	)
	flip := connectAndDetect(t, m)

	_, err := flip.NFCEmulate("/ext/nfc/test.nfc")
	if err != nil {
		t.Fatalf("NFCEmulate: %v", err)
	}

	// Verify loader close was sent.
	sawClose := false
	for _, l := range m.Lines() {
		if strings.TrimSpace(l) == "loader close" {
			sawClose = true
			break
		}
	}
	if !sawClose {
		t.Errorf("NFCEmulate did not send 'loader close'; lines=%v", m.Lines())
	}

	// The CLI must be clean — DeviceInfo must succeed.
	if _, execErr := flip.DeviceInfo(); execErr != nil {
		t.Errorf("DeviceInfo after NFCEmulate: %v", execErr)
	}
}

// TestNFCEmulateLoaderCloseTimeout verifies that NFCEmulate returns an error
// when `loader info` keeps reporting an app as running beyond the 1-second budget.
func TestNFCEmulateLoaderCloseTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped in -short mode: waits up to 1 second for loader budget")
	}
	m := mock.Spawn(t,
		mock.WithHandler("device_info", func(_ []string) string { return stockDeviceInfo }),
		mock.WithHandler("loader", func(args []string) string {
			if len(args) >= 1 {
				switch args[0] {
				case "open":
					return ""
				case "close":
					return "Application NFC has to be closed manually"
				case "info":
					// Simulate app stuck open.
					return "Application \"NFC\" is running"
				}
			}
			return ""
		}),
	)
	flip := connectAndDetect(t, m)

	_, err := flip.NFCEmulate("/ext/nfc/test.nfc")
	if err == nil {
		t.Fatal("NFCEmulate should return an error when loader does not close")
	}
	if !strings.Contains(err.Error(), "loader") {
		t.Errorf("error should mention loader, got: %v", err)
	}
}
