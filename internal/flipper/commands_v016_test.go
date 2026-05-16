//go:build linux

package flipper_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/xunholy/promptzero/internal/flipper/mock"
)

// ─── Sub-GHz device-explicit wrappers ────────────────────────────────────────

// TestSubGHzTxKeyDevice_WireCommand verifies that SubGHzTxKeyDevice emits
// the full form `subghz tx <key> <freq> <te> <repeat> -d <device>` without
// any capability-derived device append (the caller always controls device).
func TestSubGHzTxKeyDevice_WireCommand(t *testing.T) {
	const key = "AABBCCDD"
	const freq = uint32(433920000)
	const te = uint32(400)
	const repeat = 3
	const device = 1

	m := mock.Spawn(t,
		mock.WithHandler("subghz", func(args []string) string { return "" }),
	)
	flip := connectAndDetect(t, m)

	_, err := flip.SubGHzTxKeyDevice(key, freq, te, repeat, device)
	if err != nil {
		t.Fatalf("SubGHzTxKeyDevice: %v", err)
	}

	want := fmt.Sprintf("subghz tx %s %d %d %d -d %d", key, freq, te, repeat, device)
	found := false
	for _, l := range m.Lines() {
		if strings.TrimSpace(l) == want {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected wire command %q; lines=%v", want, m.Lines())
	}
}

// TestSubGHzTxKeyDevice_Device0 verifies device=0 also works (internal CC1101).
func TestSubGHzTxKeyDevice_Device0(t *testing.T) {
	m := mock.Spawn(t,
		mock.WithHandler("subghz", func(args []string) string { return "" }),
	)
	flip := connectAndDetect(t, m)

	_, err := flip.SubGHzTxKeyDevice("FF00FF00", 315000000, 300, 2, 0)
	if err != nil {
		t.Fatalf("SubGHzTxKeyDevice(device=0): %v", err)
	}

	want := "subghz tx FF00FF00 315000000 300 2 -d 0"
	found := false
	for _, l := range m.Lines() {
		if strings.TrimSpace(l) == want {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected %q; lines=%v", want, m.Lines())
	}
}

// TestSubGHzChatDevice_WireCommand verifies that SubGHzChatDevice emits
// `subghz chat <freq> -d <device>`. Uses a suppressed prompt to simulate
// the long-running streaming behaviour; the short budget fires the timeout.
func TestSubGHzChatDevice_WireCommand(t *testing.T) {
	const freq = uint32(433920000)
	const device = 1

	m := mock.Spawn(t,
		mock.WithSuppressPrompt("subghz"),
		mock.WithHandler("subghz", func(args []string) string {
			return "Chat joined"
		}),
	)
	flip := connectAndDetect(t, m)

	_, _ = flip.SubGHzChatDevice(freq, 200*time.Millisecond, device)

	want := fmt.Sprintf("subghz chat %d -d %d", freq, device)
	rx := string(m.BytesReceived())
	if !strings.Contains(rx, want) {
		t.Errorf("expected bytes to contain %q; bytes=%q", want, rx)
	}
}

// ─── Crypto enclave ───────────────────────────────────────────────────────────

// TestCryptoEncrypt_WireCommand verifies `crypto encrypt <slot> <hex-data>`.
// slot is a decimal-integer string in 1-100 (matches firmware crypto_cli).
func TestCryptoEncrypt_WireCommand(t *testing.T) {
	const slot = "5"
	const data = "DEADBEEF01020304"

	m := mock.Spawn(t,
		mock.WithHandler("crypto", func(args []string) string {
			if len(args) >= 3 && args[0] == "encrypt" {
				return "encrypted: AABBCCDD"
			}
			return ""
		}),
	)
	flip := connectAndDetect(t, m)

	out, err := flip.CryptoEncrypt(slot, data)
	if err != nil {
		t.Fatalf("CryptoEncrypt: %v", err)
	}
	if !strings.Contains(out, "encrypted") {
		t.Errorf("expected encrypted output; got %q", out)
	}

	want := fmt.Sprintf("crypto encrypt %s %s", slot, data)
	found := false
	for _, l := range m.Lines() {
		if strings.TrimSpace(l) == want {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected %q; lines=%v", want, m.Lines())
	}
}

// TestCryptoDecrypt_WireCommand verifies `crypto decrypt <slot> <hex-data>`.
// slot is a decimal-integer string in 1-100 (matches firmware crypto_cli).
func TestCryptoDecrypt_WireCommand(t *testing.T) {
	const slot = "7"
	const cipher = "AABBCCDD"

	m := mock.Spawn(t,
		mock.WithHandler("crypto", func(args []string) string {
			if len(args) >= 3 && args[0] == "decrypt" {
				return "decrypted: DEADBEEF01020304"
			}
			return ""
		}),
	)
	flip := connectAndDetect(t, m)

	out, err := flip.CryptoDecrypt(slot, cipher)
	if err != nil {
		t.Fatalf("CryptoDecrypt: %v", err)
	}
	if !strings.Contains(out, "decrypted") {
		t.Errorf("expected decrypted output; got %q", out)
	}

	want := fmt.Sprintf("crypto decrypt %s %s", slot, cipher)
	found := false
	for _, l := range m.Lines() {
		if strings.TrimSpace(l) == want {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected %q; lines=%v", want, m.Lines())
	}
}

// TestCryptoHasKey_WireCommand verifies `crypto has_key <slot>`.
// slot is a decimal-integer string in 1-100 (matches firmware crypto_cli).
func TestCryptoHasKey_WireCommand(t *testing.T) {
	const slot = "10"

	m := mock.Spawn(t,
		mock.WithHandler("crypto", func(args []string) string {
			if len(args) >= 2 && args[0] == "has_key" && args[1] == slot {
				return "Key present"
			}
			return ""
		}),
	)
	flip := connectAndDetect(t, m)

	out, err := flip.CryptoHasKey(slot)
	if err != nil {
		t.Fatalf("CryptoHasKey: %v", err)
	}
	if !strings.Contains(out, "Key present") {
		t.Errorf("expected 'Key present' in output; got %q", out)
	}

	want := fmt.Sprintf("crypto has_key %s", slot)
	found := false
	for _, l := range m.Lines() {
		if strings.TrimSpace(l) == want {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected %q; lines=%v", want, m.Lines())
	}
}

// ─── GUI screen stream (RPC) ──────────────────────────────────────────────────

// TestGuiScreenStream_RPCNotBoundOnMock verifies that GuiScreenStream returns
// a descriptive error on a USB/mock transport (bleClient == nil). The web UI
// mirror owns the screen-stream lifecycle on USB.
func TestGuiScreenStream_RPCNotBoundOnMock(t *testing.T) {
	m := mock.Spawn(t)
	flip := connectAndDetect(t, m)

	_, err := flip.GuiScreenStream(500 * time.Millisecond)
	if err == nil {
		t.Fatal("GuiScreenStream should return an error on non-BLE (mock) transport")
	}
	if !strings.Contains(err.Error(), "screen stream RPC not bound") {
		t.Errorf("error should mention 'screen stream RPC not bound'; got: %v", err)
	}
	if !strings.Contains(err.Error(), "web UI mirror") {
		t.Errorf("error should mention 'web UI mirror'; got: %v", err)
	}
}

// ─── Date / RTC ──────────────────────────────────────────────────────────────

// TestDateGet_WireCommand verifies that DateGet emits the bare `date` verb.
func TestDateGet_WireCommand(t *testing.T) {
	m := mock.Spawn(t,
		mock.WithHandler("date", func(args []string) string {
			return "2025-04-29 12:00:00 2"
		}),
	)
	flip := connectAndDetect(t, m)

	out, err := flip.DateGet()
	if err != nil {
		t.Fatalf("DateGet: %v", err)
	}
	if !strings.Contains(out, "2025") {
		t.Errorf("expected date output; got %q", out)
	}

	found := false
	for _, l := range m.Lines() {
		if strings.TrimSpace(l) == "date" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected bare 'date' command; lines=%v", m.Lines())
	}
}

// TestDateSet_WireCommand verifies that DateSet formats the CLI command
// as `date YYYY-MM-DD HH:MM:SS WD` using UTC time and ISO-8601 weekday.
func TestDateSet_WireCommand(t *testing.T) {
	// 2025-04-29 12:00:00 UTC = Tuesday = weekday 2 (ISO 8601: Mon=1)
	// Go: time.Tuesday = 2, which equals ISO 8601 Tuesday = 2. No adjustment needed.
	unix := int64(1745928000) // 2025-04-29 12:00:00 UTC

	tt := time.Unix(unix, 0).UTC()
	wd := int(tt.Weekday())
	if wd == 0 {
		wd = 7
	}
	wantCmd := fmt.Sprintf("date %s %d", tt.Format("2006-01-02 15:04:05"), wd)

	m := mock.Spawn(t,
		mock.WithHandler("date", func(args []string) string { return "" }),
	)
	flip := connectAndDetect(t, m)

	_, err := flip.DateSet(unix)
	if err != nil {
		t.Fatalf("DateSet: %v", err)
	}

	found := false
	for _, l := range m.Lines() {
		if strings.TrimSpace(l) == wantCmd {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected %q; lines=%v", wantCmd, m.Lines())
	}
}

// TestDateSet_SundayWeekday7 verifies that a Unix timestamp falling on a
// Sunday is formatted with weekday=7 (ISO 8601), not 0 (Go's time.Sunday).
func TestDateSet_SundayWeekday7(t *testing.T) {
	// 2025-04-27 00:00:00 UTC = Sunday
	unix := int64(1745712000)

	tt := time.Unix(unix, 0).UTC()
	if tt.Weekday() != time.Sunday {
		t.Fatalf("fixture is not a Sunday: %s", tt.Weekday())
	}

	m := mock.Spawn(t,
		mock.WithHandler("date", func(args []string) string { return "" }),
	)
	flip := connectAndDetect(t, m)

	_, err := flip.DateSet(unix)
	if err != nil {
		t.Fatalf("DateSet (Sunday): %v", err)
	}

	wantCmd := fmt.Sprintf("date %s 7", tt.Format("2006-01-02 15:04:05"))
	found := false
	for _, l := range m.Lines() {
		if strings.TrimSpace(l) == wantCmd {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Sunday should map to WD=7; expected %q; lines=%v", wantCmd, m.Lines())
	}
}

// ─── Storage extras ───────────────────────────────────────────────────────────

// TestStorageExtract_WireCommand verifies `storage extract <archive> <outdir>`.
func TestStorageExtract_WireCommand(t *testing.T) {
	const archive = "/ext/backup.tar"
	const outdir = "/ext/restored"

	m := mock.Spawn(t,
		mock.WithHandler("storage", func(args []string) string {
			if len(args) >= 3 && args[0] == "extract" {
				return ""
			}
			return ""
		}),
	)
	flip := connectAndDetect(t, m)

	_, err := flip.StorageExtract(archive, outdir)
	if err != nil {
		t.Fatalf("StorageExtract: %v", err)
	}

	want := fmt.Sprintf("storage extract %s %s", archive, outdir)
	found := false
	for _, l := range m.Lines() {
		if strings.TrimSpace(l) == want {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected %q; lines=%v", want, m.Lines())
	}
}

// TestStorageFormat_WireCommand verifies `storage format /ext` is the exact
// wire command (path is hardcoded in the wrapper).
func TestStorageFormat_WireCommand(t *testing.T) {
	m := mock.Spawn(t,
		mock.WithHandler("storage", func(args []string) string {
			if len(args) >= 2 && args[0] == "format" && args[1] == "/ext" {
				return "SD card formatted"
			}
			return ""
		}),
	)
	flip := connectAndDetect(t, m)

	out, err := flip.StorageFormat()
	if err != nil {
		t.Fatalf("StorageFormat: %v", err)
	}
	if !strings.Contains(out, "formatted") {
		t.Errorf("expected formatted output; got %q", out)
	}

	found := false
	for _, l := range m.Lines() {
		if strings.TrimSpace(l) == "storage format /ext" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'storage format /ext'; lines=%v", m.Lines())
	}
}

// ─── Destructive / recovery operations ───────────────────────────────────────

// TestFactoryReset_WireCommand verifies the bare `factory_reset` verb is sent.
func TestFactoryReset_WireCommand(t *testing.T) {
	m := mock.Spawn(t,
		mock.WithHandler("factory_reset", func(args []string) string {
			return "Factory reset scheduled"
		}),
	)
	flip := connectAndDetect(t, m)

	out, err := flip.FactoryReset()
	if err != nil {
		t.Fatalf("FactoryReset: %v", err)
	}
	if !strings.Contains(out, "scheduled") {
		t.Errorf("expected reset-scheduled output; got %q", out)
	}

	found := false
	for _, l := range m.Lines() {
		if strings.TrimSpace(l) == "factory_reset" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'factory_reset'; lines=%v", m.Lines())
	}
}

// TestBackupCreate_WireCommand verifies `update backup <path>`.
func TestBackupCreate_WireCommand(t *testing.T) {
	const path = "/ext/backup.tar"

	m := mock.Spawn(t,
		mock.WithHandler("update", func(args []string) string {
			if len(args) >= 2 && args[0] == "backup" {
				return "Backup complete"
			}
			return ""
		}),
	)
	flip := connectAndDetect(t, m)

	out, err := flip.BackupCreate(path)
	if err != nil {
		t.Fatalf("BackupCreate: %v", err)
	}
	if !strings.Contains(out, "Backup complete") {
		t.Errorf("expected backup output; got %q", out)
	}

	want := fmt.Sprintf("update backup %s", path)
	found := false
	for _, l := range m.Lines() {
		if strings.TrimSpace(l) == want {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected %q; lines=%v", want, m.Lines())
	}
}

// TestBackupRestore_WireCommand verifies `update restore <path>`.
func TestBackupRestore_WireCommand(t *testing.T) {
	const path = "/ext/backup.tar"

	m := mock.Spawn(t,
		mock.WithHandler("update", func(args []string) string {
			if len(args) >= 2 && args[0] == "restore" {
				return "Restore complete"
			}
			return ""
		}),
	)
	flip := connectAndDetect(t, m)

	out, err := flip.BackupRestore(path)
	if err != nil {
		t.Fatalf("BackupRestore: %v", err)
	}
	if !strings.Contains(out, "Restore complete") {
		t.Errorf("expected restore output; got %q", out)
	}

	want := fmt.Sprintf("update restore %s", path)
	found := false
	for _, l := range m.Lines() {
		if strings.TrimSpace(l) == want {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected %q; lines=%v", want, m.Lines())
	}
}

// ─── Power control ────────────────────────────────────────────────────────────

// TestPowerOff_WireCommand verifies the bare `power off` verb is sent.
func TestPowerOff_WireCommand(t *testing.T) {
	m := mock.Spawn(t,
		mock.WithHandler("power", func(args []string) string {
			if len(args) >= 1 && args[0] == "off" {
				return ""
			}
			return ""
		}),
	)
	flip := connectAndDetect(t, m)

	_, err := flip.PowerOff()
	if err != nil {
		t.Fatalf("PowerOff: %v", err)
	}

	found := false
	for _, l := range m.Lines() {
		if strings.TrimSpace(l) == "power off" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'power off'; lines=%v", m.Lines())
	}
}

// TestPower5V_EnableDisable verifies `power 5v 1` and `power 5v 0`.
func TestPower5V_EnableDisable(t *testing.T) {
	for _, tc := range []struct {
		enable bool
		want   string
	}{
		{true, "power 5v 1"},
		{false, "power 5v 0"},
	} {
		m := mock.Spawn(t,
			mock.WithHandler("power", func(args []string) string { return "" }),
		)
		flip := connectAndDetect(t, m)

		_, err := flip.Power5V(tc.enable)
		if err != nil {
			t.Fatalf("Power5V(%v): %v", tc.enable, err)
		}

		found := false
		for _, l := range m.Lines() {
			if strings.TrimSpace(l) == tc.want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Power5V(%v): expected %q; lines=%v", tc.enable, tc.want, m.Lines())
		}
	}
}

// TestPower3V3_EnableDisable verifies `power 3v3 1` and `power 3v3 0`.
func TestPower3V3_EnableDisable(t *testing.T) {
	for _, tc := range []struct {
		enable bool
		want   string
	}{
		{true, "power 3v3 1"},
		{false, "power 3v3 0"},
	} {
		m := mock.Spawn(t,
			mock.WithHandler("power", func(args []string) string { return "" }),
		)
		flip := connectAndDetect(t, m)

		_, err := flip.Power3V3(tc.enable)
		if err != nil {
			t.Fatalf("Power3V3(%v): %v", tc.enable, err)
		}

		found := false
		for _, l := range m.Lines() {
			if strings.TrimSpace(l) == tc.want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Power3V3(%v): expected %q; lines=%v", tc.enable, tc.want, m.Lines())
		}
	}
}
