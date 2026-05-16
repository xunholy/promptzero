//go:build linux

package flipper_test

import (
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/flipper"
	"github.com/xunholy/promptzero/internal/flipper/mock"
)

// commands_wire_test.go — happy-path wire-form coverage for the
// simple `f.Exec(...)` wrappers in commands.go. Mirrors the
// internal/marauder/commands_test.go table-driven pattern so a
// regression where someone renames "subghz tx_from_file" → "subghz
// tx_file" is caught at unit-test time rather than the next time
// the operator plugs in a real Flipper. The mock-pty fake's
// Connect → DetectCapabilities flow runs before the test invokes
// the wrapper, so the helper records line counts pre/post and
// asserts on the slice the wrapper added.
//
// Wrappers excluded from the table:
//
//   - Anything that goes through f.dispatch() or f.ExecLong (RPC/CLI
//     dual-path; tested in dedicated suites).
//   - Capability-gated wrappers that emit a different command on
//     different forks (SubGHzTxKey, SubGHzReceive, etc.) — these
//     have bespoke fork-aware tests in commands_v016_test.go and
//     commands_mock_test.go.
//   - Validation-bearing wrappers whose error path is the contract
//     under test.

// flipperWireCmd connects a fresh Flipper to the mock, runs the
// detect-capabilities preamble, snapshots the wire-line count, then
// invokes fn and returns the FIRST new line the mock observed.
// Callers assert on that line. Errors from fn are returned alongside
// so tests for invalid-input paths (where the wrapper returns
// without writing) can branch on the error.
func flipperWireCmd(t *testing.T, fn func(*flipper.Flipper) (string, error)) (string, error) {
	t.Helper()
	m := mock.Spawn(t)
	flip := connectAndDetect(t, m)

	before := len(m.Lines())
	_, err := fn(flip)
	after := m.Lines()

	if len(after) <= before {
		// No line was written. Could be intentional (validation
		// error returned without dispatch) — surface that to the
		// caller via the err return.
		return "", err
	}
	return strings.TrimSpace(after[before]), err
}

// flipperWireCommandCases is the table of simple-wrapper fixtures.
// Keep the want strings exactly equal to what the firmware expects;
// any whitespace mismatch is a bug, not a test artifact.
type flipperWireCommandCase struct {
	name string
	want string
	fn   func(*flipper.Flipper) (string, error)
}

func flipperWireCommandCases() []flipperWireCommandCase {
	return []flipperWireCommandCase{
		// --- Sub-GHz ---
		{"SubGHzTx", "subghz tx_from_file /ext/subghz/garage.sub", func(f *flipper.Flipper) (string, error) {
			return f.SubGHzTx("/ext/subghz/garage.sub")
		}},
		{"SubGHzDecode", "subghz decode_raw /ext/subghz/raw.sub", func(f *flipper.Flipper) (string, error) {
			return f.SubGHzDecode("/ext/subghz/raw.sub")
		}},

		// --- Infrared ---
		{"IRTxParsed", "ir tx NEC 00 04 70 00 00 00", func(f *flipper.Flipper) (string, error) {
			return f.IRTxParsed("NEC", "00 04", "70 00 00 00")
		}},
		{"IRTxRaw", "ir tx RAW F:38000 DC:0.33 9000 4500 560", func(f *flipper.Flipper) (string, error) {
			return f.IRTxRaw(38000, 0.33, "9000 4500 560")
		}},
		{"IRUniversal", "ir universal tvs Power", func(f *flipper.Flipper) (string, error) {
			return f.IRUniversal("tvs", "Power")
		}},
		{"IRDecodeFile", "ir decode /ext/infrared/test.ir", func(f *flipper.Flipper) (string, error) {
			return f.IRDecodeFile("/ext/infrared/test.ir")
		}},
		{"IRUniversalList", "ir universal list assets/infrared/assets/tvs.ir", func(f *flipper.Flipper) (string, error) {
			return f.IRUniversalList("assets/infrared/assets/tvs.ir")
		}},

		// --- LEDs ---
		{"LED_red_full", "led r 255", func(f *flipper.Flipper) (string, error) {
			return f.LED("r", 255)
		}},
		{"LED_blue_off", "led b 0", func(f *flipper.Flipper) (string, error) {
			return f.LED("b", 0)
		}},

		// --- RFID ---
		{"RFIDRawAnalyze", "rfid raw_analyze /ext/lfrfid/test.rfid", func(f *flipper.Flipper) (string, error) {
			return f.RFIDRawAnalyze("/ext/lfrfid/test.rfid")
		}},

		// --- Crypto ---
		// Wire form pins the 4-arg shape — use valid keyType/keySize/hex so
		// the pre-transport validator in CryptoStoreKey doesn't short-circuit
		// before the wire dispatch runs. 32-char hex = 128-bit key.
		{"CryptoStoreKey", "crypto store_key 1 simple 128 DEADBEEFDEADBEEFDEADBEEFDEADBEEF", func(f *flipper.Flipper) (string, error) {
			return f.CryptoStoreKey(1, "simple", 128, "DEADBEEFDEADBEEFDEADBEEFDEADBEEF")
		}},

		// --- Bluetooth ---
		{"BTHCIInfo", "bt hci_info", func(f *flipper.Flipper) (string, error) {
			return f.BTHCIInfo()
		}},
	}
}

// TestCommandsWireForm pins the wire form of every simple
// flipper/commands.go wrapper. Mirrors
// internal/marauder/commands_test.go; the failure mode that
// motivated this is a silent firmware regression where a renamed
// command token returns no error and no output — the test catches
// the rename here rather than two debug sessions later.
func TestCommandsWireForm(t *testing.T) {
	for _, tc := range flipperWireCommandCases() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := flipperWireCmd(t, tc.fn)
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			if got != tc.want {
				t.Errorf("wire = %q, want %q", got, tc.want)
			}
		})
	}
}
