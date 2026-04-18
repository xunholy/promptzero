// flipper-validate is an integration harness that exercises the safe
// subset of Flipper wrapper methods against a live device over serial.
// It connects once and then runs each case with a 10s wall-clock budget
// per case so a hang can't block the entire run. A case is PASS if the
// wrapper returns without error (even when the output is empty — "no
// signal / no tag present" is a legitimate RX result).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/xunholy/promptzero/internal/flipper"
)

type result struct {
	category string
	name     string
	status   string // PASS | FAIL | SKIP
	notes    string
}

type tcase struct {
	category string
	name     string
	run      func(context.Context, *flipper.Flipper) (string, error)
	// allowEmpty: if true, an empty-but-no-error response is PASS.
	allowEmpty bool
}

func snippet(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\n", " | ")
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}

func main() {
	port := flag.String("port", "/dev/ttyACM0", "serial device path")
	baud := flag.Int("baud", 230400, "serial baud")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	url := fmt.Sprintf("serial://%s?baud=%d", *port, *baud)
	fmt.Printf("connecting %s ...\n", url)
	flip, err := flipper.ConnectURL(ctx, url, 15*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: ConnectURL: %v\n", err)
		os.Exit(2)
	}
	defer flip.Close()
	// ConnectURL performs the CLI handshake but does NOT auto-populate
	// capabilities — callers have to opt in, same as cmd/promptzero's
	// setup.go does. Without this call, Capabilities() returns defaults
	// and every fork-specific quirk (power verb, subghz <device> arg,
	// nfc subshell presence) silently mis-fires.
	if _, err := flip.DetectCapabilities(); err != nil {
		fmt.Fprintf(os.Stderr, "WARN: DetectCapabilities: %v (continuing with defaults)\n", err)
	}
	caps := flip.Capabilities()
	fmt.Printf("connected: fork=%q version=%q power_info_cmd=%q nfc_subshell=%v subghz_dev=%v\n",
		caps.FirmwareFork, caps.FirmwareVersion, caps.PowerInfoCmd, caps.HasNFCSubshell, caps.SubGHzNeedsDev)

	cases := []tcase{
		// --- Device introspection ---
		{category: "device", name: "DeviceInfo", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			return f.DeviceInfo()
		}},
		{category: "device", name: "PowerInfoMap", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			m, err := f.PowerInfoMap()
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("keys=%d charge_level=%q", len(m), m["charge_level"]), nil
		}},
		{category: "device", name: "StorageFSInfoMap(/ext)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			m, err := f.StorageFSInfoMap("/ext")
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("present=%s label=%q type=%q totalSpace=%q freeSpace=%q",
				m["present"], m["label"], m["type"], m["totalSpace"], m["freeSpace"]), nil
		}},
		{category: "device", name: "StorageFSInfoMap(/int)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			m, err := f.StorageFSInfoMap("/int")
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("present=%s label=%q type=%q totalSpace=%q",
				m["present"], m["label"], m["type"], m["totalSpace"]), nil
		}},

		// --- Storage read ---
		{category: "storage", name: "StorageList(/ext)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			return f.StorageList("/ext")
		}},
		{category: "storage", name: "StorageStat(/ext)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			return f.StorageStat("/ext")
		}},
		{category: "storage", name: "StorageStat(/ext/subghz)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			return f.StorageStat("/ext/subghz")
		}, allowEmpty: true},
		{category: "storage", name: "StorageTree(/ext/nfc)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			return f.StorageTree("/ext/nfc")
		}, allowEmpty: true},
		{category: "storage", name: "StorageMD5(manifest.txt)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			return f.StorageMD5("/ext/Momentum/dolphin/manifest.txt")
		}, allowEmpty: true},

		// --- GPIO read (single CLI Exec) ---
		{category: "gpio", name: "GPIORead(PA7)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			return f.GPIORead("PA7")
		}, allowEmpty: true},

		// --- I2C scan.
		// NB: the wrapper falls back to `loader open "I2C Scanner"` if the raw
		// CLI verb is unrecognised, which would freeze the device. We probe
		// raw CLI directly to avoid triggering the fallback.
		{category: "i2c", name: "RawCLI(i2c scan)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			out, err := f.RawCLI("i2c scan")
			low := strings.ToLower(out)
			if strings.Contains(low, "not a recognized") || strings.Contains(low, "unknown command") || strings.Contains(low, "command not found") {
				return out, fmt.Errorf("i2c scan not recognised by firmware (wrapper would fall back to loader app — flagged, not invoked)")
			}
			return out, err
		}, allowEmpty: true},

		// --- Loader inspection (NOT loader open — app launches freeze the CLI) ---
		{category: "loader", name: "LoaderListParsed", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			la, err := f.LoaderListParsed()
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("apps=%d settings=%d", len(la.Apps), len(la.Settings)), nil
		}},
		{category: "loader", name: "LoaderInfo", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			return f.LoaderInfo()
		}, allowEmpty: true},

		// --- System / BT (single-shot CLI) ---
		{category: "system", name: "BTHCIInfo", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			return f.BTHCIInfo()
		}},

		// --- RFID passive read. Uses StreamCtx internally and honours ctx —
		// unlike the ExecLong-based streaming wrappers below. ---
		{category: "rfid", name: "RFIDRead(auto,2s)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			out, err := f.RFIDRead(ctx, "", 2*time.Second)
			if err != nil && strings.Contains(err.Error(), "no RFID tag detected") {
				return out, nil // PASS — absence of tag is acceptable
			}
			return out, err
		}, allowEmpty: true},

		// ---------- HANG-PRONE SECTION ----------
		// The wrappers below use ExecLong for commands that require Ctrl+C to
		// abort on the firmware side (e.g. `ir rx`, `ikey read`, `onewire
		// search`, `log`, `subghz rx`, `nfc` subshell). ExecLong times out the
		// Go-side read but does NOT send Ctrl+C, so the Flipper stays in the
		// streaming mode and every subsequent command hangs until a physical
		// disconnect. We run these last so the fast cases are not poisoned,
		// and accept that a failure on one cascades to the rest.

		// --- SubGHz RX ---
		{category: "subghz", name: "SubGHzRx(433920000,2s)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			return f.SubGHzRx(433920000, 2*time.Second)
		}, allowEmpty: true},

		// --- LogStream (bounded) ---
		{category: "system", name: "LogStream(1s)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			return f.LogStream(1 * time.Second)
		}, allowEmpty: true},

		// --- IR RX ---
		{category: "ir", name: "IRRx(2s)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			return f.IRRx(2 * time.Second)
		}, allowEmpty: true},

		// --- 1-Wire passive enumeration ---
		{category: "onewire", name: "OneWireSearch(2s)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			return f.OneWireSearch(2 * time.Second)
		}, allowEmpty: true},

		// --- iButton passive read ---
		{category: "ibutton", name: "IButtonRead(2s)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			return f.IButtonRead(2 * time.Second)
		}, allowEmpty: true},

		// --- NFC detect (subshell). On Momentum the subshell prompt handshake
		// fails and can leave the device inside the subshell. ---
		{category: "nfc", name: "NFCDetect(2s)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			return f.NFCDetect(2 * time.Second)
		}, allowEmpty: true},
	}

	results := make([]result, 0, len(cases))
	for _, c := range cases {
		caseCtx, caseCancel := context.WithTimeout(ctx, 10*time.Second)
		type ret struct {
			out string
			err error
		}
		ch := make(chan ret, 1)
		start := time.Now()
		go func(c tcase) {
			out, err := c.run(caseCtx, flip)
			ch <- ret{out, err}
		}(c)
		var r result
		r.category = c.category
		r.name = c.name
		select {
		case got := <-ch:
			elapsed := time.Since(start).Round(time.Millisecond)
			if got.err != nil {
				r.status = "FAIL"
				r.notes = fmt.Sprintf("[%s] err=%v; out=%s", elapsed, got.err, snippet(got.out))
			} else {
				trimmed := strings.TrimSpace(got.out)
				if trimmed == "" && !c.allowEmpty {
					r.status = "FAIL"
					r.notes = fmt.Sprintf("[%s] empty output (expected non-empty)", elapsed)
				} else {
					r.status = "PASS"
					if trimmed == "" {
						r.notes = fmt.Sprintf("[%s] (empty — accepted)", elapsed)
					} else {
						r.notes = fmt.Sprintf("[%s] %s", elapsed, snippet(got.out))
					}
				}
			}
		case <-caseCtx.Done():
			r.status = "FAIL"
			r.notes = fmt.Sprintf("case deadline exceeded after 10s (ctx=%v)", caseCtx.Err())
		}
		caseCancel()
		fmt.Printf("  [%s] %s · %s — %s\n", r.status, r.category, r.name, r.notes)
		results = append(results, r)
	}

	// Summary.
	pass, fail := 0, 0
	fmt.Println()
	fmt.Println("=== SUMMARY ===")
	for _, r := range results {
		switch r.status {
		case "PASS":
			pass++
		case "FAIL":
			fail++
		}
	}
	fmt.Printf("pass=%d fail=%d total=%d\n", pass, fail, len(results))

	if fail > 0 {
		os.Exit(1)
	}
}
