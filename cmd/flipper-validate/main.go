// flipper-validate is an integration harness that exercises Flipper wrapper
// methods against a live device over serial. It connects once and then runs
// each case with a wall-clock budget per case so a hang can't block the entire
// run. A case is PASS if the wrapper returns without error (even when the
// output is empty — "no signal / no tag present" is a legitimate RX result).
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

const (
	testDir     = "/ext/apps_data/flipper-validate"
	testHello   = testDir + "/hello.txt"
	testCopy    = testDir + "/hello-copy.txt"
	testRenamed = testDir + "/hello-renamed.txt"
	testSubFile = testDir + "/test.sub"
	testIrFile  = testDir + "/test.ir"
	testBadUSB  = testDir + "/test.badusb"
	testPortal  = testDir + "/index.html"
	testNFCFile = testDir + "/test.nfc"

	perCaseTimeout = 15 * time.Second
)

// Canned test file contents. We deliberately avoid calling the LLM-backed
// generators here — we need deterministic, fast, well-formed payloads that
// exercise the deploy / decode / TX wrappers.

const subPrincetonContent = `Filetype: Flipper SubGhz Key File
Version: 1
Frequency: 433920000
Preset: FuriHalSubGhzPresetOok650Async
Protocol: Princeton
Bit: 24
Key: 00 00 00 00 00 AB CD EF
TE: 400
Repeat: 5
`

const irNECContent = `Filetype: IR signals file
Version: 1
#
name: Test_NEC
type: parsed
protocol: NEC
address: 04 00 00 00
command: 08 00 00 00
`

const badUSBContent = `REM flipper-validate no-op payload
DELAY 10
`

const evilPortalContent = `<!DOCTYPE html>
<html><head><title>test</title></head>
<body><form action="/get" method="GET">
<input name="email" type="email"/>
<input name="password" type="password"/>
<button type="submit">login</button></form></body></html>
`

const nfcNTAGContent = `Filetype: Flipper NFC device
Version: 4
Device type: NTAG/Ultralight
UID: 04 AA BB CC DD EE FF
ATQA: 00 44
SAK: 00
Data format version: 2
NTAG/Ultralight type: NTAG213
Pages total: 4
Page 0: 04 AA BB 00
Page 1: CC DD EE FF
Page 2: 00 00 00 00
Page 3: E1 10 3E 00
`

type result struct {
	category string
	name     string
	status   string // PASS | FAIL | SKIP
	notes    string
}

var defaultDenyPatterns = []string{
	"Error:",
	"cannot be run while an application is open",
	"illegal option",
	"Unknown command",
	"not supported",
}

type tcase struct {
	category string
	name     string
	run      func(context.Context, *flipper.Flipper) (string, error)
	// allowEmpty: if true, an empty-but-no-error response is PASS.
	allowEmpty bool
	// skip: if non-empty, emit SKIP with this reason and don't run.
	skip string
	// rxTolerant: accept "no card detected" / timeout-like wrapper errors as
	// PASS, since they just mean no physical target was present.
	rxTolerant bool
	// reboot: this case intentionally disconnects the serial port. Don't run
	// cleanup after, and skip the deadline fail-over.
	reboot bool
	// denyOutputPatterns overrides defaultDenyPatterns for this case.
	denyOutputPatterns []string
	// allowOutputPatterns: if the output matches any pattern, deny scanning is
	// skipped entirely (for cases that intentionally exercise an error path).
	allowOutputPatterns []string
	// expectOutputPattern: if non-empty, output MUST contain this substring or
	// the case FAILs.
	expectOutputPattern string
}

func snippet(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\n", " | ")
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}

// isNoTargetErr heuristically classifies a wrapper error as "no physical
// target present" for RX-tolerant cases. A hung or broken wrapper returns a
// different shape (context deadline, transport error, subshell state).
func isNoTargetErr(err error, out string) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error()) + " " + strings.ToLower(out)
	needles := []string{
		"no card", "no tag", "no rfid", "no signal", "not detected",
		"timeout", "no response", "no data", "nothing",
		// Momentum NFC subshell: "Error: Protocol failure" / "Error:
		// Protocol error" on mfu rdbl / raw frames when no compatible
		// tag is present. Treat as no-target for rxTolerant cases.
		"protocol failure", "protocol error",
	}
	for _, n := range needles {
		if strings.Contains(msg, n) {
			return true
		}
	}
	return false
}

func main() {
	port := flag.String("port", "/dev/ttyACM0", "serial device path")
	baud := flag.Int("baud", 230400, "serial baud")
	skipReboot := flag.Bool("skip-reboot", false, "skip the admin · Reboot case (use while iterating — the reboot drops WSL USB passthrough and forces a replug)")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	url := fmt.Sprintf("serial://%s?baud=%d", *port, *baud)
	fmt.Printf("connecting %s ...\n", url)
	flip, err := flipper.ConnectURL(ctx, url, 15*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: ConnectURL: %v\n", err)
		os.Exit(2)
	}
	defer func() {
		if flip != nil {
			_ = flip.Close()
		}
	}()
	if _, err := flip.DetectCapabilities(); err != nil {
		fmt.Fprintf(os.Stderr, "WARN: DetectCapabilities: %v (continuing with defaults)\n", err)
	}
	caps := flip.Capabilities()
	fmt.Printf("connected: fork=%q version=%q power_info_cmd=%q nfc_subshell=%v subghz_dev=%v\n",
		caps.FirmwareFork, caps.FirmwareVersion, caps.PowerInfoCmd, caps.HasNFCSubshell, caps.SubGHzNeedsDev)

	cases := buildCases()
	if *skipReboot {
		for i := range cases {
			if cases[i].reboot {
				cases[i].skip = "SKIPPED — --skip-reboot flag set (avoid WSL USB re-enumeration during iteration)"
				cases[i].reboot = false
				cases[i].run = nil
			}
		}
	}

	// Pre-run cleanup: remove any leftover files from a previous interrupted run.
	fmt.Print("pre-run cleanup: ")
	if statOut, statErr := flip.StorageStat(testDir); statErr == nil && strings.Contains(statOut, "Directory") {
		removed := 0
		if listOut, listErr := flip.StorageList(testDir); listErr == nil {
			for _, line := range strings.Split(listOut, "\n") {
				parts := strings.Fields(line)
				var name string
				switch len(parts) {
				case 0:
					continue
				case 1:
					name = parts[0]
				default:
					// "[F] filename [size]" — filename is at index 1
					name = parts[1]
				}
				if name == "" {
					continue
				}
				if _, err := flip.StorageRemove(testDir + "/" + name); err == nil {
					removed++
				}
			}
		}
		_, _ = flip.StorageRemove(testDir)
		fmt.Printf("removed %d leftover files\n", removed)
	} else {
		fmt.Println("no leftovers")
	}

	results := make([]result, 0, len(cases))
	for _, c := range cases {
		r := result{category: c.category, name: c.name}

		if c.skip != "" {
			r.status = "SKIP"
			r.notes = c.skip
			fmt.Printf("  [%s] %s · %s — %s\n", r.status, r.category, r.name, r.notes)
			results = append(results, r)
			continue
		}

		caseCtx, caseCancel := context.WithTimeout(ctx, perCaseTimeout)
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

		select {
		case got := <-ch:
			elapsed := time.Since(start).Round(time.Millisecond)
			switch {
			case got.err != nil && c.rxTolerant && isNoTargetErr(got.err, got.out):
				r.status = "PASS"
				r.notes = fmt.Sprintf("[%s] (no target present — accepted) %s", elapsed, snippet(got.err.Error()))
			case got.err != nil:
				r.status = "FAIL"
				r.notes = fmt.Sprintf("[%s] err=%v; out=%s", elapsed, got.err, snippet(got.out))
			default:
				trimmed := strings.TrimSpace(got.out)

				// Allow patterns short-circuit deny scanning.
				allowed := false
				for _, pat := range c.allowOutputPatterns {
					if strings.Contains(got.out, pat) {
						allowed = true
						break
					}
				}

				denyMatch := ""
				if !allowed {
					denySet := c.denyOutputPatterns
					if len(denySet) == 0 {
						denySet = defaultDenyPatterns
					}
					for _, pat := range denySet {
						if strings.Contains(got.out, pat) {
							denyMatch = pat
							break
						}
					}
				}

				switch {
				case denyMatch != "":
					r.status = "FAIL"
					r.notes = fmt.Sprintf("[%s] deny-match: %s", elapsed, denyMatch)
				case strings.HasPrefix(trimmed, "Usage:"):
					r.status = "FAIL"
					r.notes = fmt.Sprintf("[%s] bare usage banner", elapsed)
				case c.expectOutputPattern != "" && !strings.Contains(got.out, c.expectOutputPattern):
					r.status = "FAIL"
					r.notes = fmt.Sprintf("[%s] expected substring not found: %q", elapsed, c.expectOutputPattern)
				case trimmed == "" && !c.allowEmpty:
					r.status = "FAIL"
					r.notes = fmt.Sprintf("[%s] empty output (expected non-empty)", elapsed)
				default:
					r.status = "PASS"
					if trimmed == "" {
						r.notes = fmt.Sprintf("[%s] (empty — accepted)", elapsed)
					} else {
						r.notes = fmt.Sprintf("[%s] %s", elapsed, snippet(got.out))
					}
				}
			}
		case <-caseCtx.Done():
			if c.reboot {
				// Expected — reboot case tears down serial.
				r.status = "PASS"
				r.notes = fmt.Sprintf("reboot dispatched (context closed after %v) — reconnect attempt follows", perCaseTimeout)
			} else {
				r.status = "FAIL"
				r.notes = fmt.Sprintf("case deadline exceeded after %v (ctx=%v)", perCaseTimeout, caseCtx.Err())
			}
		}
		caseCancel()
		fmt.Printf("  [%s] %s · %s — %s\n", r.status, r.category, r.name, r.notes)
		results = append(results, r)

		if c.reboot {
			// Close current session, try reconnect. If it comes back, update note.
			_ = flip.Close()
			flip = nil
			fmt.Println("  … reboot: waiting 5s before reconnect attempt")
			time.Sleep(5 * time.Second)
			reconnectCtx, rcCancel := context.WithTimeout(ctx, 30*time.Second)
			deadline := time.Now().Add(30 * time.Second)
			var reconnected *flipper.Flipper
			for time.Now().Before(deadline) {
				f2, err := flipper.ConnectURL(reconnectCtx, url, 5*time.Second)
				if err == nil {
					reconnected = f2
					break
				}
				fmt.Printf("  … reconnect attempt: %v\n", err)
				time.Sleep(2 * time.Second)
			}
			rcCancel()
			if reconnected != nil {
				flip = reconnected
				fmt.Println("  [PASS] admin · Reconnect — Flipper came back on serial")
				results = append(results, result{category: "admin", name: "Reconnect", status: "PASS", notes: "reconnected after reboot"})
			} else {
				fmt.Println("  [FAIL] admin · Reconnect — Flipper did NOT return within 30s; physical reconnect required")
				results = append(results, result{category: "admin", name: "Reconnect", status: "FAIL", notes: "Flipper offline after reboot"})
			}
		}
	}

	// Cleanup — ALWAYS runs. May fail if reboot+reconnect didn't restore the session.
	fmt.Println()
	fmt.Println("=== CLEANUP ===")
	if flip == nil {
		fmt.Println("cleanup: no active session — Flipper disconnected after reboot. Skipping SD cleanup.")
	} else {
		cleanup(flip)
		fmt.Println("cleanup complete")
	}

	// Summary.
	pass, fail, skip := 0, 0, 0
	fmt.Println()
	fmt.Println("=== SUMMARY ===")
	for _, r := range results {
		switch r.status {
		case "PASS":
			pass++
		case "FAIL":
			fail++
		case "SKIP":
			skip++
		}
	}
	fmt.Printf("pass=%d fail=%d skip=%d total=%d\n", pass, fail, skip, len(results))

	if fail > 0 {
		os.Exit(1)
	}
}

func cleanup(f *flipper.Flipper) {
	// Remove known test files individually — `storage remove` doesn't recurse.
	for _, p := range []string{
		testHello, testCopy, testRenamed, testSubFile, testIrFile,
		testBadUSB, testPortal, testNFCFile,
	} {
		if out, err := f.StorageRemove(p); err != nil {
			fmt.Printf("cleanup: remove %s: err=%v out=%s\n", p, err, snippet(out))
		}
	}
	if out, err := f.StorageRemove(testDir); err != nil {
		fmt.Printf("cleanup: remove dir %s: err=%v out=%s\n", testDir, err, snippet(out))
	}
	// Restore LED / backlight.
	_ = f.SetLED("r", 0)
	_ = f.SetLED("g", 0)
	_ = f.SetLED("b", 0)
	_ = f.SetLED("bl", 255)
}

func buildCases() []tcase {
	return []tcase{
		// ================================================================
		// Round 0 — prior validated baseline (device introspection + safe RX)
		// ================================================================
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
			return fmt.Sprintf("present=%s label=%q type=%q total=%q free=%q",
				m["present"], m["label"], m["type"], m["totalSpace"], m["freeSpace"]), nil
		}},

		// ================================================================
		// Round 1 — local effects only (safe)
		// ================================================================
		{category: "indicator", name: "LEDSet(r,64)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			if err := f.SetLED("r", 64); err != nil {
				return "", err
			}
			time.Sleep(200 * time.Millisecond)
			if err := f.SetLED("r", 0); err != nil {
				return "", err
			}
			return "led pulsed r=64 for 200ms", nil
		}},
		{category: "indicator", name: "Vibro(120ms)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			if _, err := f.Exec("vibro 1"); err != nil {
				return "", err
			}
			time.Sleep(120 * time.Millisecond)
			if _, err := f.Exec("vibro 0"); err != nil {
				return "", err
			}
			return "vibro pulsed 120ms", nil
		}},
		{category: "input", name: "InputSend(back,short)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			out, err := f.InputSend("back", "short")
			if err != nil {
				// Fall back to raw CLI per task note.
				return f.RawCLI("input send back 0")
			}
			return out, nil
		}, allowEmpty: true},

		// Storage CRUD lifecycle
		{category: "storage", name: "StorageMkdir(testDir)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			out, err := f.StorageMkdir(testDir)
			if err != nil && !strings.Contains(strings.ToLower(out+err.Error()), "exist") {
				return out, err
			}
			return out, nil
		}, allowEmpty: true},
		{category: "storage", name: "StorageWrite(hello.txt)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			if err := f.StorageWrite(testHello, "hello\n"); err != nil {
				return "", err
			}
			return "wrote 6 bytes", nil
		}},
		{category: "storage", name: "StorageRead(hello.txt)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			out, err := f.StorageRead(testHello)
			if err != nil {
				return out, err
			}
			if !strings.Contains(out, "hello") {
				return out, fmt.Errorf("expected 'hello' in output")
			}
			return out, nil
		}},
		{category: "storage", name: "StorageStat(hello.txt)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			return f.StorageStat(testHello)
		}},
		{category: "storage", name: "StorageMD5(hello.txt)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			return f.StorageMD5(testHello)
		}},
		{category: "storage", name: "StorageList(testDir)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			out, err := f.StorageList(testDir)
			if err != nil {
				return out, err
			}
			if !strings.Contains(out, "hello.txt") {
				return out, fmt.Errorf("expected hello.txt in listing")
			}
			return out, nil
		}},
		{category: "storage", name: "StorageTree(testDir)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			return f.StorageTree(testDir)
		}, allowEmpty: true},
		{category: "storage", name: "StorageCopy(hello→copy)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			return f.StorageCopy(testHello, testCopy)
		}, allowEmpty: true},
		{category: "storage", name: "StorageRename(copy→renamed)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			return f.StorageRename(testCopy, testRenamed)
		}, allowEmpty: true},

		// Generator-style deploys (canned payloads written via StorageWrite — no LLM)
		{category: "generate", name: "WriteTestSubGHz(Princeton)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			if err := f.StorageWrite(testSubFile, subPrincetonContent); err != nil {
				return "", err
			}
			return fmt.Sprintf("wrote %d bytes to %s", len(subPrincetonContent), testSubFile), nil
		}},
		{category: "generate", name: "WriteTestIR(NEC)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			if err := f.StorageWrite(testIrFile, irNECContent); err != nil {
				return "", err
			}
			return fmt.Sprintf("wrote %d bytes to %s", len(irNECContent), testIrFile), nil
		}},
		{category: "generate", name: "WriteTestBadUSB(noop)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			if err := f.StorageWrite(testBadUSB, badUSBContent); err != nil {
				return "", err
			}
			return fmt.Sprintf("wrote %d bytes to %s", len(badUSBContent), testBadUSB), nil
		}},
		{category: "generate", name: "WriteTestEvilPortal(html)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			if err := f.StorageWrite(testPortal, evilPortalContent); err != nil {
				return "", err
			}
			return fmt.Sprintf("wrote %d bytes to %s", len(evilPortalContent), testPortal), nil
		}},
		{category: "generate", name: "WriteTestNFC(NTAG)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			if err := f.StorageWrite(testNFCFile, nfcNTAGContent); err != nil {
				return "", err
			}
			return fmt.Sprintf("wrote %d bytes to %s", len(nfcNTAGContent), testNFCFile), nil
		}},

		// Local decode — no RF.
		{category: "subghz", name: "SubGHzDecode(testSubFile)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			return f.SubGHzDecode(testSubFile)
		}, allowEmpty: true},
		{category: "ir", name: "IRDecodeFile(testIrFile)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			return f.IRDecodeFile(testIrFile)
		}, allowEmpty: true},

		// Sanity re-run baseline
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
		{category: "system", name: "BTHCIInfo", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			return f.BTHCIInfo()
		}},

		// ================================================================
		// Round 2 — brief RF / passive reads
		// ================================================================
		{category: "nfc", name: "NFCAPDU(SELECT PPSE)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			return f.NFCAPDU("00A404000E325041592E5359532E444446303100", 4*time.Second)
		}, allowEmpty: true, rxTolerant: true},
		{category: "nfc", name: "NFCMFURead(0)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			return f.NFCMFURead(0, 4*time.Second)
		}, allowEmpty: true, rxTolerant: true},
		{category: "nfc", name: "NFCRawFrame(26)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			return f.NFCRawFrame("26", 4*time.Second)
		}, allowEmpty: true, rxTolerant: true},
		{category: "rfid", name: "RFIDRawRead(ask,2s)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			// Momentum's rfid raw_read REQUIRES a modulation arg (ask|psk);
			// empty mode returns the rfid usage banner.
			return f.RFIDRawRead("ask", testDir+"/raw.lfrfid", 2*time.Second)
		}, allowEmpty: true, rxTolerant: true},
		{category: "rfid", name: "RFIDRawAnalyze(raw.lfrfid)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			return f.RFIDRawAnalyze(testDir + "/raw.lfrfid")
		}, allowEmpty: true, rxTolerant: true},

		// ================================================================
		// Round 3 — TX + emulate (bounded, generated payloads)
		// ================================================================
		{category: "ir", name: "IRTxParsed(NEC,0x04,0x08)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			return f.IRTxParsed("NEC", "0x04", "0x08")
		}, allowEmpty: true},
		{category: "ir", name: "IRTxRaw(38k,0.33,100 200 300)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			return f.IRTxRaw(38000, 0.33, "100 200 300")
		}, allowEmpty: true},
		{category: "ir", name: "IRUniversal(tv,POWER)",
			skip: "SKIPPED — would target user's TV; not authorised to aim at specific appliances"},
		{category: "subghz", name: "SubGHzTx(testSubFile)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			return f.SubGHzTx(testSubFile)
		}, allowEmpty: true},
		{category: "subghz", name: "SubGHzTxKey(ABCDEF,433920000,200,1)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			return f.SubGHzTxKey("ABCDEF", 433920000, 200, 1)
		}, allowEmpty: true},
		{category: "nfc", name: "NFCEmulate(testNFCFile)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			// NFCEmulate wraps LoaderOpen + loader-close wait. The wrapper
			// handles the full open → settle → close → post-teardown wait
			// sequence; just call it directly and let the case deadline
			// (15s) bound total time.
			return f.NFCEmulate(testNFCFile)
		}, allowEmpty: true, rxTolerant: true},
		{category: "rfid", name: "RFIDEmulate(EM4100,deadbeef01,2s)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			return f.RFIDEmulate("EM4100", "DEADBEEF01", 2*time.Second)
		}, allowEmpty: true, rxTolerant: true},
		{category: "ibutton", name: "IButtonEmulate(Dallas,…,2s)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			return f.IButtonEmulate("Dallas", "0102030405060708", 2*time.Second)
		}, allowEmpty: true, rxTolerant: true},
		{category: "loader", name: "LoaderOpen(About)",
			skip: "SKIPPED — app launch freezes CLI until back-button; cannot dismiss programmatically without InputSend working in a live app context"},

		// ================================================================
		// Round 4 — admin
		// ================================================================
		{category: "crypto", name: "CryptoStoreKey(slot=10,simple,128)", run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			return f.CryptoStoreKey(10, "simple", 128, "AABBCCDDEEFF00112233445566778899")
		}, allowEmpty: true},

		// SKIPs — globally off-limits for this run
		{category: "admin", name: "UpdateInstall",
			skip: "SKIPPED — globally off-limits (firmware update is high-blast-radius; user policy)"},
		{category: "admin", name: "RebootDFU",
			skip: "SKIPPED — globally off-limits (puts device into DFU, physical recovery required)"},
		{category: "badusb", name: "BadUSBRun",
			skip: "SKIPPED — globally off-limits (keystrokes typed into host; not authorised)"},

		// Reboot LAST — expect serial drop, reconnect logic runs after.
		{category: "admin", name: "Reboot", reboot: true, run: func(ctx context.Context, f *flipper.Flipper) (string, error) {
			return f.Reboot()
		}, allowEmpty: true},
	}
}
