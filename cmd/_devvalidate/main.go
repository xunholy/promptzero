// Command _devvalidate is a read-only, LLM-free validation harness for a
// physically-connected Flipper Zero. The leading underscore in the
// directory name makes the Go toolchain skip it for `go build ./...`,
// `go test ./...` and lint — it never affects CI — but it can be run
// directly against a live device:
//
//	go run ./cmd/_devvalidate -port /dev/ttyACM0
//
// It drives the production internal/flipper transport through a battery
// of safe, read-only commands and cross-checks each parser against the
// real device output, surfacing any mismatch between what the code
// expects and what the firmware actually returns. No writes, no TX, no
// emulation — purely identity, capability and storage reads.
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
	name   string
	level  string // PASS / WARN / FAIL
	detail string
}

func main() {
	port := flag.String("port", "/dev/ttyACM0", "Flipper serial port")
	baud := flag.Int("baud", 230400, "serial baud rate")
	timeout := flag.Duration("timeout", 15*time.Second, "connect timeout")
	deep := flag.Bool("deep", false, "include passive-radio checks (NFC detect + Sub-GHz RX)")
	capsCheck := flag.Bool("caps", false, "truth-check detected capabilities against the device's `help` command list")
	flag.Parse()

	url := fmt.Sprintf("serial://%s?baud=%d", *port, *baud)
	fmt.Printf("== PromptZero device validation ==\nconnecting: %s\n\n", url)

	ctx, cancel := context.WithTimeout(context.Background(), *timeout+10*time.Second)
	defer cancel()

	f, report, err := flipper.ConnectURL(ctx, url, *timeout)
	if err != nil {
		fmt.Printf("FATAL: connect failed: %v\n", err)
		if report != nil {
			fmt.Println("\nconnection report:")
			fmt.Println(report.Summary())
		}
		os.Exit(1)
	}
	defer func() { _ = f.Close() }()

	if report != nil {
		fmt.Println("connection report:")
		fmt.Println(report.Summary())
		fmt.Println()
	}

	var results []result
	add := func(name, level, detail string) {
		results = append(results, result{name, level, detail})
		fmt.Printf("[%-4s] %-22s %s\n", level, name, detail)
	}

	// --- Capabilities / fork detection ---------------------------------
	caps, err := f.DetectCapabilities()
	if err != nil {
		add("detect_capabilities", "FAIL", err.Error())
	} else {
		add("detect_capabilities", "PASS", fmt.Sprintf("fork=%s band=%s api=%d.%d hw_ver=%d",
			caps.FriendlyFork(), caps.FirmwareBand, caps.FirmwareAPIMajor, caps.FirmwareAPIMinor, caps.HardwareVer))
	}

	// --- device_info key/value map -------------------------------------
	dim, err := f.DeviceInfoMap()
	switch {
	case err != nil:
		add("device_info_map", "FAIL", err.Error())
	case len(dim) == 0:
		add("device_info_map", "FAIL", "empty map — parser extracted no key/value pairs")
	default:
		want := []string{"hardware_name", "firmware_version", "hardware_ver"}
		var missing []string
		for _, k := range want {
			if _, ok := dim[k]; !ok {
				missing = append(missing, k)
			}
		}
		if len(missing) > 0 {
			add("device_info_map", "WARN", fmt.Sprintf("%d keys; missing expected: %s",
				len(dim), strings.Join(missing, ",")))
		} else {
			add("device_info_map", "PASS", fmt.Sprintf("%d keys; name=%q fw=%q",
				len(dim), dim["hardware_name"], dim["firmware_version"]))
		}
	}

	// --- power info map -------------------------------------------------
	pim, err := f.PowerInfoMap()
	switch {
	case err != nil:
		add("power_info_map", "FAIL", err.Error())
	case len(pim) == 0:
		add("power_info_map", "WARN", "empty map (some forks gate `info power`)")
	default:
		add("power_info_map", "PASS", fmt.Sprintf("%d keys; charge=%q volt=%q",
			len(pim), pim["charge_level"], pim["battery_voltage"]))
	}

	// --- loader app list ------------------------------------------------
	apps, err := f.LoaderListParsed()
	if err != nil {
		add("loader_list_parsed", "FAIL", err.Error())
	} else {
		add("loader_list_parsed", "PASS", fmt.Sprintf("%+v", apps))
	}

	// --- storage list /ext ---------------------------------------------
	sl, err := f.StorageList("/ext")
	switch {
	case err != nil:
		add("storage_list /ext", "FAIL", err.Error())
	case strings.TrimSpace(sl) == "":
		add("storage_list /ext", "WARN", "empty listing (no SD card?)")
	default:
		n := strings.Count(sl, "\n")
		add("storage_list /ext", "PASS", fmt.Sprintf("%d lines", n+1))
	}

	// --- storage stat /ext ---------------------------------------------
	st, err := f.StorageStat("/ext")
	if err != nil {
		add("storage_stat /ext", "WARN", err.Error())
	} else {
		add("storage_stat /ext", "PASS", strings.TrimSpace(firstLine(st)))
	}

	// --- raw read-only commands ----------------------------------------
	for _, cmd := range []string{"uptime", "free", "date"} {
		out, err := f.Exec(cmd)
		if err != nil {
			add(cmd, "WARN", err.Error())
		} else {
			add(cmd, "PASS", strings.TrimSpace(firstLine(out)))
		}
	}

	// --- loader info ----------------------------------------------------
	if li, err := f.LoaderInfo(); err != nil {
		add("loader_info", "WARN", err.Error())
	} else {
		add("loader_info", "PASS", strings.TrimSpace(firstLine(li)))
	}

	if !*deep {
		fmt.Println("\n(skipping passive-radio checks; pass -deep to include NFC detect + Sub-GHz RX)")
	} else {
		// --- passive NFC detect (no card expected) ----------------------
		// Receive-only: validates the NFCDetect parser path. With no card
		// present it returns a clean "no card" after the timeout.
		if out, err := f.NFCDetect(3 * time.Second); err != nil {
			add("nfc_detect (passive)", "WARN", err.Error())
		} else {
			add("nfc_detect (passive)", "PASS", summarize(out))
		}

		// --- passive Sub-GHz RX on 433.92 MHz ---------------------------
		// Receive-only sniff; validates SubGHzReceive parsing against real
		// device output. No transmit.
		if out, err := f.SubGHzRx(433920000, 3*time.Second); err != nil {
			add("subghz_rx 433.92 (passive)", "WARN", err.Error())
		} else {
			add("subghz_rx 433.92 (passive)", "PASS", summarize(out))
		}
	}

	// --- capability-detection truth-check -------------------------------
	// Cross-check what detectCapabilities() concluded against how the real
	// firmware actually behaves, using `help` (the device's authoritative
	// command list) as ground truth. A mismatch is a genuine detection bug.
	if *capsCheck {
		help, herr := f.Exec("help")
		if herr != nil || strings.TrimSpace(help) == "" {
			help, _ = f.Exec("?")
		}
		// `help` is a space-padded multi-column grid (≈3 commands/row), so
		// match the command in ANY column, not just the first token.
		hasCmd := func(name string) bool {
			for _, tok := range strings.Fields(help) {
				if tok == name {
					return true
				}
			}
			return false
		}
		type capCheck struct {
			flag    string
			claimed bool
			cmd     string
		}
		for _, c := range []capCheck{
			{"HasPsCmd", caps.HasPsCmd, "ps"},
			{"HasClearCmd", caps.HasClearCmd, "clear"},
			{"HasNFCSubshell", caps.HasNFCSubshell, "nfc"},
		} {
			actual := hasCmd(c.cmd)
			if actual == c.claimed {
				add("cap:"+c.flag, "PASS", fmt.Sprintf("claimed=%v · help has %q=%v", c.claimed, c.cmd, actual))
			} else {
				add("cap:"+c.flag, "FAIL", fmt.Sprintf("MISMATCH claimed=%v but help has %q=%v", c.claimed, c.cmd, actual))
			}
		}

		// Subcommand-gated flags: a bare parent invocation prints a usage
		// block enumerating its real subcommands — the device's own ground
		// truth for which verbs exist. hasSub reports whole-word presence.
		usage := map[string]string{}
		for _, parent := range []string{"subghz", "storage"} {
			out, _ := f.Exec(parent)
			usage[parent] = out
		}
		hasSub := func(parent, verb string) bool {
			for _, tok := range strings.Fields(usage[parent]) {
				if tok == verb {
					return true
				}
			}
			return false
		}
		type subCheck struct {
			flag    string
			claimed bool
			parent  string
			verb    string
		}
		for _, c := range []subCheck{
			{"HasSubGHzChat", caps.HasSubGHzChat, "subghz", "chat"},
			{"HasSubGHzEncryptKeeloq", caps.HasSubGHzEncryptKeeloq, "subghz", "encrypt_keeloq"},
			{"HasStorageFormatExt", caps.HasStorageFormatExt, "storage", "format_ext"},
		} {
			actual := hasSub(c.parent, c.verb)
			if actual == c.claimed {
				add("cap:"+c.flag, "PASS", fmt.Sprintf("claimed=%v · %s usage has %q=%v", c.claimed, c.parent, c.verb, actual))
			} else {
				add("cap:"+c.flag, "FAIL", fmt.Sprintf("MISMATCH claimed=%v but %s usage has %q=%v", c.claimed, c.parent, c.verb, actual))
			}
		}

		fmt.Printf("\ndetected capabilities:\n%s\n", dumpCaps(caps))
	}

	// --- summary --------------------------------------------------------
	var pass, warn, fail int
	for _, r := range results {
		switch r.level {
		case "PASS":
			pass++
		case "WARN":
			warn++
		case "FAIL":
			fail++
		}
	}
	fmt.Printf("\n== summary: %d pass / %d warn / %d fail ==\n", pass, warn, fail)
	if fail > 0 {
		os.Exit(2)
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// dumpCaps renders the high-signal capability flags one per line.
func dumpCaps(c flipper.Capabilities) string {
	var b strings.Builder
	fmt.Fprintf(&b, "  fork=%s ver=%s commit=%s\n", c.FirmwareFork, c.FirmwareVersion, c.FirmwareCommit)
	fmt.Fprintf(&b, "  hardware=%s region=%s ver=%d uid=%s\n", c.HardwareName, c.HardwareRegion, c.HardwareVer, c.HardwareUID)
	fmt.Fprintf(&b, "  power_info_cmd=%q nfc_subshell=%v subghz_needs_dev=%v js=%q\n",
		c.PowerInfoCmd, c.HasNFCSubshell, c.SubGHzNeedsDev, c.JSEngineKind)
	fmt.Fprintf(&b, "  ps=%v clear=%v storage_format_ext=%v subghz_chat=%v subghz_encrypt_keeloq=%v\n",
		c.HasPsCmd, c.HasClearCmd, c.HasStorageFormatExt, c.HasSubGHzChat, c.HasSubGHzEncryptKeeloq)
	fmt.Fprintf(&b, "  FAPs: ble_spam=%v bruteforcer=%v mousejack=%v seader=%v picopass=%v nfcmagic=%v mfkey=%v nested=%v\n",
		c.HasBLESpam, c.HasSubGHzBruteforcer, c.HasMouseJackerFAP, c.HasSeaderFAP,
		c.HasPicopassFAP, c.HasNFCMagicFAP, c.HasMFKeyFAP, c.HasMifareNestedFAP)
	fmt.Fprintf(&b, "  ir_library=%q marauder=%v", c.UniversalIRLibraryName, c.MarauderDetected)
	return b.String()
}

// summarize collapses multi-line device output into a single compact line
// (line count + first non-empty line) for one-line check reporting.
func summarize(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "(empty response)"
	}
	lines := strings.Split(s, "\n")
	for _, ln := range lines {
		if t := strings.TrimSpace(ln); t != "" {
			return fmt.Sprintf("%d lines; %q", len(lines), t)
		}
	}
	return fmt.Sprintf("%d lines", len(lines))
}
