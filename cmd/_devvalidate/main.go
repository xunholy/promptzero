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
