// marauder-validate is an integration harness that exercises the safe
// read/RX/inspection subset of Marauder wrapper methods against a live
// ESP32 Marauder devboard over USB serial. Mirrors the shape of
// cmd/flipper-validate. TX / emulate / spam verbs are SKIPPED by safety
// policy — they require explicit target authorisation.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/xunholy/promptzero/internal/marauder"
)

const perCaseTimeout = 20 * time.Second

type result struct {
	category string
	name     string
	status   string // PASS | FAIL | SKIP
	notes    string
}

var defaultDenyPatterns = []string{
	"Invalid command",
	"unknown command",
}

type tcase struct {
	category            string
	name                string
	run                 func(context.Context, *marauder.Marauder) (string, error)
	allowEmpty          bool
	skip                string
	denyOutputPatterns  []string
	allowOutputPatterns []string
	expectOutputPattern string
}

func snippet(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\n", " | ")
	if len(s) > 180 {
		s = s[:180] + "…"
	}
	return s
}

func main() {
	port := flag.String("port", "/dev/ttyUSB0", "serial device path")
	baud := flag.Int("baud", 115200, "serial baud")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	fmt.Printf("connecting %s @%d ...\n", *port, *baud)
	m, err := marauder.Connect(*port, *baud)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: connect: %v\n", err)
		os.Exit(2)
	}
	defer m.Close()

	cases := buildCases()

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
			out, err := c.run(caseCtx, m)
			ch <- ret{out, err}
		}(c)

		select {
		case got := <-ch:
			elapsed := time.Since(start).Round(time.Millisecond)
			if got.err != nil {
				r.status = "FAIL"
				r.notes = fmt.Sprintf("[%s] err=%v; out=%s", elapsed, got.err, snippet(got.out))
			} else {
				trimmed := strings.TrimSpace(got.out)
				denied := ""
				if len(c.allowOutputPatterns) > 0 {
					skipDeny := false
					for _, p := range c.allowOutputPatterns {
						if strings.Contains(got.out, p) {
							skipDeny = true
							break
						}
					}
					if !skipDeny {
						denied = firstMatch(got.out, denyFor(c))
					}
				} else {
					denied = firstMatch(got.out, denyFor(c))
				}
				switch {
				case denied != "":
					r.status = "FAIL"
					r.notes = fmt.Sprintf("[%s] deny-match: %s; out=%s", elapsed, denied, snippet(got.out))
				case c.expectOutputPattern != "" && !strings.Contains(got.out, c.expectOutputPattern):
					r.status = "FAIL"
					r.notes = fmt.Sprintf("[%s] expected substring %q not found; out=%s", elapsed, c.expectOutputPattern, snippet(got.out))
				case trimmed == "" && !c.allowEmpty:
					r.status = "FAIL"
					r.notes = fmt.Sprintf("[%s] empty output (expected non-empty)", elapsed)
				case trimmed == "":
					r.status = "PASS"
					r.notes = fmt.Sprintf("[%s] (empty — accepted)", elapsed)
				default:
					r.status = "PASS"
					r.notes = fmt.Sprintf("[%s] %s", elapsed, snippet(got.out))
				}
			}
		case <-caseCtx.Done():
			r.status = "FAIL"
			r.notes = fmt.Sprintf("case deadline exceeded after %v (ctx=%v)", perCaseTimeout, caseCtx.Err())
		}
		caseCancel()
		fmt.Printf("  [%s] %s · %s — %s\n", r.status, r.category, r.name, r.notes)
		results = append(results, r)
	}

	pass, fail, skip := 0, 0, 0
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
	fmt.Println()
	fmt.Println("=== SUMMARY ===")
	fmt.Printf("pass=%d fail=%d skip=%d total=%d\n", pass, fail, skip, len(results))

	if fail > 0 {
		os.Exit(1)
	}
}

func denyFor(c tcase) []string {
	if len(c.denyOutputPatterns) > 0 {
		return c.denyOutputPatterns
	}
	return defaultDenyPatterns
}

func firstMatch(haystack string, needles []string) string {
	for _, n := range needles {
		if strings.Contains(haystack, n) {
			return n
		}
	}
	return ""
}

func buildCases() []tcase {
	return []tcase{
		// ================================================================
		// Round 1 — identity / metadata (read-only)
		// ================================================================
		{category: "device", name: "Info", run: func(_ context.Context, m *marauder.Marauder) (string, error) {
			return m.Info()
		}, expectOutputPattern: "AP MAC"},
		{category: "device", name: "Settings", run: func(_ context.Context, m *marauder.Marauder) (string, error) {
			return m.Settings()
		}, allowEmpty: true},
		{category: "device", name: "GetChannel", run: func(_ context.Context, m *marauder.Marauder) (string, error) {
			return m.GetChannel()
		}, expectOutputPattern: "Current channel:"},

		// ================================================================
		// Round 2 — list management (no RF)
		// ================================================================
		{category: "list", name: "ClearAPs", run: func(_ context.Context, m *marauder.Marauder) (string, error) {
			return m.ClearAPs()
		}, allowEmpty: true},
		{category: "list", name: "ClearSSIDs", run: func(_ context.Context, m *marauder.Marauder) (string, error) {
			return m.ClearSSIDs()
		}, allowEmpty: true},
		{category: "list", name: "ClearStations", run: func(_ context.Context, m *marauder.Marauder) (string, error) {
			return m.ClearStations()
		}, allowEmpty: true},
		{category: "list", name: "ListAPs(empty)", run: func(_ context.Context, m *marauder.Marauder) (string, error) {
			return m.ListAPs()
		}, allowEmpty: true},
		{category: "list", name: "ListSSIDs(empty)", run: func(_ context.Context, m *marauder.Marauder) (string, error) {
			return m.ListSSIDs()
		}, allowEmpty: true},
		{category: "list", name: "ListStations(empty)", run: func(_ context.Context, m *marauder.Marauder) (string, error) {
			return m.ListStations()
		}, allowEmpty: true},
		{category: "list", name: "AddSSID(test-pz)", run: func(_ context.Context, m *marauder.Marauder) (string, error) {
			return m.AddSSID("test-pz")
		}, allowEmpty: true},
		{category: "list", name: "GenerateSSIDs(3)", run: func(_ context.Context, m *marauder.Marauder) (string, error) {
			return m.GenerateSSIDs(3)
		}, allowEmpty: true},
		{category: "list", name: "ListSSIDs(after add+gen)", run: func(_ context.Context, m *marauder.Marauder) (string, error) {
			return m.ListSSIDs()
		}, expectOutputPattern: "test-pz"},
		{category: "list", name: "RemoveSSID(0)", run: func(_ context.Context, m *marauder.Marauder) (string, error) {
			return m.RemoveSSID(0)
		}, allowEmpty: true},
		{category: "list", name: "SaveSSIDs", run: func(_ context.Context, m *marauder.Marauder) (string, error) {
			return m.SaveSSIDs()
		}, allowEmpty: true},
		{category: "list", name: "LoadSSIDs", run: func(_ context.Context, m *marauder.Marauder) (string, error) {
			return m.LoadSSIDs()
		}, allowEmpty: true},
		{category: "list", name: "ClearSSIDs(final)", run: func(_ context.Context, m *marauder.Marauder) (string, error) {
			return m.ClearSSIDs()
		}, allowEmpty: true},

		// ================================================================
		// Round 3 — passive WiFi scanning / sniffing (RX only)
		// ================================================================
		{category: "scan", name: "ScanAP(3s)", run: func(_ context.Context, m *marauder.Marauder) (string, error) {
			_, _ = m.ScanAP(3 * time.Second)
			_, _ = m.StopScan()
			return m.ListAPs()
		}, allowEmpty: true},
		{category: "scan", name: "ScanAll(3s)", run: func(_ context.Context, m *marauder.Marauder) (string, error) {
			_, _ = m.ScanAll(3 * time.Second)
			_, _ = m.StopScan()
			return m.Info()
		}, expectOutputPattern: "AP MAC"},
		{category: "sniff", name: "SniffBeacon(2s)", run: func(_ context.Context, m *marauder.Marauder) (string, error) {
			_, _ = m.SniffBeacon(2 * time.Second)
			_, _ = m.StopScan()
			return "", nil
		}, allowEmpty: true},
		{category: "sniff", name: "SniffDeauth(2s)", run: func(_ context.Context, m *marauder.Marauder) (string, error) {
			_, _ = m.SniffDeauth(2 * time.Second)
			_, _ = m.StopScan()
			return "", nil
		}, allowEmpty: true},
		{category: "sniff", name: "SniffProbe(2s)", run: func(_ context.Context, m *marauder.Marauder) (string, error) {
			_, _ = m.SniffProbe(2 * time.Second)
			_, _ = m.StopScan()
			return "", nil
		}, allowEmpty: true},
		{category: "sniff", name: "SniffRaw(2s)", run: func(_ context.Context, m *marauder.Marauder) (string, error) {
			_, _ = m.SniffRaw(2 * time.Second)
			_, _ = m.StopScan()
			return "", nil
		}, allowEmpty: true},
		{category: "sniff", name: "SniffPwnagotchi(2s)", run: func(_ context.Context, m *marauder.Marauder) (string, error) {
			_, _ = m.SniffPwnagotchi(2 * time.Second)
			_, _ = m.StopScan()
			return "", nil
		}, allowEmpty: true},

		// ================================================================
		// Round 4 — MAC randomisation (Marauder-local, no RF effect)
		// ================================================================
		{category: "mac", name: "RandomAPMAC", run: func(_ context.Context, m *marauder.Marauder) (string, error) {
			return m.RandomAPMAC()
		}, allowEmpty: true},
		{category: "mac", name: "RandomStaMAC", run: func(_ context.Context, m *marauder.Marauder) (string, error) {
			return m.RandomStaMAC()
		}, allowEmpty: true},
		{category: "mac", name: "Info(post-random)", run: func(_ context.Context, m *marauder.Marauder) (string, error) {
			return m.Info()
		}, expectOutputPattern: "AP MAC"},

		// ================================================================
		// Round 5 — SKIPS (safety policy, require explicit target)
		// ================================================================
		{category: "attack", name: "DeauthAttack", skip: "SKIPPED — transmits deauth frames to any captured APs; requires explicit authorisation"},
		{category: "attack", name: "DeauthToStationList", skip: "SKIPPED — transmits deauth frames to station list; requires explicit authorisation"},
		{category: "attack", name: "BeaconSpamList", skip: "SKIPPED — broadcasts fake APs; RF spectrum pollution"},
		{category: "attack", name: "BeaconSpamRandom", skip: "SKIPPED — broadcasts fake APs"},
		{category: "attack", name: "BeaconSpamClone", skip: "SKIPPED — clones + broadcasts nearby APs"},
		{category: "attack", name: "BeaconSpamRickroll", skip: "SKIPPED — broadcasts fake APs"},
		{category: "attack", name: "BeaconSpamFunny", skip: "SKIPPED — broadcasts fake APs"},
		{category: "attack", name: "ProbeFlood", skip: "SKIPPED — floods probe requests"},
		{category: "attack", name: "CSAAttack", skip: "SKIPPED — CSA frames disrupt APs; needs authorisation"},
		{category: "attack", name: "SAEFlood", skip: "SKIPPED — WPA3 DoS vector"},
		{category: "ble", name: "BLESpam(apple)", skip: "SKIPPED — BLE advertisement spam affects nearby phones"},
		{category: "evilportal", name: "EvilPortalStart", skip: "SKIPPED — active fake AP; needs authorised target"},
		{category: "net", name: "Join", skip: "SKIPPED — requires user's WiFi credentials"},
		{category: "net", name: "PingScan / ARPScan / PortScan", skip: "SKIPPED — require Join first; not authorised to probe user's LAN here"},
		{category: "admin", name: "Reboot", skip: "SKIPPED — disconnects serial; WSL USB re-enumeration burns iteration cycles"},
		{category: "admin", name: "Update", skip: "SKIPPED — OTA firmware update; bricking risk"},

		// Final cleanup
		{category: "device", name: "StopScan(final)", run: func(_ context.Context, m *marauder.Marauder) (string, error) {
			return m.StopScan()
		}, allowEmpty: true},
	}
}
