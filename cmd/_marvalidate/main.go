// Command _marvalidate is a read-only / benign validation harness for a
// physically-connected ESP32 Marauder devboard. Leading-underscore dir →
// skipped by go build ./... / test / lint; run explicitly:
//
//	go run ./cmd/_marvalidate -port /dev/ttyUSB0
//
// It drives the production internal/marauder client through identity and
// settings reads and a benign stop/list, cross-checking the parser against
// real firmware. It deliberately issues NO offensive transmission
// (deauth / beacon-spam / probe-flood / sniff) — purely identity + config
// reads, plus a stop-scan to leave the board idle.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/xunholy/promptzero/internal/marauder"
)

func main() {
	port := flag.String("port", "/dev/ttyUSB0", "Marauder serial port (CP210x → /dev/ttyUSB0)")
	baud := flag.Int("baud", 115200, "serial baud rate")
	flag.Parse()

	fmt.Printf("== Marauder validation ==\nconnecting: %s @ %d\n\n", *port, *baud)

	m, err := marauder.Connect(*port, *baud)
	if err != nil {
		fmt.Printf("FATAL: connect failed: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = m.Close() }()

	var pass, warn, fail int
	add := func(name, level, detail string) {
		switch level {
		case "PASS":
			pass++
		case "WARN":
			warn++
		case "FAIL":
			fail++
		}
		fmt.Printf("[%-4s] %-20s %s\n", level, name, detail)
	}

	// --- device info / identity (read-only) ----------------------------
	info, err := m.InfoParsed()
	switch {
	case err != nil:
		add("info", "FAIL", err.Error())
	case !info.Detected:
		add("info", "WARN", "device responded but parser did not detect a Marauder identity")
	default:
		add("info", "PASS", fmt.Sprintf("fw=%q ver=%q idf=%q ch=%d mac=%q band=%s",
			info.FirmwareName, info.FirmwareVersion, info.ESPIDFVersion, info.Channel, info.MAC, info.CompatBand()))
	}

	// --- settings (read-only) -------------------------------------------
	if s, err := m.Settings(); err != nil {
		add("settings", "WARN", err.Error())
	} else {
		add("settings", "PASS", summarize(s))
	}

	// --- list APs (read current memory; expected empty/clean) -----------
	if aps, err := m.ListAPs(); err != nil {
		add("list_aps", "WARN", err.Error())
	} else {
		add("list_aps", "PASS", summarize(aps))
	}

	// --- stop scan (benign — leaves the board idle, no TX) --------------
	if _, err := m.StopScan(); err != nil {
		add("stop_scan", "WARN", err.Error())
	} else {
		add("stop_scan", "PASS", "scan stopped (board left idle)")
	}

	fmt.Printf("\n== summary: %d pass / %d warn / %d fail ==\n", pass, warn, fail)
	if fail > 0 {
		os.Exit(2)
	}
}

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
