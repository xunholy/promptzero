package marauder

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Structured types emitted by the *Parsed variants of the scan / list
// commands. Field tags follow the snake_case style already used by
// the agent's JSON tool_result payloads so the LLM sees a consistent
// shape across features.
//
// AccessPoint covers the output of scanap / list -a. All fields but
// Index are best-effort — firmware variations across Marauder
// versions move SSIDs into / out of quotes, replace "CH" with
// "Channel", etc. Missing fields stay zero/empty rather than
// surfacing a parse error so the model still gets something useful.
type AccessPoint struct {
	Index    int    `json:"index"`
	SSID     string `json:"ssid,omitempty"`
	BSSID    string `json:"bssid,omitempty"`
	RSSI     int    `json:"rssi,omitempty"`    // dBm
	Channel  int    `json:"channel,omitempty"` // 1-14 (2.4 GHz) or 5GHz equivalents
	RawLine  string `json:"raw,omitempty"`     // original line for audit / fallback
	Selected bool   `json:"selected,omitempty"`
}

// Station is the output shape of list -c / station sniffs. MAC is the
// client's hardware address; AssociatedBSSID is the AP it was last
// seen talking to when the firmware tracks that correlation.
type Station struct {
	Index           int    `json:"index"`
	MAC             string `json:"mac,omitempty"`
	RSSI            int    `json:"rssi,omitempty"`
	AssociatedBSSID string `json:"associated_bssid,omitempty"`
	RawLine         string `json:"raw,omitempty"`
}

// ScanResult wraps a list of access points alongside the raw excerpt
// so the LLM can fall back to the text when it doesn't recognise a
// row. Keeping the raw excerpt is also load-bearing for the
// prompt-injection quarantine layer upstream (see internal/agent) —
// the sanitised text is what's bounced into the tool_result.
type ScanResult struct {
	APs      []AccessPoint `json:"aps,omitempty"`
	Count    int           `json:"count"`
	RawLines []string      `json:"raw_lines,omitempty"`
}

// StationResult mirrors ScanResult for the station list.
type StationResult struct {
	Stations []Station `json:"stations,omitempty"`
	Count    int       `json:"count"`
	RawLines []string  `json:"raw_lines,omitempty"`
}

// apLinePattern matches a handful of common Marauder AP list line
// formats:
//
//	"0 | SSID: HomeNet, BSSID: aa:bb:cc:dd:ee:ff, RSSI: -45, CH: 6"
//	"0 | SSID: HomeNet BSSID: aa:bb:cc:dd:ee:ff RSSI: -45 Channel: 6"
//	"0: HomeNet [aa:bb:cc:dd:ee:ff] -45dBm ch6"
//
// Rather than pinning one format we extract each field independently
// with forgiving regex patterns so adding a new firmware variant
// doesn't regress older captures.
var (
	apIndexRE = regexp.MustCompile(`^\s*(\d+)\s*[|:]`)
	// Anchored on a field boundary (start-of-line, comma, pipe, or
	// whitespace) so "BSSID:" doesn't get mis-matched as the SSID
	// field (BSSID contains SSID as a suffix — a naive regex would
	// otherwise capture the MAC address as the SSID).
	ssidFieldRE = regexp.MustCompile(`(?:^|[,|\t ])(?:SSID|ssid)\s*[:=]\s*(.+?)(?:,|\s{2,}|\s*BSSID|\s*RSSI|\s*CH|\s*Channel|\s*\[|$)`)
	bssidRE     = regexp.MustCompile(`([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})`)
	rssiRE      = regexp.MustCompile(`-?\d+\s*(?:dBm|DBM)|(?:RSSI|rssi)\s*[:=]\s*(-?\d+)`)
	channelRE   = regexp.MustCompile(`(?:CH|Channel|ch|channel)\s*[:=]?\s*(\d+)`)
	macOnlyRE   = regexp.MustCompile(`^([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})`)
)

// ParseAPList parses a Marauder AP-list response (from scanap,
// list -a, or similar) into a ScanResult. Lines that don't look like
// AP entries are preserved in RawLines so the model retains full
// context; lines that parse into an AccessPoint contribute to both
// the structured APs slice AND are stored in each AP's RawLine field
// for debugging.
//
// Tolerance is deliberate:
//   - an entry with no SSID (hidden network) still parses on BSSID alone
//   - entries with only an index + SSID still parse, just with zero
//     RSSI / Channel
//   - completely unparseable lines land in RawLines so nothing is lost
func ParseAPList(raw string) ScanResult {
	res := ScanResult{}
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimRight(line, " \r\n\t")
		if trimmed == "" {
			continue
		}
		ap, ok := parseAPLine(trimmed)
		if ok {
			res.APs = append(res.APs, ap)
		} else {
			res.RawLines = append(res.RawLines, trimmed)
		}
	}
	res.Count = len(res.APs)
	return res
}

// parseAPLine attempts to extract AP fields from a single line.
// Returns ok=false when the line carries neither an index nor a
// BSSID — that signals "definitely not an AP row, skip it".
func parseAPLine(line string) (AccessPoint, bool) {
	ap := AccessPoint{RawLine: line}

	if m := apIndexRE.FindStringSubmatch(line); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil {
			ap.Index = n
		}
	}

	if m := bssidRE.FindStringSubmatch(line); m != nil {
		ap.BSSID = strings.ToLower(m[1])
	}

	if m := ssidFieldRE.FindStringSubmatch(line); m != nil {
		ap.SSID = strings.Trim(strings.TrimSpace(m[1]), `"'`)
	}

	// Look for RSSI as either "<N>dBm" or "RSSI: -N".
	if m := rssiRE.FindStringSubmatch(line); m != nil {
		var raw string
		if m[1] != "" {
			raw = m[1]
		} else {
			raw = strings.TrimSpace(strings.TrimSuffix(strings.TrimSuffix(m[0], "dBm"), "DBM"))
		}
		if n, err := strconv.Atoi(raw); err == nil {
			ap.RSSI = n
		}
	}

	if m := channelRE.FindStringSubmatch(line); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil {
			ap.Channel = n
		}
	}

	// An index alone ("42 |") without any other signal is noise; demand at
	// least an SSID or BSSID to count as a real row.
	if ap.SSID == "" && ap.BSSID == "" {
		return AccessPoint{}, false
	}
	return ap, true
}

// ParseStationList parses the output of list -c / station-scan into a
// StationResult. The same tolerance rules apply as ParseAPList: a row
// needs at least a MAC address to count.
func ParseStationList(raw string) StationResult {
	res := StationResult{}
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimRight(line, " \r\n\t")
		if trimmed == "" {
			continue
		}
		st, ok := parseStationLine(trimmed)
		if ok {
			res.Stations = append(res.Stations, st)
		} else {
			res.RawLines = append(res.RawLines, trimmed)
		}
	}
	res.Count = len(res.Stations)
	return res
}

func parseStationLine(line string) (Station, bool) {
	st := Station{RawLine: line}

	if m := apIndexRE.FindStringSubmatch(line); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil {
			st.Index = n
		}
	}

	// Stations sometimes print as a bare MAC on their own line. The
	// bssidRE captures any six-octet MAC — we take the first match for
	// the station itself and, if a second MAC appears on the same line,
	// treat it as the associated BSSID.
	macs := bssidRE.FindAllStringSubmatch(line, -1)
	for i, m := range macs {
		mac := strings.ToLower(m[1])
		switch i {
		case 0:
			st.MAC = mac
		case 1:
			st.AssociatedBSSID = mac
		}
	}
	// Fallback for lines that are just a bare MAC with no index prefix.
	if st.MAC == "" {
		if m := macOnlyRE.FindStringSubmatch(line); m != nil {
			st.MAC = strings.ToLower(m[1])
		}
	}

	if m := rssiRE.FindStringSubmatch(line); m != nil {
		var raw string
		if m[1] != "" {
			raw = m[1]
		} else {
			raw = strings.TrimSpace(strings.TrimSuffix(strings.TrimSuffix(m[0], "dBm"), "DBM"))
		}
		if n, err := strconv.Atoi(raw); err == nil {
			st.RSSI = n
		}
	}

	if st.MAC == "" {
		return Station{}, false
	}
	return st, true
}

// ScanAPParsed runs scanap and returns the result parsed into a
// ScanResult. On parse failure the raw string is still carried in
// RawLines so the caller can fall back to text display.
func (m *Marauder) ScanAPParsed(timeout time.Duration) (ScanResult, error) {
	return m.ScanAPParsedCtx(context.Background(), timeout)
}

// ScanAPParsedCtx is the context-aware variant of ScanAPParsed.
// A turn-level cancel (e.g. operator Ctrl+C in the REPL) propagates
// to the underlying Marauder read loop within ~100 ms, so the call
// returns promptly rather than blocking until the timeout fires.
// Mirrors the [Flipper.ExecLongCtx] convention so handlers can
// thread their dispatch ctx all the way through to the wire.
func (m *Marauder) ScanAPParsedCtx(ctx context.Context, timeout time.Duration) (ScanResult, error) {
	raw, err := m.ExecCtx(ctx, "scanap", timeout)
	if err != nil {
		return ScanResult{}, err
	}
	return ParseAPList(raw), nil
}

// ScanAPParsedStream is the line-streaming variant of ScanAPParsed.
// onLine is invoked for every scanap line as the firmware emits it
// (typically one per detected AP); returning stop=true ends the
// scan early. The accumulated raw output is parsed and returned
// the same way ScanAPParsed would. Errors propagate; stream-end
// (timeout / ctx cancel / onLine stop) is treated as success and
// the parser runs against whatever was accumulated.
func (m *Marauder) ScanAPParsedStream(ctx context.Context, timeout time.Duration, onLine func(line string) (stop bool)) (ScanResult, error) {
	raw, err := m.StreamLines(ctx, "scanap", timeout, onLine)
	if err != nil {
		return ScanResult{}, err
	}
	return ParseAPList(raw), nil
}

// ListAPsParsed runs list -a and returns the parsed AP list.
func (m *Marauder) ListAPsParsed() (ScanResult, error) {
	raw, err := m.ListAPs()
	if err != nil {
		return ScanResult{}, err
	}
	return ParseAPList(raw), nil
}

// ListStationsParsed runs list -c and returns the parsed station list.
func (m *Marauder) ListStationsParsed() (StationResult, error) {
	raw, err := m.ListStations()
	if err != nil {
		return StationResult{}, err
	}
	return ParseStationList(raw), nil
}

// ErrParseEmpty signals that the input to a parser was empty after
// trimming. Parsers currently don't return this — empty input yields
// a zero-valued result with Count=0 — but it's exposed so future
// strict callers can upgrade without an API break.
var ErrParseEmpty = fmt.Errorf("marauder: empty parse input")
