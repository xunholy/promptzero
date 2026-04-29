// Package parsers turns Marauder CLI output lines into typed events the web
// layer can ship as JSON.
//
// Each parser is a pure function: input is one line (or one logical block of
// lines for the GPS data parser), output is a typed event plus an ok bool
// telling the caller whether the line carried a recognisable event. Lines
// that don't parse return ok=false; the caller decides whether to drop them
// silently or relay as raw text.
//
// Tolerance is deliberate. Marauder firmware varies by board (HAS_FULL_SCREEN,
// HAS_DUAL_BAND, HAS_GPS) and by version. Parsers extract fields with
// independent regexes rather than pinning a single line shape so a firmware
// rev that adds or moves a column doesn't regress everything.
//
// Source-of-truth for canonical formats lives in
// `internal/marauder/parsers/testdata/README.md`.
package parsers

import (
	"regexp"
	"strconv"
	"strings"
)

// ---- event types ----

// APEvent is one row of `scanap` / `sniffbeacon` output.
type APEvent struct {
	RSSI    int    `json:"rssi"`
	Channel int    `json:"channel"`
	BSSID   string `json:"bssid"`
	SSID    string `json:"ssid,omitempty"`
}

// STAEvent is one row of `scansta` / `scanall` station output.
type STAEvent struct {
	Index           int    `json:"index"`
	MAC             string `json:"mac"`
	RSSI            int    `json:"rssi,omitempty"`
	AssociatedBSSID string `json:"associated_bssid,omitempty"`
}

// ProbeEvent is one row of `sniffprobe` output.
type ProbeEvent struct {
	RSSI      int    `json:"rssi"`
	Channel   int    `json:"channel"`
	ClientMAC string `json:"client_mac"`
	Probe     string `json:"probe,omitempty"`
}

// DeauthEvent is one row of `sniffdeauth` output.
type DeauthEvent struct {
	RSSI    int    `json:"rssi"`
	Channel int    `json:"channel"`
	Source  string `json:"src"`
	Dest    string `json:"dst"`
}

// PacketRate is one tick of the aggregate packet stats block emitted by
// `sniffraw` (renderRawStats). The same shape covers Packet Monitor.
type PacketRate struct {
	Mgmt     int `json:"mgmt"`
	Data     int `json:"data"`
	Channel  int `json:"channel"`
	Beacon   int `json:"beacon"`
	ProbeReq int `json:"probe_req"`
	ProbeRes int `json:"probe_res"`
	Deauth   int `json:"deauth"`
	EAPOL    int `json:"eapol"`
	RSSIMin  int `json:"rssi_min,omitempty"`
	RSSIMax  int `json:"rssi_max,omitempty"`
}

// PacketCountEvent is one row of `packetcount` (renderPacketRate) output:
// an SSID-or-MAC label and the cumulative packet count for that selection.
type PacketCountEvent struct {
	Label   string `json:"label"`
	Packets int    `json:"packets"`
}

// GPSSnapshot is the parsed payload of one ==== GPS Data ==== block.
type GPSSnapshot struct {
	Fix      bool    `json:"fix"`
	Sats     int     `json:"sats"`
	Accuracy float64 `json:"accuracy,omitempty"`
	Lat      float64 `json:"lat,omitempty"`
	Lon      float64 `json:"lon,omitempty"`
	Alt      float64 `json:"alt,omitempty"`
	Datetime string  `json:"datetime,omitempty"`
	Text     string  `json:"text,omitempty"`
}

// LSEntry is one row of `ls <path>` output.
type LSEntry struct {
	Name  string `json:"name"`
	Bytes int64  `json:"bytes"`
	IsDir bool   `json:"is_dir"`
}

// BLEEvent is one row of `sniffbt` (BLE scan) output.
type BLEEvent struct {
	RSSI int    `json:"rssi"`
	Name string `json:"name,omitempty"`
	MAC  string `json:"mac,omitempty"`
}

// BLEWardriveEvent is one BLE wardrive CSV row.
type BLEWardriveEvent struct {
	MAC      string  `json:"mac"`
	Datetime string  `json:"datetime,omitempty"`
	RSSI     int     `json:"rssi"`
	Lat      float64 `json:"lat"`
	Lon      float64 `json:"lon"`
	Alt      float64 `json:"alt"`
	Accuracy float64 `json:"accuracy"`
}

// AttackStatus is one tick of attack rate-output (`packets/sec: <n>`).
type AttackStatus struct {
	PacketsPerSec int `json:"packets_per_sec"`
}

// PortalStatus is one notable line from an evilportal session
// (`Evil Portal READY`, `client connected`, `ap ip address: ...`, etc.).
type PortalStatus struct {
	State   string `json:"state"`
	Message string `json:"message,omitempty"`
}

// RawEvent is a passthrough: opaque text the caller may want to relay.
type RawEvent struct {
	Line string `json:"line"`
}

// ---- shared regexes ----

var (
	// Anchored leading "<rssi> Ch: <channel> ..."
	rssiChanLeadRE = regexp.MustCompile(`^\s*(-?\d+)\s+Ch:\s*(\d+)\s+`)
	// 6-octet MAC, case-insensitive.
	macRE = regexp.MustCompile(`([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})`)
	// Indexed station row: "0 | MAC: <mac>, RSSI: -55"
	staIndexRE = regexp.MustCompile(`^\s*(\d+)\s*\|`)
	// "RSSI: -55" or "RSSI=-55".
	rssiKVRE = regexp.MustCompile(`(?:RSSI|rssi)\s*[:=]\s*(-?\d+)`)
	// renderRawStats labels: leading whitespace + label + colon + integer.
	rawStatLineRE = regexp.MustCompile(`^\s*([A-Za-z][A-Za-z ]*?):\s*(-?\d+(?:\s*-\s*-?\d+)?)\s*$`)
	// "<label>: <int>" packetcount per-selection rows.
	pcLineRE = regexp.MustCompile(`^\s*(.+?):\s*(\d+)\s*$`)
	// "<rssi> Device: <name-or-mac>" — BLE scan all.
	bleDeviceRE = regexp.MustCompile(`^\s*(-?\d+)\s+Device:\s*(.+?)\s*$`)
	// BLE wardrive CSV row: MAC,,[BLE],<datetime>,0,<rssi>,<lat>,<lon>,<alt>,<acc>,BLE
	bleWardriveCSVRE = regexp.MustCompile(`^([0-9a-fA-F:]{17}),,\[BLE\],([^,]*),0,(-?\d+),([\-0-9.]+),([\-0-9.]+),([\-0-9.]+),([\-0-9.]+),BLE\s*$`)
	// "packets/sec: <n>"
	attackRateRE = regexp.MustCompile(`(?i)^\s*packets/sec\s*:\s*(\d+)\s*$`)
	// `<filename>\t<size>` ls row.
	lsRowRE = regexp.MustCompile(`^([^\t]+)\t(\d+)\s*$`)
)

// ---- Phase-1 parsers ----

// ParseScanAP parses one line of `scanap` / `sniffbeacon` output.
//
// Canonical upstream format (WiFiScan.cpp apSnifferCallbackFull):
//
//	"<rssi> Ch: <channel> <bssid> ESSID: <essid>"
//
// The trailing two bytes (beacon[0] beacon[1]) are sometimes appended as
// space-separated hex pairs; we tolerate them by ignoring trailing
// whitespace-separated hex tokens. ESSID may be empty (hidden network) — the
// parser still returns ok=true with SSID="".
func ParseScanAP(line string) (APEvent, bool) {
	m := rssiChanLeadRE.FindStringSubmatchIndex(line)
	if m == nil {
		return APEvent{}, false
	}
	rssi, _ := strconv.Atoi(line[m[2]:m[3]])
	ch, _ := strconv.Atoi(line[m[4]:m[5]])
	rest := line[m[1]:]

	bssidMatch := macRE.FindStringIndex(rest)
	if bssidMatch == nil {
		return APEvent{}, false
	}
	bssid := strings.ToLower(rest[bssidMatch[0]:bssidMatch[1]])
	tail := rest[bssidMatch[1]:]

	ssid := ""
	if idx := strings.Index(tail, "ESSID:"); idx >= 0 {
		ssid = strings.TrimSpace(tail[idx+len("ESSID:"):])
		// Strip trailing space-separated hex pairs (the beacon-byte
		// telemetry the firmware prints after ESSID).
		ssid = stripTrailingHexPairs(ssid)
	}

	return APEvent{
		RSSI:    rssi,
		Channel: ch,
		BSSID:   bssid,
		SSID:    ssid,
	}, true
}

// ParseScanSta parses one line of pre-v1.11 `scansta` output, also matches
// the station rows interleaved into `scanall` output. Two shapes are
// supported:
//
//	"0 | MAC: <mac>, RSSI: -55"
//	"0 | MAC: <mac>, BSSID: <bssid>, RSSI: -72"
//	"STA: <mac> -> <bssid>"   // scanall variant
func ParseScanSta(line string) (STAEvent, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return STAEvent{}, false
	}

	// scanall variant first: "STA: <mac> -> <bssid>"
	if strings.HasPrefix(trimmed, "STA:") {
		macs := macRE.FindAllString(trimmed, -1)
		if len(macs) == 0 {
			return STAEvent{}, false
		}
		ev := STAEvent{MAC: strings.ToLower(macs[0])}
		if len(macs) > 1 {
			ev.AssociatedBSSID = strings.ToLower(macs[1])
		}
		return ev, true
	}

	// Indexed list variant.
	ev := STAEvent{}
	if m := staIndexRE.FindStringSubmatch(trimmed); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil {
			ev.Index = n
		}
	}

	macs := macRE.FindAllString(trimmed, -1)
	if len(macs) == 0 {
		return STAEvent{}, false
	}
	ev.MAC = strings.ToLower(macs[0])
	if len(macs) > 1 {
		ev.AssociatedBSSID = strings.ToLower(macs[1])
	}
	if m := rssiKVRE.FindStringSubmatch(trimmed); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil {
			ev.RSSI = n
		}
	}
	return ev, true
}

// ParseSniffBeacon is an alias for ParseScanAP — the firmware routes both
// commands to the same WIFI_SCAN_AP code path, so the wire format is
// identical. Kept as a separate symbol so the registry stays self-documenting.
func ParseSniffBeacon(line string) (APEvent, bool) { return ParseScanAP(line) }

// ParseSniffProbe parses one line of `sniffprobe` output.
//
// Canonical upstream format (WiFiScan.cpp WIFI_SCAN_PROBE branch):
//
//	"<rssi> Ch: <channel> Client: <mac> Probe: <ssid>"
func ParseSniffProbe(line string) (ProbeEvent, bool) {
	m := rssiChanLeadRE.FindStringSubmatchIndex(line)
	if m == nil {
		return ProbeEvent{}, false
	}
	rssi, _ := strconv.Atoi(line[m[2]:m[3]])
	ch, _ := strconv.Atoi(line[m[4]:m[5]])
	rest := line[m[1]:]

	clientIdx := strings.Index(rest, "Client:")
	if clientIdx < 0 {
		return ProbeEvent{}, false
	}
	afterClient := rest[clientIdx+len("Client:"):]
	macMatch := macRE.FindStringIndex(afterClient)
	if macMatch == nil {
		return ProbeEvent{}, false
	}
	client := strings.ToLower(afterClient[macMatch[0]:macMatch[1]])
	tail := afterClient[macMatch[1]:]

	probe := ""
	if idx := strings.Index(tail, "Probe:"); idx >= 0 {
		probe = strings.TrimSpace(tail[idx+len("Probe:"):])
	}

	return ProbeEvent{
		RSSI:      rssi,
		Channel:   ch,
		ClientMAC: client,
		Probe:     probe,
	}, true
}

// ParseSniffDeauth parses one line of `sniffdeauth` output.
//
// Canonical upstream format (WiFiScan.cpp WIFI_SCAN_DEAUTH branch):
//
//	"<rssi> Ch: <channel> <src_mac> -> <dst_mac>"
func ParseSniffDeauth(line string) (DeauthEvent, bool) {
	m := rssiChanLeadRE.FindStringSubmatchIndex(line)
	if m == nil {
		return DeauthEvent{}, false
	}
	rssi, _ := strconv.Atoi(line[m[2]:m[3]])
	ch, _ := strconv.Atoi(line[m[4]:m[5]])
	rest := line[m[1]:]

	macs := macRE.FindAllString(rest, -1)
	if len(macs) < 2 {
		return DeauthEvent{}, false
	}
	return DeauthEvent{
		RSSI:    rssi,
		Channel: ch,
		Source:  strings.ToLower(macs[0]),
		Dest:    strings.ToLower(macs[1]),
	}, true
}

// ParsePacketCount parses one line of `packetcount` (renderPacketRate)
// output. The firmware prints each selected AP/STA as `<label>: <packets>`
// where label is either an SSID or a MAC string.
//
// Returns ok=false for blank lines or ones that don't fit the shape.
func ParsePacketCount(line string) (PacketCountEvent, bool) {
	m := pcLineRE.FindStringSubmatch(line)
	if m == nil {
		return PacketCountEvent{}, false
	}
	n, err := strconv.Atoi(m[2])
	if err != nil {
		return PacketCountEvent{}, false
	}
	label := strings.TrimSpace(m[1])
	if label == "" {
		return PacketCountEvent{}, false
	}
	return PacketCountEvent{Label: label, Packets: n}, true
}

// ParseRawStats parses a complete renderRawStats block emitted by `sniffraw`
// (and which also serves the Packet Monitor screen). The block is multiple
// labelled lines:
//
//	     Mgmt: 142
//	     Data: 87
//	  Channel: 6
//	   Beacon: 64
//	Probe Req: 12
//	Probe Res: 7
//	   Deauth: 0
//	    EAPOL: 0
//	     RSSI: -91 - -33
//
// Lines outside that label set are ignored. Returns ok=true if at least one
// recognised numeric field was found, so callers can use it as a tick signal
// even when only a subset of the block landed in the input.
func ParseRawStats(block []string) (PacketRate, bool) {
	pr := PacketRate{}
	gotAny := false
	for _, line := range block {
		m := rawStatLineRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		label := strings.TrimSpace(m[1])
		val := strings.TrimSpace(m[2])
		switch label {
		case "Mgmt":
			pr.Mgmt = atoiOr(val, 0)
			gotAny = true
		case "Data":
			pr.Data = atoiOr(val, 0)
			gotAny = true
		case "Channel":
			pr.Channel = atoiOr(val, 0)
			gotAny = true
		case "Beacon":
			pr.Beacon = atoiOr(val, 0)
			gotAny = true
		case "Probe Req":
			pr.ProbeReq = atoiOr(val, 0)
			gotAny = true
		case "Probe Res":
			pr.ProbeRes = atoiOr(val, 0)
			gotAny = true
		case "Deauth":
			pr.Deauth = atoiOr(val, 0)
			gotAny = true
		case "EAPOL":
			pr.EAPOL = atoiOr(val, 0)
			gotAny = true
		case "RSSI":
			lo, hi, ok := parseRSSIRange(val)
			if ok {
				pr.RSSIMin = lo
				pr.RSSIMax = hi
				gotAny = true
			}
		}
	}
	return pr, gotAny
}

// ParseGPSData parses one ==== GPS Data ==== block from `gpsdata` stream.
// The block is a header followed by labelled lines:
//
//	==== GPS Data ====
//	  Good Fix: Yes|No
//	      Text: <free-form>     (optional)
//	Satellites: <int>
//	  Accuracy: <float>
//	  Latitude: <float>
//	 Longitude: <float>
//	  Altitude: <float>
//	  Datetime: <YYYY-MM-DD HH:MM:SS>
//
// The header line itself is optional; pass either "the block including
// header" or "the lines after the header". Anything we can't recognise is
// ignored. Returns ok=false only if no useful field was extracted.
func ParseGPSData(block []string) (GPSSnapshot, bool) {
	snap := GPSSnapshot{}
	gotAny := false
	for _, line := range block {
		raw := strings.TrimSpace(line)
		if raw == "" || strings.HasPrefix(raw, "====") {
			continue
		}
		idx := strings.Index(raw, ":")
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(raw[:idx])
		val := strings.TrimSpace(raw[idx+1:])
		switch key {
		case "Good Fix":
			snap.Fix = strings.EqualFold(val, "Yes")
			gotAny = true
		case "Satellites":
			snap.Sats = atoiOr(val, 0)
			gotAny = true
		case "Accuracy":
			snap.Accuracy = atofOr(val, 0)
			gotAny = true
		case "Latitude":
			snap.Lat = atofOr(val, 0)
			gotAny = true
		case "Longitude":
			snap.Lon = atofOr(val, 0)
			gotAny = true
		case "Altitude":
			snap.Alt = atofOr(val, 0)
			gotAny = true
		case "Datetime":
			snap.Datetime = val
			gotAny = true
		case "Text":
			snap.Text = val
			gotAny = true
		}
	}
	return snap, gotAny
}

// ParseLs parses one row of `ls <path>` output. Format is `<name>\t<size>`
// per SDInterface.cpp listDir. Directories are emitted by SD with size 0;
// callers can disambiguate via IsDir if they extend the firmware later, but
// today we mark size==0 entries IsDir=false (the firmware doesn't actually
// distinguish on the wire).
func ParseLs(line string) (LSEntry, bool) {
	m := lsRowRE.FindStringSubmatch(line)
	if m == nil {
		return LSEntry{}, false
	}
	bytes, err := strconv.ParseInt(m[2], 10, 64)
	if err != nil {
		return LSEntry{}, false
	}
	return LSEntry{Name: strings.TrimSpace(m[1]), Bytes: bytes}, true
}

// ParseBLESniff parses one line of `sniffbt -t all` (BT_SCAN_ALL) output.
// Canonical format (WiFiScan.cpp BT_SCAN_ALL branch):
//
//	"<rssi> Device: <name-or-mac>"
//
// When the device exposes a name, the field is the friendly name; otherwise
// it's the bare MAC string. We auto-detect: if the value parses as a 6-octet
// MAC we set MAC, else Name.
func ParseBLESniff(line string) (BLEEvent, bool) {
	m := bleDeviceRE.FindStringSubmatch(line)
	if m == nil {
		return BLEEvent{}, false
	}
	rssi, err := strconv.Atoi(m[1])
	if err != nil {
		return BLEEvent{}, false
	}
	value := strings.TrimSpace(m[2])
	ev := BLEEvent{RSSI: rssi}
	if macRE.MatchString(value) && len(value) == 17 {
		ev.MAC = strings.ToLower(value)
	} else {
		ev.Name = value
	}
	return ev, true
}

// ParseBLEWardrive parses one row of BLE-wardrive CSV output (the
// `<bssid>,,[BLE],...,BLE` rows the firmware prints in the BLE branch of
// `wardrive`). The accompanying `Device: ...` line (also emitted) does NOT
// match — callers running a stream parser should fall through.
func ParseBLEWardrive(line string) (BLEWardriveEvent, bool) {
	m := bleWardriveCSVRE.FindStringSubmatch(line)
	if m == nil {
		return BLEWardriveEvent{}, false
	}
	rssi, _ := strconv.Atoi(m[3])
	return BLEWardriveEvent{
		MAC:      strings.ToLower(m[1]),
		Datetime: m[2],
		RSSI:     rssi,
		Lat:      atofOr(m[4], 0),
		Lon:      atofOr(m[5], 0),
		Alt:      atofOr(m[6], 0),
		Accuracy: atofOr(m[7], 0),
	}, true
}

// ParseAttackStatus parses one line of attack-mode rate output. Upstream
// emits `packets/sec: <n>` once per second from displayTransmitRate via
// lang_var.h text18. Anything else returns ok=false.
func ParseAttackStatus(line string) (AttackStatus, bool) {
	m := attackRateRE.FindStringSubmatch(line)
	if m == nil {
		return AttackStatus{}, false
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return AttackStatus{}, false
	}
	return AttackStatus{PacketsPerSec: n}, true
}

// ParseEvilPortal recognises the notable status lines from an
// `evilportal -c start` session. Mapping (EvilPortal.cpp):
//
//	"Starting Evil Portal. Stop with stopscan" → state=starting
//	"ap config set"                            → state=ap_configured
//	"Evil Portal READY"                        → state=ready
//	"client connected"                         → state=client_connected
//	"ap ip address: <ip>"                      → state=ap_ip      (ip in Message)
//	"Setting HTML..." / "html set"             → state=html_set   (or html_setting)
//	"Could not find /<path>. Use stopscan..." → state=error      (msg = full line)
//
// Anything else returns ok=false.
func ParseEvilPortal(line string) (PortalStatus, bool) {
	trim := strings.TrimSpace(line)
	switch {
	case strings.HasPrefix(trim, "Starting Evil Portal"):
		return PortalStatus{State: "starting"}, true
	case trim == "ap config set":
		return PortalStatus{State: "ap_configured"}, true
	case trim == "Evil Portal READY":
		return PortalStatus{State: "ready"}, true
	case trim == "client connected":
		return PortalStatus{State: "client_connected"}, true
	case strings.HasPrefix(trim, "ap ip address:"):
		ip := strings.TrimSpace(strings.TrimPrefix(trim, "ap ip address:"))
		return PortalStatus{State: "ap_ip", Message: ip}, true
	case trim == "html set":
		return PortalStatus{State: "html_set"}, true
	case strings.HasPrefix(trim, "Setting HTML"):
		return PortalStatus{State: "html_setting"}, true
	case strings.HasPrefix(trim, "Could not"), strings.Contains(trim, "Use stopscan..."):
		return PortalStatus{State: "error", Message: trim}, true
	}
	return PortalStatus{}, false
}

// ParseRaw is a passthrough — used by the sniffraw stream when callers want
// per-line raw data alongside the periodic stats. Always ok=true unless the
// line is empty after trim.
func ParseRaw(line string) (RawEvent, bool) {
	t := strings.TrimSpace(line)
	if t == "" {
		return RawEvent{}, false
	}
	return RawEvent{Line: t}, true
}

// ---- helpers ----

// stripTrailingHexPairs removes any trailing whitespace-separated 2-char hex
// tokens from s. The Marauder firmware appends two beacon header bytes after
// the ESSID; they're useful as raw frame metadata but not as part of the SSID
// string.
func stripTrailingHexPairs(s string) string {
	for {
		s = strings.TrimRight(s, " \t")
		if len(s) < 2 {
			return s
		}
		// Find the last whitespace-delimited token.
		idx := strings.LastIndexAny(s, " \t")
		token := s
		if idx >= 0 {
			token = s[idx+1:]
		}
		if len(token) != 2 || !isHex(token[0]) || !isHex(token[1]) {
			return s
		}
		if idx < 0 {
			return ""
		}
		s = s[:idx]
	}
}

func isHex(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

func atoiOr(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return def
}

func atofOr(s string, def float64) float64 {
	if f, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil {
		return f
	}
	return def
}

// parseRSSIRange parses "<lo> - <hi>" (signed ints, dashes either way).
func parseRSSIRange(s string) (lo, hi int, ok bool) {
	parts := strings.Split(s, " - ")
	if len(parts) != 2 {
		return 0, 0, false
	}
	a, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, 0, false
	}
	b, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0, 0, false
	}
	return a, b, true
}
