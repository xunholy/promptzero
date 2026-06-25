// SPDX-License-Identifier: AGPL-3.0-or-later

// Package wigle encodes GPS-stamped WiFi observations into the WiGLE
// "WigleWifi-1.4" CSV interchange format — the de-facto wardrive export
// consumed by wigle.net and compatible analysis tools.
//
// It composes the two capture primitives PromptZero already has — Marauder
// AP scans (SSID / BSSID / RSSI / channel) and GPS NMEA fixes (lat / lon /
// altitude) — into the file a wardriver imports or uploads. Encoding is
// offline and deterministic: the same observations always produce the same
// bytes. Upload itself is intentionally out of scope — it is an
// outward-facing, authenticated action the operator performs explicitly.
//
// The one genuinely tricky correctness point is that SSIDs are
// attacker-controllable and may contain commas, quotes, or newlines; all
// record fields are written through encoding/csv so they are RFC 4180
// quoted/escaped and a hostile SSID can never break the row structure or
// inject extra columns.
package wigle

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	// formatTag is the first token of the WigleWifi-1.4 pre-header line;
	// wigle.net keys its parser off this exact string.
	formatTag = "WigleWifi-1.4"

	// timeLayout is the FirstSeen format the WigleWifi app emits: a
	// space-separated, timezone-less stamp. Observations are encoded in UTC.
	timeLayout = "2006-01-02 15:04:05"

	// maxObservations bounds a single export so a runaway or malicious
	// caller can't ask for an unbounded CSV. A real wardrive session is
	// thousands of APs; 100k is generous headroom.
	maxObservations = 100_000

	// wifiType is the Type column value for an access-point row. WiGLE also
	// defines BT/BLE/GSM/etc. rows; this encoder handles WiFi only.
	wifiType = "WIFI"
)

// columnHeader is the canonical WigleWifi-1.4 column order. Order is
// load-bearing — wigle.net maps columns positionally.
var columnHeader = []string{
	"MAC", "SSID", "AuthMode", "FirstSeen", "Channel", "RSSI",
	"CurrentLatitude", "CurrentLongitude", "AltitudeMeters", "AccuracyMeters", "Type",
}

// Observation is one GPS-stamped WiFi access-point sighting.
type Observation struct {
	// BSSID is the AP hardware address. It is accepted in any case and with
	// ':', '-', '.' or no separators, and is normalised to the canonical
	// upper-case colon form (AA:BB:CC:DD:EE:FF) on encode.
	BSSID string
	// SSID is the network name. It may be empty (hidden network) and may
	// contain CSV metacharacters — those are escaped, not stripped.
	SSID string
	// AuthMode is the WiGLE capability string, e.g. "[WPA2-PSK-CCMP][ESS]".
	// Empty is allowed (auth unknown) — Marauder scans don't always report it.
	AuthMode string
	// Channel is the 802.11 channel (0 = unknown).
	Channel int
	// RSSI is signal strength in dBm (negative for a real measurement).
	RSSI int
	// Latitude / Longitude are decimal degrees from the GPS fix.
	Latitude  float64
	Longitude float64
	// AltitudeM is altitude in metres; AccuracyM is the fix's horizontal
	// accuracy in metres (0 = unknown).
	AltitudeM float64
	AccuracyM float64
	// FirstSeen is when the AP was observed; encoded as UTC. Required — a
	// wardrive row without a timestamp is not useful to WiGLE.
	FirstSeen time.Time
}

// Metadata is the WigleWifi pre-header line describing the capturing
// device. Empty fields fall back to PromptZero defaults in Encode. Commas
// and newlines in values are stripped, since this line is not CSV-quoted.
type Metadata struct {
	AppRelease string
	Model      string
	Release    string
	Device     string
	Display    string
	Board      string
	Brand      string
}

// withDefaults fills empty Metadata fields with sensible PromptZero values
// and strips characters that would corrupt the comma-delimited pre-header.
func (m Metadata) withDefaults(appVersion string) Metadata {
	pick := func(v, fallback string) string {
		v = strings.TrimSpace(v)
		if v == "" {
			v = fallback
		}
		// The pre-header is a flat comma-joined line, so a comma or newline
		// inside a value would shift every following key=value pair.
		return strings.NewReplacer(",", " ", "\n", " ", "\r", " ").Replace(v)
	}
	return Metadata{
		AppRelease: pick(m.AppRelease, "promptzero "+appVersion),
		Model:      pick(m.Model, "Flipper Zero + ESP32 Marauder"),
		Release:    pick(m.Release, appVersion),
		Device:     pick(m.Device, "promptzero"),
		Display:    pick(m.Display, ""),
		Board:      pick(m.Board, ""),
		Brand:      pick(m.Brand, "xunholy"),
	}
}

// preHeader renders the WigleWifi-1.4 metadata line.
func (m Metadata) preHeader() string {
	return fmt.Sprintf(
		"%s,appRelease=%s,model=%s,release=%s,device=%s,display=%s,board=%s,brand=%s",
		formatTag, m.AppRelease, m.Model, m.Release, m.Device, m.Display, m.Board, m.Brand,
	)
}

// normaliseBSSID accepts a MAC in any common form and returns the
// canonical upper-case colon-separated form, or an error if it is not
// exactly six hex octets.
func normaliseBSSID(s string) (string, error) {
	cleaned := strings.Map(func(r rune) rune {
		switch r {
		case ':', '-', '.', ' ':
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if len(cleaned) != 12 {
		return "", fmt.Errorf("bssid %q: want 6 hex octets (12 hex digits), got %d digits", s, len(cleaned))
	}
	for _, r := range cleaned {
		isHex := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
		if !isHex {
			return "", fmt.Errorf("bssid %q: contains non-hex character %q", s, r)
		}
	}
	up := strings.ToUpper(cleaned)
	var b strings.Builder
	b.Grow(17)
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(up[i : i+2])
	}
	return b.String(), nil
}

// record validates one observation and returns its CSV field slice in
// columnHeader order. Validation is fail-closed: a bad MAC, an
// out-of-range coordinate, or a missing timestamp is an error, not a
// silently-skipped or coerced row.
func (o Observation) record() ([]string, error) {
	mac, err := normaliseBSSID(o.BSSID)
	if err != nil {
		return nil, err
	}
	if o.Latitude < -90 || o.Latitude > 90 {
		return nil, fmt.Errorf("bssid %s: latitude %g out of range [-90,90]", mac, o.Latitude)
	}
	if o.Longitude < -180 || o.Longitude > 180 {
		return nil, fmt.Errorf("bssid %s: longitude %g out of range [-180,180]", mac, o.Longitude)
	}
	if o.Channel < 0 || o.Channel > 196 {
		return nil, fmt.Errorf("bssid %s: channel %d out of range [0,196]", mac, o.Channel)
	}
	if o.FirstSeen.IsZero() {
		return nil, fmt.Errorf("bssid %s: first_seen timestamp is required", mac)
	}
	f := func(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }
	return []string{
		mac,
		o.SSID,     // csv.Writer handles RFC 4180 escaping of any metacharacters
		o.AuthMode, // free-form capability string; escaped the same way
		o.FirstSeen.UTC().Format(timeLayout),
		strconv.Itoa(o.Channel),
		strconv.Itoa(o.RSSI),
		f(o.Latitude),
		f(o.Longitude),
		f(o.AltitudeM),
		f(o.AccuracyM),
		wifiType,
	}, nil
}

// Encode renders observations as a WigleWifi-1.4 CSV document. It returns
// an error if there are no observations, too many, or any single
// observation fails validation — a partial/corrupt wardrive file is worse
// than a clear error, so encoding is all-or-nothing.
func Encode(meta Metadata, appVersion string, obs []Observation) ([]byte, error) {
	if len(obs) == 0 {
		return nil, fmt.Errorf("wigle: no observations to encode")
	}
	if len(obs) > maxObservations {
		return nil, fmt.Errorf("wigle: %d observations exceeds cap of %d", len(obs), maxObservations)
	}

	var buf bytes.Buffer
	buf.WriteString(meta.withDefaults(appVersion).preHeader())
	buf.WriteByte('\n')

	w := csv.NewWriter(&buf)
	if err := w.Write(columnHeader); err != nil {
		return nil, fmt.Errorf("wigle: writing header: %w", err)
	}
	for i, o := range obs {
		rec, err := o.record()
		if err != nil {
			return nil, fmt.Errorf("wigle: observation %d: %w", i, err)
		}
		if err := w.Write(rec); err != nil {
			return nil, fmt.Errorf("wigle: writing observation %d: %w", i, err)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, fmt.Errorf("wigle: flushing: %w", err)
	}
	return buf.Bytes(), nil
}
