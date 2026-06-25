// SPDX-License-Identifier: AGPL-3.0-or-later

package wigle

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
)

// maxParseRows bounds how many data rows ParseCSV will ingest from an
// operator-supplied file, so a hostile or accidentally-huge wardrive can't
// exhaust memory. Real sessions are tens of thousands of APs; 500k is
// generous headroom and still bounded.
const maxParseRows = 500_000

// firstSeenLayouts are the timestamp formats seen across WiGLE/Kismet
// exporters. ParseCSV tries each; an unparseable timestamp is tolerated
// (left zero) rather than dropping an otherwise-good observation.
var firstSeenLayouts = []string{
	timeLayout,             // "2006-01-02 15:04:05" — WigleWifi app
	"2006-01-02T15:04:05Z", // ISO 8601 UTC
	time.RFC3339,           // ISO 8601 with offset
}

// ParseResult is the outcome of parsing a WiGLE CSV: the WiFi observations
// recovered, plus counts so the caller can report how much was skipped.
type ParseResult struct {
	Observations []Observation
	// SkippedRows is data rows dropped because they were malformed (bad MAC
	// or unparseable coordinates) or non-WiFi (a BT/BLE/GSM Type row).
	SkippedRows int
	// DataRows is the total number of data rows seen (excludes the header
	// and the optional WigleWifi pre-header line).
	DataRows int
}

// ParseCSV reads a WiGLE-style wardrive CSV — the WigleWifi-1.4 export and
// close variants (Kismet, files with extra columns) — into WiFi
// observations. It is the inverse of Encode.
//
// Parsing is deliberately resilient, not fail-closed: this ingests
// operator-supplied capture files, where dropping a 5000-AP wardrive over
// one malformed line would be worse than skipping that line. Columns are
// matched by header name (not position) so extra/re-ordered columns from
// other exporters are tolerated; a row with a bad MAC or coordinate, or a
// non-WiFi Type, is skipped and counted. A genuinely unusable input — not
// CSV, or no recognisable MAC column — is a hard error.
func ParseCSV(data []byte) (*ParseResult, error) {
	body := stripPreHeader(data)

	r := csv.NewReader(bytes.NewReader(body))
	r.FieldsPerRecord = -1 // tolerate variable column counts across exporters
	r.LazyQuotes = true
	r.ReuseRecord = true

	header, err := r.Read()
	if err == io.EOF {
		return nil, fmt.Errorf("wigle: empty input")
	}
	if err != nil {
		return nil, fmt.Errorf("wigle: reading header: %w", err)
	}
	cols := indexColumns(header)
	macIdx, ok := cols["mac"]
	if !ok {
		// Some exporters label it BSSID.
		if macIdx, ok = cols["bssid"]; !ok {
			return nil, fmt.Errorf("wigle: no MAC/BSSID column found in header %q", strings.Join(header, ","))
		}
	}

	res := &ParseResult{}
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			// A row-level CSV error (e.g. a stray quote LazyQuotes couldn't
			// recover) — skip it and continue rather than abandon the file.
			res.SkippedRows++
			continue
		}
		res.DataRows++
		if res.DataRows > maxParseRows {
			return nil, fmt.Errorf("wigle: input exceeds %d data rows", maxParseRows)
		}

		obs, ok := parseRow(rec, cols, macIdx)
		if !ok {
			res.SkippedRows++
			continue
		}
		res.Observations = append(res.Observations, obs)
	}
	return res, nil
}

// stripPreHeader drops a leading "WigleWifi-..." metadata line if present,
// returning the remaining bytes that begin with the CSV column header.
func stripPreHeader(data []byte) []byte {
	nl := bytes.IndexByte(data, '\n')
	if nl < 0 {
		return data
	}
	first := bytes.TrimSpace(data[:nl])
	if bytes.HasPrefix(bytes.ToLower(first), []byte("wiglewifi")) {
		return data[nl+1:]
	}
	return data
}

// indexColumns maps lower-cased, trimmed header names to their position.
func indexColumns(header []string) map[string]int {
	m := make(map[string]int, len(header))
	for i, h := range header {
		key := strings.ToLower(strings.TrimSpace(h))
		if key != "" {
			if _, exists := m[key]; !exists {
				m[key] = i
			}
		}
	}
	return m
}

// parseRow extracts one WiFi observation. It returns ok=false (skip) for a
// bad MAC, an unparseable coordinate, or a non-WiFi Type row.
func parseRow(rec []string, cols map[string]int, macIdx int) (Observation, bool) {
	get := func(name string) string {
		if i, ok := cols[name]; ok && i < len(rec) {
			return strings.TrimSpace(rec[i])
		}
		return ""
	}

	if macIdx >= len(rec) {
		return Observation{}, false
	}
	mac, err := normaliseBSSID(rec[macIdx])
	if err != nil {
		return Observation{}, false
	}

	// Only WiFi rows; WiGLE files may also carry BT/BLE/GSM/LTE rows.
	if t := strings.ToUpper(get("type")); t != "" && t != "WIFI" {
		return Observation{}, false
	}

	lat, latErr := strconv.ParseFloat(get("currentlatitude"), 64)
	lon, lonErr := strconv.ParseFloat(get("currentlongitude"), 64)
	if latErr != nil || lonErr != nil || lat < -90 || lat > 90 || lon < -180 || lon > 180 {
		return Observation{}, false
	}

	o := Observation{
		BSSID:     mac,
		SSID:      get("ssid"),
		AuthMode:  get("authmode"),
		Latitude:  lat,
		Longitude: lon,
	}
	if v, err := strconv.Atoi(get("channel")); err == nil {
		o.Channel = v
	}
	if v, err := strconv.Atoi(get("rssi")); err == nil {
		o.RSSI = v
	}
	if v, err := strconv.ParseFloat(get("altitudemeters"), 64); err == nil {
		o.AltitudeM = v
	}
	if v, err := strconv.ParseFloat(get("accuracymeters"), 64); err == nil {
		o.AccuracyM = v
	}
	o.FirstSeen = parseFirstSeen(get("firstseen"))
	return o, true
}

func parseFirstSeen(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	for _, layout := range firstSeenLayouts {
		if ts, err := time.Parse(layout, s); err == nil {
			return ts.UTC()
		}
	}
	return time.Time{}
}

// Encryption buckets for triage. Open and WEP are the soft targets a
// reviewer cares about first.
const (
	EncOpen    = "open"
	EncWEP     = "wep"
	EncWPA     = "wpa"
	EncWPA2    = "wpa2"
	EncWPA3    = "wpa3"
	EncUnknown = "unknown"
)

// Classify maps a WiGLE AuthMode capability string to a coarse encryption
// bucket (one of the Enc* constants). Order matters: "WPA3"/"WPA2" both contain "WPA", so
// the strongest match is tested first. A capability with only [ESS]/[IBSS]
// (or empty) is an open network.
func Classify(authMode string) string {
	a := strings.ToUpper(authMode)
	switch {
	case strings.Contains(a, "WPA3") || strings.Contains(a, "SAE"):
		return EncWPA3
	case strings.Contains(a, "WPA2") || strings.Contains(a, "RSN"):
		return EncWPA2
	case strings.Contains(a, "WPA"):
		return EncWPA
	case strings.Contains(a, "WEP"):
		return EncWEP
	case a == "" || a == "[ESS]" || a == "[IBSS]" || strings.Contains(a, "OPEN"):
		return EncOpen
	default:
		// A capability string we don't recognise but that isn't obviously
		// WPA/WEP — e.g. exotic vendor tags. Don't claim it's open.
		return EncUnknown
	}
}

// SSIDCount is one entry in the most-common-SSID ranking.
type SSIDCount struct {
	SSID  string `json:"ssid"`
	Count int    `json:"count"`
}

// BoundingBox is the geographic extent of the fixed observations.
type BoundingBox struct {
	MinLatitude  float64 `json:"min_latitude"`
	MinLongitude float64 `json:"min_longitude"`
	MaxLatitude  float64 `json:"max_latitude"`
	MaxLongitude float64 `json:"max_longitude"`
	CenterLat    float64 `json:"center_latitude"`
	CenterLon    float64 `json:"center_longitude"`
}

// Summary is a security-oriented overview of a parsed wardrive.
type Summary struct {
	AccessPoints int `json:"access_points"` // total WiFi observations summarised
	UniqueBSSIDs int `json:"unique_bssids"` // distinct hardware addresses
	HiddenSSIDs  int `json:"hidden_ssids"`  // observations with an empty SSID

	// Encryption is the count per coarse bucket (open/wep/wpa/wpa2/wpa3/unknown).
	Encryption map[string]int `json:"encryption"`
	// SoftTargets is open + WEP — the networks worth a reviewer's first look.
	SoftTargets int `json:"soft_targets"`

	// Channels is observation count per 802.11 channel.
	Channels map[int]int `json:"channels"`

	// WithFix / NoFix split observations by whether they carry a real GPS
	// position (NoFix = 0,0, a "no lock" sentinel common in wardrive files).
	WithFix int `json:"with_fix"`
	NoFix   int `json:"no_fix"`
	// BBox is the extent over WithFix observations; nil when none have a fix.
	BBox *BoundingBox `json:"bounding_box,omitempty"`

	// TopSSIDs is the most frequently-seen non-empty SSIDs, highest first.
	TopSSIDs []SSIDCount `json:"top_ssids,omitempty"`
}

// Summarize computes a security-oriented overview of the observations.
// topN caps the TopSSIDs list (<=0 selects a default of 10).
func Summarize(obs []Observation, topN int) Summary {
	if topN <= 0 {
		topN = 10
	}
	s := Summary{
		AccessPoints: len(obs),
		Encryption:   map[string]int{},
		Channels:     map[int]int{},
	}
	bssids := make(map[string]struct{}, len(obs))
	ssidCounts := map[string]int{}
	var haveFix bool
	var minLat, minLon, maxLat, maxLon float64

	for _, o := range obs {
		bssids[o.BSSID] = struct{}{}
		if o.SSID == "" {
			s.HiddenSSIDs++
		} else {
			ssidCounts[o.SSID]++
		}

		bucket := Classify(o.AuthMode)
		s.Encryption[bucket]++
		if bucket == EncOpen || bucket == EncWEP {
			s.SoftTargets++
		}

		s.Channels[o.Channel]++

		// 0,0 is the conventional "no GPS lock" sentinel; exclude it from
		// the geographic extent rather than stretching the box to null island.
		if o.Latitude == 0 && o.Longitude == 0 {
			s.NoFix++
			continue
		}
		s.WithFix++
		if !haveFix {
			minLat, maxLat = o.Latitude, o.Latitude
			minLon, maxLon = o.Longitude, o.Longitude
			haveFix = true
		} else {
			minLat, maxLat = min(minLat, o.Latitude), max(maxLat, o.Latitude)
			minLon, maxLon = min(minLon, o.Longitude), max(maxLon, o.Longitude)
		}
	}
	s.UniqueBSSIDs = len(bssids)

	if haveFix {
		s.BBox = &BoundingBox{
			MinLatitude: minLat, MinLongitude: minLon,
			MaxLatitude: maxLat, MaxLongitude: maxLon,
			CenterLat: (minLat + maxLat) / 2, CenterLon: (minLon + maxLon) / 2,
		}
	}

	s.TopSSIDs = topSSIDs(ssidCounts, topN)
	return s
}

// topSSIDs returns the highest-count SSIDs, ties broken by name for a
// deterministic ranking.
func topSSIDs(counts map[string]int, topN int) []SSIDCount {
	ranked := make([]SSIDCount, 0, len(counts))
	for ssid, c := range counts {
		ranked = append(ranked, SSIDCount{SSID: ssid, Count: c})
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].Count != ranked[j].Count {
			return ranked[i].Count > ranked[j].Count
		}
		return ranked[i].SSID < ranked[j].SSID
	})
	if len(ranked) > topN {
		ranked = ranked[:topN]
	}
	return ranked
}
