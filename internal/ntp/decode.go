// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ntp decodes NTP / SNTP packets per RFC 5905 (v4),
// RFC 1305 (v3), and RFC 4330 (SNTPv4). NTP is the time-
// synchronisation protocol every networked device speaks
// against pool.ntp.org / its vendor pool / a local stratum-2
// server. Capturing NTP traffic is the workhorse primitive
// for time-sync forensics, NTP amplification DDoS detection
// (mode 7 / monlist abuse), log-timestamp correlation, and
// certificate-validity-window debugging.
//
// # Wrap-vs-native judgement
//
// Native. The NTP wire format is a fixed 48-byte header per
// RFC 5905 §7.3 with optional extension fields + authenticator
// at the end. Every field is a fixed-position integer or
// fixed-point seconds value. NTP timestamps are 64-bit (32-bit
// integer seconds since 1900-01-01 + 32-bit fractional
// seconds at 2^-32 resolution). Pasting a hex blob from
// Wireshark / tshark / tcpdump-of-123 capture is enough — no
// time server, no key material, no live network attach.
//
// # What this package covers
//
//   - Byte 0 broken out: LI (Leap Indicator: 0 no warning /
//     1 +61sec / 2 -61sec / 3 alarm-unsynchronised), VN
//     (Version Number — 1, 2, 3, 4), Mode (1 symmetric
//     active / 2 symmetric passive / 3 client / 4 server /
//     5 broadcast / 6 NTP control message / 7 private use).
//   - Stratum (1=primary reference / 2-15=secondary /
//     16=unsynchronised / 17-255=reserved) with name lookup.
//   - Poll (signed log2 seconds — the maximum poll interval
//     between successive messages, rendered as both raw log2
//     and as seconds).
//   - Precision (signed log2 seconds — the precision of the
//     local clock, similarly rendered).
//   - Root Delay + Root Dispersion as 32-bit NTPv3 short-
//     format fixed-point seconds (16-bit integer + 16-bit
//     fractional, surfaced as float64 seconds).
//   - Reference ID with stratum-dependent interpretation:
//   - Stratum 0: Kiss-o'-Death (KoD) 4-character code
//     (ACST/AUTH/AUTO/BCST/CRYP/DENY/DROP/RSTR/INIT/
//     MCST/NKEY/NTSN/RATE/RMOT/STEP) per RFC 5905 §7.4.
//   - Stratum 1: 4-character ASCII source identifier
//     (GPS/PPS/NIST/ACTS/WWV/WWVB/WWVH/DCF/MSF/DTOC/PTB/
//     USNO/LORC) per RFC 5905 §7.3.
//   - Stratum 2-15: IPv4 of the upstream server (or the
//     MD5 hash of the upstream IPv6 if IPv6 is being used,
//     but we report the 4 bytes as IPv4 for the common
//     case).
//   - 4 NTP timestamps: Reference (last time the local clock
//     was set), Origin / T1 (when client sent the request),
//     Receive / T2 (when server received the request),
//     Transmit / T3 (when server sent the response). Each
//     is surfaced as both the raw 64-bit NTP value and an
//     RFC 3339 string in UTC.
//   - Optional NTPv4 extension fields (RFC 5906) — count +
//     raw hex for each.
//   - Optional authenticator (key ID + MAC) — detected by
//     remaining bytes after the header + extensions; the
//     key ID and the MAC hex are surfaced (MAC length 16
//     bytes = MD5, 20 bytes = SHA-1).
//
// # What this package does NOT cover (deliberately out of scope)
//
//   - NTP control message (mode 6) deep decode — the RFC 1305
//     §3.5 control message format is its own ~150 LoC parser
//     (op-code + sequence + status + assoc ID + offset +
//     count + data); the envelope is recognised and labeled
//     but the body is surfaced as raw hex.
//   - NTP mode 7 (private use, vendor-specific) — historically
//     abused for monlist DDoS amplification; we label it but
//     don't dissect the vendor body.
//   - Autokey (RFC 5906) authentication — extension fields
//     are counted but the certificate / cookie / signature
//     contents are not validated.
//   - NTS (Network Time Security, RFC 8915) — newer
//     authenticated-NTP variant; the cookie/AEAD extension
//     fields are recognised by tag but the contents are
//     surfaced as raw hex (decryption requires session keys).
//   - SNTP simple-client behaviour — the wire format is
//     identical to NTP so the same decoder applies.
package ntp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"strings"
	"time"
)

// Packet is the decoded NTP message view.
type Packet struct {
	HexInput          string         `json:"hex_input"`
	LeapIndicator     int            `json:"leap_indicator"`
	LeapIndicatorName string         `json:"leap_indicator_name"`
	VersionNumber     int            `json:"version_number"`
	Mode              int            `json:"mode"`
	ModeName          string         `json:"mode_name"`
	Stratum           int            `json:"stratum"`
	StratumName       string         `json:"stratum_name"`
	PollIntervalLog2  int            `json:"poll_interval_log2"`
	PollIntervalSec   float64        `json:"poll_interval_sec"`
	PrecisionLog2     int            `json:"precision_log2"`
	PrecisionSec      float64        `json:"precision_sec"`
	RootDelaySec      float64        `json:"root_delay_sec"`
	RootDispersionSec float64        `json:"root_dispersion_sec"`
	ReferenceID       *ReferenceID   `json:"reference_id"`
	ReferenceTime     *NTPTimestamp  `json:"reference_time,omitempty"`
	OriginTime        *NTPTimestamp  `json:"origin_time,omitempty"`
	ReceiveTime       *NTPTimestamp  `json:"receive_time,omitempty"`
	TransmitTime      *NTPTimestamp  `json:"transmit_time,omitempty"`
	ExtensionCount    int            `json:"extension_count,omitempty"`
	ExtensionsHex     []string       `json:"extensions_hex,omitempty"`
	Authenticator     *Authenticator `json:"authenticator,omitempty"`
}

// ReferenceID is the 4-byte Reference Identifier field
// interpreted per the current stratum.
type ReferenceID struct {
	RawHex         string `json:"raw_hex"`
	Interpretation string `json:"interpretation"`
	ASCIICode      string `json:"ascii_code,omitempty"`
	ASCIIName      string `json:"ascii_name,omitempty"`
	KoDCode        string `json:"kod_code,omitempty"`
	KoDName        string `json:"kod_name,omitempty"`
	IPv4           string `json:"ipv4,omitempty"`
}

// NTPTimestamp is one decoded 64-bit NTP timestamp.
//
// The NTP epoch starts at 1900-01-01 00:00:00 UTC; Unix
// epoch is 1970-01-01 00:00:00 UTC. The offset between the
// two is 2,208,988,800 seconds.
type NTPTimestamp struct {
	Seconds     uint32  `json:"seconds_since_1900"`
	Fraction    uint32  `json:"fraction"`
	UnixSeconds int64   `json:"unix_seconds,omitempty"`
	FractionSec float64 `json:"fraction_sec"`
	RFC3339     string  `json:"rfc3339,omitempty"`
	IsZero      bool    `json:"is_zero,omitempty"`
}

// Authenticator carries the optional Key Identifier + MAC
// at the tail of an authenticated NTP packet (RFC 5905 §7.5
// + RFC 1305 §3.2).
type Authenticator struct {
	KeyID  uint32 `json:"key_id"`
	MACHex string `json:"mac_hex"`
	MACAlg string `json:"mac_algorithm"`
}

// ntpEpochOffset is the difference between the NTP epoch
// (1900-01-01 00:00:00 UTC) and the Unix epoch (1970-01-01
// 00:00:00 UTC) in seconds.
const ntpEpochOffset = uint32(2208988800)

// Decode parses a hex-encoded NTP packet.
func Decode(hexBlob string) (*Packet, error) {
	b, err := parseHex(hexBlob)
	if err != nil {
		return nil, err
	}
	return DecodeBytes(b)
}

// DecodeBytes parses a raw NTP packet.
func DecodeBytes(b []byte) (*Packet, error) {
	if len(b) < 48 {
		return nil, fmt.Errorf(
			"ntp: packet too short (%d bytes); NTP header is fixed at 48 bytes",
			len(b))
	}
	p := &Packet{
		HexInput: strings.ToUpper(hex.EncodeToString(b)),
	}
	flags := b[0]
	p.LeapIndicator = int(flags >> 6)
	p.LeapIndicatorName = leapIndicatorName(p.LeapIndicator)
	p.VersionNumber = int((flags >> 3) & 0x07)
	p.Mode = int(flags & 0x07)
	p.ModeName = modeName(p.Mode)
	p.Stratum = int(b[1])
	p.StratumName = stratumName(p.Stratum)
	p.PollIntervalLog2 = int(int8(b[2]))
	p.PollIntervalSec = math.Pow(2, float64(p.PollIntervalLog2))
	p.PrecisionLog2 = int(int8(b[3]))
	p.PrecisionSec = math.Pow(2, float64(p.PrecisionLog2))
	p.RootDelaySec = decodeShortFixed(b[4:8])
	p.RootDispersionSec = decodeShortFixed(b[8:12])
	p.ReferenceID = decodeReferenceID(b[12:16], p.Stratum)
	p.ReferenceTime = decodeNTPTimestamp(b[16:24])
	p.OriginTime = decodeNTPTimestamp(b[24:32])
	p.ReceiveTime = decodeNTPTimestamp(b[32:40])
	p.TransmitTime = decodeNTPTimestamp(b[40:48])

	// Walk any trailing extension fields + authenticator.
	rest := b[48:]
	if len(rest) > 0 {
		decodeTrailing(p, rest)
	}
	return p, nil
}

// decodeShortFixed reads a 32-bit NTPv3 short-format fixed-
// point value: 16-bit integer seconds (high half) + 16-bit
// fractional seconds (low half / 65536).
func decodeShortFixed(b []byte) float64 {
	if len(b) < 4 {
		return 0
	}
	intPart := int16(binary.BigEndian.Uint16(b[0:2]))
	fracPart := binary.BigEndian.Uint16(b[2:4])
	return float64(intPart) + float64(fracPart)/65536.0
}

// decodeNTPTimestamp reads a 64-bit NTP timestamp.
func decodeNTPTimestamp(b []byte) *NTPTimestamp {
	if len(b) < 8 {
		return nil
	}
	secs := binary.BigEndian.Uint32(b[0:4])
	frac := binary.BigEndian.Uint32(b[4:8])
	ts := &NTPTimestamp{
		Seconds:     secs,
		Fraction:    frac,
		FractionSec: float64(frac) / float64(1<<32),
	}
	if secs == 0 && frac == 0 {
		ts.IsZero = true
		return ts
	}
	// NTP era 0 covers 1900-01-01 through 2036-02-07 06:28:15.
	// After that, the 32-bit second counter wraps. We always
	// assume era 0 for now (the standard caveat).
	if secs >= ntpEpochOffset {
		ts.UnixSeconds = int64(secs - ntpEpochOffset)
		t := time.Unix(ts.UnixSeconds, int64(ts.FractionSec*1e9)).UTC()
		ts.RFC3339 = t.Format(time.RFC3339Nano)
	}
	return ts
}

// decodeReferenceID interprets the 4-byte Reference ID by
// current stratum.
func decodeReferenceID(b []byte, stratum int) *ReferenceID {
	ref := &ReferenceID{
		RawHex: strings.ToUpper(hex.EncodeToString(b)),
	}
	switch {
	case stratum == 0:
		ref.Interpretation = "Kiss-o'-Death code (stratum 0)"
		ref.KoDCode = sanitizeASCII(b)
		ref.KoDName = kodCodeName(ref.KoDCode)
	case stratum == 1:
		ref.Interpretation = "Primary source identifier (stratum 1)"
		ref.ASCIICode = sanitizeASCII(b)
		ref.ASCIIName = primarySourceName(ref.ASCIICode)
	case stratum >= 2 && stratum <= 15:
		ref.Interpretation = fmt.Sprintf("Upstream IPv4 reference (stratum %d)", stratum)
		ref.IPv4 = net.IP(b).String()
	default:
		ref.Interpretation = "Reserved / unsynchronised"
	}
	return ref
}

// decodeTrailing walks bytes past the 48-byte header and
// interprets either extension fields (RFC 5906 — each is
// [type:2][length:2][value:length]) or an authenticator
// (the last 20 or 24 bytes per RFC 5905 §7.5).
func decodeTrailing(p *Packet, rest []byte) {
	// Authenticator detection: total length 20 (4-byte key
	// ID + 16-byte MD5 MAC) or 24 (4-byte key ID + 20-byte
	// SHA-1 MAC) at the tail.
	hasAuthMD5 := len(rest) == 20 || (len(rest) > 20 && (len(rest)-20)%4 == 0 && hasExtensionShape(rest[:len(rest)-20]))
	hasAuthSHA1 := len(rest) == 24 || (len(rest) > 24 && (len(rest)-24)%4 == 0 && hasExtensionShape(rest[:len(rest)-24]))
	var authStart int
	switch {
	case hasAuthMD5:
		authStart = len(rest) - 20
	case hasAuthSHA1:
		authStart = len(rest) - 24
	default:
		authStart = len(rest)
	}
	extBytes := rest[:authStart]
	for len(extBytes) >= 4 {
		length := int(binary.BigEndian.Uint16(extBytes[2:4]))
		if length < 4 || length > len(extBytes) {
			break
		}
		p.ExtensionCount++
		p.ExtensionsHex = append(p.ExtensionsHex, strings.ToUpper(hex.EncodeToString(extBytes[:length])))
		extBytes = extBytes[length:]
	}
	if authStart < len(rest) {
		auth := rest[authStart:]
		a := &Authenticator{
			KeyID:  binary.BigEndian.Uint32(auth[0:4]),
			MACHex: strings.ToUpper(hex.EncodeToString(auth[4:])),
		}
		switch len(auth) {
		case 20:
			a.MACAlg = "MD5 (16-byte MAC)"
		case 24:
			a.MACAlg = "SHA-1 (20-byte MAC)"
		default:
			a.MACAlg = fmt.Sprintf("Unknown (%d-byte MAC)", len(auth)-4)
		}
		p.Authenticator = a
	}
}

// hasExtensionShape returns true when b looks like a series
// of well-formed RFC 5906 extension fields ([type:2][len:2]
// [value:len-4]).
func hasExtensionShape(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	for len(b) >= 4 {
		length := int(binary.BigEndian.Uint16(b[2:4]))
		if length < 4 || length > len(b) {
			return false
		}
		b = b[length:]
	}
	return len(b) == 0
}

// sanitizeASCII renders the 4-byte ASCII Reference ID,
// stripping NULs at the tail and replacing any non-printable
// bytes with '?' so the output stays inspectable.
func sanitizeASCII(b []byte) string {
	out := make([]byte, 0, 4)
	for _, c := range b {
		if c == 0 {
			break
		}
		if c < 0x20 || c > 0x7E {
			out = append(out, '?')
			continue
		}
		out = append(out, c)
	}
	return string(out)
}

func leapIndicatorName(li int) string {
	switch li {
	case 0:
		return "No warning"
	case 1:
		return "Last minute has 61 seconds"
	case 2:
		return "Last minute has 59 seconds"
	case 3:
		return "Alarm condition (clock not synchronised)"
	}
	return ""
}

func modeName(m int) string {
	switch m {
	case 0:
		return "Reserved"
	case 1:
		return "Symmetric active"
	case 2:
		return "Symmetric passive"
	case 3:
		return "Client"
	case 4:
		return "Server"
	case 5:
		return "Broadcast"
	case 6:
		return "NTP control message"
	case 7:
		return "Private use (reserved)"
	}
	return fmt.Sprintf("Unknown (mode %d)", m)
}

func stratumName(s int) string {
	switch {
	case s == 0:
		return "Unspecified / invalid (Kiss-o'-Death)"
	case s == 1:
		return "Primary reference (directly attached source)"
	case s >= 2 && s <= 15:
		return fmt.Sprintf("Secondary reference (synced via stratum %d server)", s-1)
	case s == 16:
		return "Unsynchronised"
	}
	return fmt.Sprintf("Reserved (%d)", s)
}

// primarySourceName labels the 4-character ASCII codes that
// stratum-1 servers use to identify their primary reference
// source (RFC 5905 §7.3, IANA NTP Reference Identifiers).
func primarySourceName(code string) string {
	switch strings.ToUpper(code) {
	case "GOES":
		return "Geosynchronous Operational Environmental Satellite"
	case "GPS":
		return "Global Positioning System"
	case "GAL":
		return "Galileo Positioning System"
	case "PPS":
		return "Generic pulse-per-second"
	case "IRIG":
		return "Inter-Range Instrumentation Group"
	case "WWVB":
		return "LF Radio WWVB Fort Collins, CO USA"
	case "DCF", "DCF77":
		return "LF Radio DCF77 Mainflingen, DE"
	case "HBG":
		return "LF Radio HBG Prangins, HB"
	case "MSF":
		return "LF Radio MSF Anthorn, UK"
	case "JJY":
		return "LF Radio JJY Fukushima, JP"
	case "LORC":
		return "MF Radio LORAN-C station"
	case "TDF":
		return "MF Radio Allouis, FR"
	case "CHU":
		return "HF Radio CHU Ottawa, ON"
	case "WWV":
		return "HF Radio WWV Ft. Collins, CO USA"
	case "WWVH":
		return "HF Radio WWVH Kauai, HI USA"
	case "NIST":
		return "NIST telephone modem"
	case "ACTS":
		return "NIST telephone modem (ACTS)"
	case "USNO":
		return "USNO telephone modem"
	case "PTB":
		return "European telephone modem (PTB)"
	case "MRS":
		return "Multi-reference source"
	case "ROA":
		return "ROA"
	case "DTOC":
		return "(historical / unused)"
	}
	return ""
}

// kodCodeName labels the Kiss-o'-Death reason codes (RFC
// 5905 §7.4) that stratum-0 servers use to tell clients to
// back off / reconnect / fail.
func kodCodeName(code string) string {
	switch strings.ToUpper(code) {
	case "ACST":
		return "The association belongs to a unicast server"
	case "AUTH":
		return "Server authentication failed"
	case "AUTO":
		return "Autokey sequence failed"
	case "BCST":
		return "The association belongs to a broadcast server"
	case "CRYP":
		return "Cryptographic authentication or identification failed"
	case "DENY":
		return "Access denied by remote server"
	case "DROP":
		return "Lost peer in symmetric mode"
	case "RSTR":
		return "Access denied due to local policy"
	case "INIT":
		return "The association has not yet synchronised for the first time"
	case "MCST":
		return "The association belongs to a dynamically-discovered server"
	case "NKEY":
		return "No key found"
	case "NTSN":
		return "Network Time Security (NTS) negative-acknowledgment"
	case "RATE":
		return "Rate exceeded (back off, slow your polls)"
	case "RMOT":
		return "Alteration of association from a remote host"
	case "STEP":
		return "A step change in system time has occurred"
	}
	return ""
}

func parseHex(s string) ([]byte, error) {
	s = stripSeparators(s)
	if s == "" {
		return nil, fmt.Errorf("ntp: empty hex input")
	}
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("ntp: invalid hex: %w", err)
	}
	return b, nil
}

func stripSeparators(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case ':', '-', '_', ' ', '\t', '\n', '\r':
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
