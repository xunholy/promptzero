// SPDX-License-Identifier: AGPL-3.0-or-later

// Package syslog decodes syslog messages in both the modern
// RFC 5424 (IETF) format and the legacy RFC 3164 (BSD)
// format. Syslog is the lingua franca of log aggregation —
// every operating system, network device, container runtime,
// and SIEM agent emits it.
//
// # Wrap-vs-native judgement
//
// Native. Both syslog formats are plain ASCII text with a
// well-bounded grammar. Pasting a line from journalctl /
// /var/log/messages / a Splunk extraction / a Wireshark
// follow-stream of UDP/514 is enough — no log shipper, no
// SIEM agent, no live network attach.
//
// # What this package covers
//
//   - **PRI** (priority value) — the leading `<NNN>` integer
//     in every syslog message broken out as facility (kern,
//     user, mail, daemon, auth, syslog, lpr, news, uucp,
//     cron, authpriv, ftp, ntp, audit, alert, clock daemon,
//     local0..local7) + severity (Emergency / Alert /
//     Critical / Error / Warning / Notice / Informational /
//     Debug) name lookup per RFC 5424 §6.2.
//
//   - **Format auto-detection** — the byte immediately after
//     `<PRI>` distinguishes the two formats: a digit means
//     RFC 5424 (the `VERSION` field, always `1` in current
//     practice); anything else is treated as RFC 3164.
//
//   - **RFC 5424 IETF format** (modern, structured):
//
//     <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID
//     [SD-ID-1@PEN key1="val1" key2="val2"] [SD-ID-2 ...]
//     MSG
//
//     Fields use `-` for nil. TIMESTAMP is RFC 3339 with
//     optional sub-second precision and offset. Structured
//     data is a list of `[SD-ID PARAM-NAME="value" ...]`
//     groups; the decoder walks them into named entries
//     with key/value maps.
//
//   - **RFC 3164 BSD format** (legacy):
//
//     <PRI>TIMESTAMP HOSTNAME TAG[PID]: MSG
//
//     TIMESTAMP is `Mmm dd hh:mm:ss` (with the year
//     missing — operators infer it). TAG is the process
//     name; if it ends in `[NNN]:` the PID is split out.
//
//   - **Severity highlighting** — the integer severity is
//     surfaced both as a number and a name; the operationally
//     important "Critical / Alert / Emergency" levels are
//     trivially greppable in the JSON output.
//
// # What this package does NOT cover (deliberately out of scope)
//
//   - Transport framing: RFC 6587 (TCP framing with `\n` or
//     octet count) and RFC 5425 (TLS) — operators feed a
//     single message at a time after stripping the transport
//     wrapper.
//   - Cisco / Juniper / vendor-extension formats (e.g.
//     `*Mar 24 12:34:56.789 UTC: %SYS-5-CONFIG_I:`) — the
//     PRI + message body are still extracted, but the
//     vendor-specific fields (sequence number, mnemonic,
//     facility-severity-mnemonic) are exposed as part of the
//     message text rather than broken out.
//   - CEF / LEEF / Common Event Format payloads — these are
//     wrappers around the syslog message body and warrant a
//     separate Spec.
//   - Octet escaping inside structured-data parameter values
//     (`\\"`, `\\\\`, `\\]`) — handled per RFC 5424 §6.3.3.
//     Edge cases with unbalanced escapes are surfaced as-is.
package syslog

import (
	"fmt"
	"strconv"
	"strings"
)

// Message is the decoded syslog message view.
type Message struct {
	Format         string                  `json:"format"`
	Raw            string                  `json:"raw"`
	Priority       int                     `json:"priority"`
	Facility       int                     `json:"facility"`
	FacilityName   string                  `json:"facility_name"`
	Severity       int                     `json:"severity"`
	SeverityName   string                  `json:"severity_name"`
	Version        int                     `json:"version,omitempty"`
	Timestamp      string                  `json:"timestamp,omitempty"`
	Hostname       string                  `json:"hostname,omitempty"`
	AppName        string                  `json:"app_name,omitempty"`
	ProcID         string                  `json:"proc_id,omitempty"`
	MsgID          string                  `json:"msg_id,omitempty"`
	Tag            string                  `json:"tag,omitempty"`
	StructuredData []StructuredDataElement `json:"structured_data,omitempty"`
	Message        string                  `json:"message,omitempty"`
}

// StructuredDataElement is one `[SD-ID@PEN key="val" ...]`
// group in an RFC 5424 message.
type StructuredDataElement struct {
	ID         string            `json:"id"`
	Parameters map[string]string `json:"parameters"`
}

// Decode parses one syslog message. Both RFC 5424 and RFC
// 3164 are auto-detected.
func Decode(line string) (*Message, error) {
	s := strings.TrimSpace(line)
	if s == "" {
		return nil, fmt.Errorf("syslog: empty input")
	}
	if !strings.HasPrefix(s, "<") {
		return nil, fmt.Errorf("syslog: message must start with '<PRI>'")
	}
	end := strings.Index(s, ">")
	if end < 0 || end > 4 {
		return nil, fmt.Errorf("syslog: malformed PRI (expected '<NNN>' in first 5 chars)")
	}
	pri, err := strconv.Atoi(s[1:end])
	if err != nil {
		return nil, fmt.Errorf("syslog: PRI not numeric: %w", err)
	}
	if pri < 0 || pri > 191 {
		return nil, fmt.Errorf("syslog: PRI %d out of 0..191", pri)
	}
	m := &Message{
		Raw:          s,
		Priority:     pri,
		Facility:     pri / 8,
		FacilityName: facilityName(pri / 8),
		Severity:     pri % 8,
		SeverityName: severityName(pri % 8),
	}
	rest := s[end+1:]
	if len(rest) > 0 && rest[0] >= '0' && rest[0] <= '9' {
		// RFC 5424: digit after '>' is the version
		if err := decodeRFC5424(m, rest); err != nil {
			return nil, fmt.Errorf("syslog: RFC 5424: %w", err)
		}
		return m, nil
	}
	if err := decodeRFC3164(m, rest); err != nil {
		return nil, fmt.Errorf("syslog: RFC 3164: %w", err)
	}
	return m, nil
}

// decodeRFC5424 parses the IETF format:
//
//	VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP
//	MSGID SP STRUCTURED-DATA [SP MSG]
//
// Any field may be `-` to indicate nil.
func decodeRFC5424(m *Message, s string) error {
	m.Format = "RFC 5424 (IETF)"
	// Pop fields up to MSGID — they're all space-delimited.
	parts := splitN(s, " ", 7)
	if len(parts) < 6 {
		return fmt.Errorf("missing required fields (need at least version + timestamp + hostname + app-name + procid + msgid)")
	}
	v, err := strconv.Atoi(parts[0])
	if err != nil {
		return fmt.Errorf("version not numeric: %w", err)
	}
	m.Version = v
	m.Timestamp = nilDash(parts[1])
	m.Hostname = nilDash(parts[2])
	m.AppName = nilDash(parts[3])
	m.ProcID = nilDash(parts[4])
	m.MsgID = nilDash(parts[5])
	if len(parts) < 7 {
		// No structured data, no message.
		return nil
	}
	rest := parts[6]
	sd, msg, err := splitStructuredData(rest)
	if err != nil {
		return err
	}
	m.StructuredData = sd
	m.Message = strings.TrimPrefix(msg, " ")
	return nil
}

// splitStructuredData walks `[...] [...] [...] MSG` returning
// the parsed elements + the trailing message (which is
// everything after the last balanced ']').
func splitStructuredData(s string) ([]StructuredDataElement, string, error) {
	if strings.HasPrefix(s, "-") {
		// Nil structured data.
		rest := strings.TrimPrefix(s, "-")
		return nil, strings.TrimPrefix(rest, " "), nil
	}
	if !strings.HasPrefix(s, "[") {
		// Treat as a message with no structured data.
		return nil, s, nil
	}
	var out []StructuredDataElement
	for strings.HasPrefix(s, "[") {
		end := findSDEnd(s)
		if end < 0 {
			return nil, "", fmt.Errorf("unterminated structured-data block")
		}
		body := s[1:end]
		s = s[end+1:]
		sd, err := parseSDElement(body)
		if err != nil {
			return nil, "", err
		}
		out = append(out, sd)
	}
	return out, strings.TrimPrefix(s, " "), nil
}

// findSDEnd returns the index of the closing ']' of an
// `[SD-ID ...]` block at the start of s, accounting for
// backslash-escaped `]` inside parameter values.
func findSDEnd(s string) int {
	if !strings.HasPrefix(s, "[") {
		return -1
	}
	inQuote := false
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if i+1 < len(s) {
				i++
			}
		case '"':
			inQuote = !inQuote
		case ']':
			if !inQuote {
				return i
			}
		}
	}
	return -1
}

// parseSDElement parses an `SD-ID PARAM="value" PARAM="value"`
// body (no outer brackets).
func parseSDElement(body string) (StructuredDataElement, error) {
	sp := strings.IndexByte(body, ' ')
	if sp < 0 {
		// No parameters.
		return StructuredDataElement{ID: body, Parameters: map[string]string{}}, nil
	}
	id := body[:sp]
	rest := body[sp+1:]
	params := map[string]string{}
	i := 0
	for i < len(rest) {
		// Skip whitespace.
		for i < len(rest) && rest[i] == ' ' {
			i++
		}
		// Read PARAM-NAME up to '='.
		eq := strings.IndexByte(rest[i:], '=')
		if eq < 0 {
			break
		}
		name := rest[i : i+eq]
		i += eq + 1
		if i >= len(rest) || rest[i] != '"' {
			return StructuredDataElement{}, fmt.Errorf("expected '\"' after %q=", name)
		}
		i++ // skip opening quote
		var value strings.Builder
		for i < len(rest) {
			c := rest[i]
			if c == '\\' && i+1 < len(rest) {
				value.WriteByte(rest[i+1])
				i += 2
				continue
			}
			if c == '"' {
				i++
				break
			}
			value.WriteByte(c)
			i++
		}
		params[name] = value.String()
	}
	return StructuredDataElement{ID: id, Parameters: params}, nil
}

// decodeRFC3164 parses the BSD format:
//
//	TIMESTAMP SP HOSTNAME SP TAG[PID]: MSG
//
// TIMESTAMP is "Mmm dd hh:mm:ss" (15 chars). The TAG may
// contain `[PID]` immediately before the colon.
func decodeRFC3164(m *Message, s string) error {
	m.Format = "RFC 3164 (BSD)"
	// Try to peel off a 15-char timestamp like "Jan  2 03:04:05".
	if len(s) >= 15 && bsdTimestampLooksLike(s[:15]) {
		m.Timestamp = s[:15]
		s = strings.TrimPrefix(s[15:], " ")
	}
	// Hostname (up to next space).
	sp := strings.IndexByte(s, ' ')
	if sp < 0 {
		m.Message = s
		return nil
	}
	m.Hostname = s[:sp]
	rest := strings.TrimPrefix(s[sp+1:], " ")
	// TAG and optional [PID] up to ':'.
	colon := strings.IndexByte(rest, ':')
	if colon < 0 {
		m.Message = rest
		return nil
	}
	tag := rest[:colon]
	m.Message = strings.TrimPrefix(rest[colon+1:], " ")
	if open := strings.IndexByte(tag, '['); open >= 0 {
		closeb := strings.IndexByte(tag, ']')
		if closeb > open {
			m.Tag = tag[:open]
			m.ProcID = tag[open+1 : closeb]
		} else {
			m.Tag = tag
		}
	} else {
		m.Tag = tag
	}
	return nil
}

// bsdTimestampLooksLike returns true when s looks like a
// BSD-style timestamp `Mmm dd hh:mm:ss` (case-insensitive on
// the month abbreviation; day may be space-padded).
func bsdTimestampLooksLike(s string) bool {
	if len(s) != 15 {
		return false
	}
	months := []string{"Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
	ok := false
	for _, m := range months {
		if s[:3] == m {
			ok = true
			break
		}
	}
	if !ok {
		return false
	}
	if s[3] != ' ' {
		return false
	}
	// Day: one digit + space, or two digits.
	if s[4] != ' ' && (s[4] < '0' || s[4] > '9') {
		return false
	}
	if s[5] < '0' || s[5] > '9' {
		return false
	}
	if s[6] != ' ' {
		return false
	}
	// Time: HH:MM:SS
	return s[9] == ':' && s[12] == ':'
}

// splitN behaves like strings.SplitN but treats the empty
// string as a single empty field rather than an empty slice.
func splitN(s, sep string, n int) []string {
	return strings.SplitN(s, sep, n)
}

func nilDash(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

func facilityName(f int) string {
	switch f {
	case 0:
		return "kern (kernel messages)"
	case 1:
		return "user (user-level messages)"
	case 2:
		return "mail (mail system)"
	case 3:
		return "daemon (system daemons)"
	case 4:
		return "auth (security / authorization)"
	case 5:
		return "syslog (syslogd internal)"
	case 6:
		return "lpr (line-printer subsystem)"
	case 7:
		return "news (network news subsystem)"
	case 8:
		return "uucp (UUCP subsystem)"
	case 9:
		return "cron (clock daemon)"
	case 10:
		return "authpriv (security / authorization, private)"
	case 11:
		return "ftp (FTP daemon)"
	case 12:
		return "ntp (NTP subsystem)"
	case 13:
		return "audit (log audit)"
	case 14:
		return "alert (log alert)"
	case 15:
		return "clock (clock daemon)"
	case 16, 17, 18, 19, 20, 21, 22, 23:
		return fmt.Sprintf("local%d", f-16)
	}
	return fmt.Sprintf("Reserved (facility %d)", f)
}

func severityName(s int) string {
	switch s {
	case 0:
		return "Emergency (system unusable)"
	case 1:
		return "Alert (action must be taken immediately)"
	case 2:
		return "Critical (critical conditions)"
	case 3:
		return "Error (error conditions)"
	case 4:
		return "Warning (warning conditions)"
	case 5:
		return "Notice (normal but significant)"
	case 6:
		return "Informational"
	case 7:
		return "Debug"
	}
	return fmt.Sprintf("Reserved (severity %d)", s)
}
