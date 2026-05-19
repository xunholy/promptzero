// syslog.go — host-side syslog message dissector Spec,
// delegating to the internal/syslog package for the walker
// proper.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/syslog"
)

func init() { //nolint:gochecknoinits
	Register(syslogMessageDecodeSpec)
}

var syslogMessageDecodeSpec = Spec{
	Name: "syslog_message_decode",
	Description: "Decode a syslog message in either the modern RFC 5424 (IETF) format or " +
		"the legacy RFC 3164 (BSD) format. Syslog is the lingua franca of log aggregation " +
		"— every operating system, network device, container runtime, and SIEM agent emits " +
		"it. Workhorse blue-team primitive for log triage, alert generation, and SIEM " +
		"correlation. Decodes:\n\n" +
		"- **PRI** (priority value) — the leading `<NNN>` integer broken out as facility + " +
		"severity name lookup per RFC 5424 §6.2:\n" +
		"  - **Facility** (24 entries): kern (0) / user (1) / mail (2) / daemon (3) / " +
		"auth (4) / syslog (5) / lpr (6) / news (7) / uucp (8) / cron (9) / authpriv " +
		"(10) / ftp (11) / ntp (12) / audit (13) / alert (14) / clock (15) / local0..7 " +
		"(16-23).\n" +
		"  - **Severity** (8 levels): Emergency (system unusable) / Alert (action " +
		"required immediately) / Critical (critical conditions) / Error / Warning / " +
		"Notice (normal but significant) / Informational / Debug.\n" +
		"- **Format auto-detection** — the byte immediately after `<PRI>` distinguishes " +
		"the two formats: a digit means RFC 5424 (the VERSION field, always `1` in " +
		"current practice); anything else is treated as RFC 3164.\n" +
		"- **RFC 5424 IETF format**:\n" +
		"\n" +
		"      <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID\n" +
		"      [SD-ID-1@PEN key1=\"val1\" key2=\"val2\"] [SD-ID-2 ...]\n" +
		"      MSG\n" +
		"\n" +
		"  Fields use `-` for nil. TIMESTAMP is RFC 3339 with optional sub-second " +
		"precision + offset. Structured-data parameters are walked with backslash-" +
		"escape handling for `\\\"` and `\\]` inside values; SD-ID supports the " +
		"`@PEN` (Private Enterprise Number) suffix for vendor-specific extensions.\n" +
		"- **RFC 3164 BSD format**:\n" +
		"\n" +
		"      <PRI>TIMESTAMP HOSTNAME TAG[PID]: MSG\n" +
		"\n" +
		"  TIMESTAMP is `Mmm dd hh:mm:ss` (15 chars; day may be space-padded). The TAG " +
		"may end in `[NNN]` to carry the originating process ID, which is split out into " +
		"a separate field.\n" +
		"- **Severity highlighting** — the integer severity is surfaced both as a number " +
		"and a name; the operationally-important Emergency / Alert / Critical levels are " +
		"trivially greppable in the JSON output for SIEM alerting pipelines.\n\n" +
		"Pure offline parser — operators paste a line from journalctl / " +
		"/var/log/messages / a Splunk extraction / a Wireshark follow-stream of UDP/514 / " +
		"a SIEM raw-event view and inspect every documented field without re-shipping " +
		"the log line. Complements dns_packet_decode + dhcp_packet_decode + " +
		"snmp_packet_decode + ntp_packet_decode for the complete observability decode " +
		"stack.\n\n" +
		"Out of scope (deferred to future iterations): RFC 6587 TCP framing / RFC 5425 " +
		"TLS transport (feed a single message at a time after stripping wrapper); " +
		"Cisco / Juniper / vendor-specific message bodies (PRI + raw body extracted but " +
		"vendor mnemonics not broken out); CEF / LEEF / Common Event Format payloads " +
		"(separate Spec); octet-escape edge cases inside SD parameter values surfaced " +
		"as-is.\n\n" +
		"Source: docs/catalog/gap-analysis.md (log-aggregation decode space — universally " +
		"applicable blue-team primitive). Wrap-vs-native: native — RFC 5424 + 3164 are " +
		"fully public ASCII grammars, dispatch is a switch on the byte after the PRI " +
		"closer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"line":{"type":"string","description":"One syslog message starting with '<PRI>'. RFC 5424 (digit immediately after '>') or RFC 3164 (anything else) is auto-detected."}
		},
		"required":["line"]
	}`),
	Required:  []string{"line"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   syslogMessageDecodeHandler,
}

func syslogMessageDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "line")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("syslog_message_decode: 'line' is required")
	}
	res, err := syslog.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("syslog_message_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
