// hicp_decode.go — host-side HICP (HMS Anybus Host IP Configuration
// Protocol) decoder Spec, delegating to internal/hicp.
//
// Wrap-vs-native: native — a small text protocol (command keyword + a
// "Key = value;" list); a prefix check + key-value split, stdlib only.
// The HMS-Anybus device-discovery / reconfiguration decoder, joining the
// OT/ICS family (modbus/dnp3/iec104/s7comm/enip/profinetdcp). Surfaces the
// industrial-asset inventory + the unauthenticated-reconfig signal.
// Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/hicp"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(hicpDecodeSpec)
}

var hicpDecodeSpec = Spec{
	Name: "hicp_decode",
	Description: "Decode **HICP** (HMS Anybus Host IP Configuration Protocol, UDP 3250) — the protocol for " +
		"discovering and (re)configuring **industrial Ethernet gateway modules** (HMS Anybus / X-gateway). " +
		"Joins the project's OT/ICS decoder family (`modbus`, `dnp3`, `iec104`, `s7comm`, `enip`, " +
		"`profinetdcp`, `opcua`, `ethercat`, `knxnetip`) as an industrial **device-discovery** decoder — the " +
		"HMS-Anybus analogue of `profinetdcp`. HICP is an OT attack surface: a broadcast **Module Scan** " +
		"enumerates every Anybus gateway on the segment, a **Configure** message can change a module's IP / " +
		"subnet / gateway / hostname, and the **Module Scan Response** advertises whether the module is " +
		"password-protected (**PSWD = OFF** ⇒ reconfiguration is unauthenticated). A captured HICP exchange " +
		"is industrial-asset inventory + a hijack / misconfiguration signal.\n\n" +
		"Decodes the message type (Module Scan / Module Scan Response / Configure / Reconfigured / Invalid " +
		"Configuration / Invalid Password / Wink) and the **Key = value** fields — fieldbus type, module " +
		"version, MAC, IP, subnet, gateway, DHCP, password state, hostname, DNS — surfacing every pair found " +
		"and flagging an unauthenticated-reconfig (PSWD = OFF) module.\n\n" +
		"No confidently-wrong output: HICP's spec is not public, so the parser is generic (it surfaces all " +
		"Key=value pairs and normalises the inconsistent MAC separators) and was verified against scapy's " +
		"HICP layer; an unrecognised payload is rejected. No network, no device, transmits nothing, so it is " +
		"Low risk. Accepts the raw ASCII message or hex (':' / '-' / '_' / whitespace separators and a '0x' " +
		"prefix tolerated).\n\n" +
		"Source: docs/catalog/gap-analysis.md (industrial Anybus device-discovery / reconfiguration recon). " +
		"Wrap-vs-native: native — a prefix check + key-value split, stdlib only, no new go.mod dep. Verified " +
		"against scapy's HICP layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The HICP message (the UDP-3250 payload) as raw ASCII text or hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   hicpDecodeHandler,
}

func hicpDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("hicp_decode: 'hex' is required")
	}
	res, err := hicp.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("hicp_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
