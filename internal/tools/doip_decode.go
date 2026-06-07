// doip_decode.go — host-side DoIP (Diagnostics over IP, ISO 13400) decoder
// Spec, delegating to internal/doip.
//
// Wrap-vs-native: native — an 8-byte header (version + inverse version +
// payload type + length) + a fixed payload-type-specific body; a byte-slice
// walk + a payload-type lookup, stdlib only. The vehicle-Ethernet-diagnostics
// decoder — surfaces vehicle identification (VIN/EID/GID), routing activation,
// and the UDS payload of a diagnostic message. Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/doip"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(doipDecodeSpec)
}

var doipDecodeSpec = Spec{
	Name: "doip_decode",
	Description: "Decode a **DoIP (Diagnostics over Internet Protocol, ISO 13400)** message — the Ethernet/IP " +
		"transport that carries **vehicle diagnostics (UDS)** in modern cars, replacing the OBD-II-over-CAN " +
		"link. A DoIP edge node (the vehicle's diagnostic gateway) is reached over TCP/UDP 13400; a tester " +
		"discovers it (vehicle identification), authorises a session (routing activation), then tunnels UDS " +
		"diagnostic messages to the in-vehicle ECUs. DoIP is a real, growing **automotive-security target**: " +
		"it is the network entry point to the whole diagnostic surface, the vehicle-identification response " +
		"broadcasts the **VIN / EID / GID / logical address** (asset identification), and routing activation " +
		"is the access-control gate (its 'denied due to missing authentication' response reveals the posture). " +
		"It joins the project's automotive family (`uds_decode`, `kwp_decode`, `obd2_*`, `xcp_decode`, " +
		"`isotp_decode`, `canbus_fd_decode`).\n\n" +
		"A captured DoIP message identifies the **operation** — vehicle identification (+ the leaked VIN / EID " +
		"/ GID), routing activation (request type + response code), an alive check, an entity-status or " +
		"power-mode query, or a diagnostic message — and, for a diagnostic message, lifts out the **UDS " +
		"payload** for handoff to `uds_decode`.\n\n" +
		"No confidently-wrong output: the header layout, the payload-type table and the sub-code tables " +
		"(generic NACK, routing-activation type / response, further-action, VIN/GID status, diagnostic NACK) " +
		"are code-generated from scapy's authoritative DoIP layer (`scapy.contrib.automotive.doip`) and " +
		"verified field-for-field against ISO 13400 vectors. Only the standardised fields are decoded; the " +
		"**diagnostic-message user data is the UDS payload and is surfaced as raw hex** (never reinterpreted " +
		"here), and any trailing previous-message echo is surfaced raw. The inverse-version byte is validated " +
		"(must be the one's-complement of the version); a declared payload length disagreeing with the buffer, " +
		"or a body too short for the payload type, is reported, not guessed. No network, no device, transmits " +
		"nothing, so it is Low risk. The input is the DoIP message starting at the protocol-version byte. ':' " +
		"/ '-' / '_' / whitespace separators and a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (automotive Ethernet-diagnostics recon; the DoIP transport for " +
		"uds_decode). Wrap-vs-native: native — a byte-slice walk + a payload-type lookup, stdlib only, no new " +
		"go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The DoIP message starting at the protocol-version byte as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   doipDecodeHandler,
}

func doipDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("doip_decode: 'hex' is required")
	}
	res, err := doip.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("doip_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
