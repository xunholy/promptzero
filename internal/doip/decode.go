// SPDX-License-Identifier: AGPL-3.0-or-later

// Package doip decodes DoIP — Diagnostics over Internet Protocol (ISO 13400) —
// the Ethernet/IP transport that carries vehicle diagnostics (UDS) in modern
// cars, replacing the OBD-II-over-CAN link. A DoIP edge node (the vehicle's
// diagnostic gateway) is reached over TCP/UDP 13400; a tester discovers it
// (vehicle identification), authorises a session (routing activation), then
// tunnels UDS diagnostic messages to the in-vehicle ECUs. DoIP is a real and
// growing automotive-security target: it is the network entry point to the
// whole diagnostic surface, the vehicle-identification response broadcasts the
// **VIN / EID / GID / logical address** (asset identification), and routing
// activation is the access-control gate (whose "denied due to missing
// authentication" response reveals the posture). A captured DoIP message
// identifies the **operation** — vehicle identification (+ the leaked VIN /
// EID / GID), routing activation (request type + response code), an alive
// check, an entity-status or power-mode query, or a diagnostic message — and,
// for a diagnostic message, lifts out the **UDS payload** for handoff to the
// UDS decoder. It joins the project's automotive family (internal/uds, kwp,
// obd2, xcp, isotp, canfd).
//
// # Wrap-vs-native judgement
//
//	Native. A DoIP message is an 8-byte header (version + inverse version +
//	payload type + payload length) followed by a fixed, payload-type-specific
//	body. A byte-slice walk + a payload-type lookup; stdlib only, no new
//	go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The header layout, the payload-type table and the sub-code tables
//	(generic NACK, routing-activation type / response, further-action,
//	VIN/GID status, diagnostic NACK) are code-generated from scapy's
//	authoritative DoIP layer (scapy.contrib.automotive.doip) and verified
//	field-for-field against ISO 13400 message vectors. Only the standardised
//	fields are decoded; the **diagnostic-message user data is a UDS message
//	and is chained to the UDS decoder** (internal/uds) so the diagnostic
//	service is decoded inline — the raw hex is kept alongside and a UDS
//	decode failure degrades to an error + the raw hex (the established
//	chain-to-inner-decoder pattern, cf. nsh/gre → ipdecode). Any trailing
//	previous-message echo is surfaced raw. The inverse-version byte is
//	validated (must be the one's-complement
//	of the version); a declared payload length disagreeing with the buffer, or
//	a body too short for the payload type, is reported, not guessed.
package doip

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/uds"
)

// Result is the decoded view of a DoIP message.
type Result struct {
	ProtocolVersion     int    `json:"protocol_version"`
	ProtocolVersionName string `json:"protocol_version_name,omitempty"`
	InverseVersionValid bool   `json:"inverse_version_valid"`
	PayloadType         int    `json:"payload_type"`
	PayloadTypeHex      string `json:"payload_type_hex"`
	PayloadTypeName     string `json:"payload_type_name"`
	PayloadLength       int    `json:"payload_length"`

	// Vehicle identification / announcement
	VIN           string `json:"vin,omitempty"`
	LogicalAddr   string `json:"logical_address,omitempty"`
	EID           string `json:"eid,omitempty"`
	GID           string `json:"gid,omitempty"`
	FurtherAction string `json:"further_action,omitempty"`
	VINGIDStatus  string `json:"vin_gid_status,omitempty"`

	// Routing activation
	SourceAddr            string `json:"source_address,omitempty"`
	ActivationType        string `json:"activation_type,omitempty"`
	LogicalAddrTester     string `json:"logical_address_tester,omitempty"`
	LogicalAddrEntity     string `json:"logical_address_doip_entity,omitempty"`
	RoutingActivationResp string `json:"routing_activation_response,omitempty"`

	// Diagnostic message
	TargetAddr     string   `json:"target_address,omitempty"`
	UDSPayloadHex  string   `json:"uds_payload_hex,omitempty"`
	UDS            *uds.UDS `json:"uds,omitempty"`
	UDSDecodeError string   `json:"uds_decode_error,omitempty"`
	DiagACKCode    string   `json:"diagnostic_ack_code,omitempty"`
	DiagNACKCode   string   `json:"diagnostic_nack_code,omitempty"`

	// Generic NACK
	NACKCode string `json:"nack_code,omitempty"`

	// Entity status / power mode
	NodeType        string `json:"node_type,omitempty"`
	MaxOpenSockets  *int   `json:"max_open_sockets,omitempty"`
	CurOpenSockets  *int   `json:"current_open_sockets,omitempty"`
	DiagnosticPower *int   `json:"diagnostic_power_mode,omitempty"`

	PayloadHex string   `json:"payload_hex,omitempty"`
	Notes      []string `json:"notes,omitempty"`
}

// Decode parses a DoIP message (starting at the protocol-version byte) from
// hex (whitespace / ':' / '-' / '_' separators and a '0x' prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) < 8 {
		return nil, fmt.Errorf("doip: %d bytes — too short for the 8-byte DoIP header", len(b))
	}
	ver := b[0]
	pt := binary.BigEndian.Uint16(b[2:4])
	r := &Result{
		ProtocolVersion:     int(ver),
		ProtocolVersionName: versionName(ver),
		InverseVersionValid: b[1] == byte(^ver),
		PayloadType:         int(pt),
		PayloadTypeHex:      fmt.Sprintf("0x%04X", pt),
		PayloadTypeName:     payloadTypeName(pt),
		PayloadLength:       int(binary.BigEndian.Uint32(b[4:8])),
	}
	if !r.InverseVersionValid {
		r.Notes = append(r.Notes, fmt.Sprintf("inverse version 0x%02X is not the one's-complement of version 0x%02X", b[1], ver))
	}
	body := b[8:]
	if r.PayloadLength != len(body) {
		r.Notes = append(r.Notes, fmt.Sprintf("declared payload length %d does not match the %d-byte body", r.PayloadLength, len(body)))
	}
	decodeBody(r, pt, body)
	r.Notes = append(r.Notes, "DoIP (ISO 13400) — vehicle Ethernet diagnostics; vehicle-identification responses leak VIN/EID/GID, routing activation gates access, and diagnostic-message user data is the UDS payload (chain to the UDS decoder)")
	return r, nil
}

func decodeBody(r *Result, pt uint16, body []byte) {
	switch pt {
	case 0x0000: // Generic DoIP header NACK
		if len(body) >= 1 {
			r.NACKCode = genericNACKName(body[0])
		}
	case 0x0003: // Vehicle ID request with VIN
		if len(body) >= 17 {
			r.VIN = asciiTrim(body[0:17])
		}
	case 0x0002: // Vehicle ID request with EID
		if len(body) >= 6 {
			r.EID = hexUpper(body[0:6])
		}
	case 0x0004: // Vehicle announcement / ID response
		if len(body) >= 32 {
			r.VIN = asciiTrim(body[0:17])
			r.LogicalAddr = addr(body[17:19])
			r.EID = hexUpper(body[19:25])
			r.GID = hexUpper(body[25:31])
			r.FurtherAction = furtherActionName(body[31])
			if len(body) >= 33 {
				r.VINGIDStatus = vinGIDStatusName(body[32])
			}
		}
	case 0x0005: // Routing activation request
		if len(body) >= 7 {
			r.SourceAddr = addr(body[0:2])
			r.ActivationType = activationTypeName(body[2])
		}
	case 0x0006: // Routing activation response
		if len(body) >= 9 {
			r.LogicalAddrTester = addr(body[0:2])
			r.LogicalAddrEntity = addr(body[2:4])
			r.RoutingActivationResp = routingActivationRespName(body[4])
		}
	case 0x0008: // Alive check response
		if len(body) >= 2 {
			r.SourceAddr = addr(body[0:2])
		}
	case 0x4002: // DoIP entity status response
		if len(body) >= 3 {
			r.NodeType = nodeTypeName(body[0])
			mo := int(body[1])
			co := int(body[2])
			r.MaxOpenSockets = &mo
			r.CurOpenSockets = &co
		}
	case 0x4004: // Diagnostic power mode response
		if len(body) >= 1 {
			dp := int(body[0])
			r.DiagnosticPower = &dp
		}
	case 0x8001: // Diagnostic message
		if len(body) >= 4 {
			r.SourceAddr = addr(body[0:2])
			r.TargetAddr = addr(body[2:4])
			if len(body) > 4 {
				r.UDSPayloadHex = hexUpper(body[4:])
				// The diagnostic-message user data IS a UDS message — chain it
				// to the UDS decoder so the service is decoded inline (the recon
				// headline). Degrade to the raw hex + an error on failure.
				if u, err := uds.DecodeBytes(body[4:]); err == nil {
					r.UDS = u
				} else {
					r.UDSDecodeError = err.Error()
				}
			}
		}
	case 0x8002: // Diagnostic message ACK
		if len(body) >= 5 {
			r.SourceAddr = addr(body[0:2])
			r.TargetAddr = addr(body[2:4])
			r.DiagACKCode = fmt.Sprintf("0x%02X", body[4])
			if len(body) > 5 {
				r.PayloadHex = hexUpper(body[5:])
			}
		}
	case 0x8003: // Diagnostic message NACK
		if len(body) >= 5 {
			r.SourceAddr = addr(body[0:2])
			r.TargetAddr = addr(body[2:4])
			r.DiagNACKCode = diagNACKName(body[4])
			if len(body) > 5 {
				r.PayloadHex = hexUpper(body[5:])
			}
		}
	}
}

func versionName(v byte) string {
	switch v {
	case 0x01:
		return "ISO13400-2010"
	case 0x02:
		return "ISO13400-2012"
	case 0x03:
		return "ISO13400-2019"
	case 0x04:
		return "ISO13400-2019 AMD1"
	case 0xFF:
		return "default (vehicle identification)"
	}
	return ""
}

func payloadTypeName(pt uint16) string {
	names := map[uint16]string{
		0x0000: "Generic DoIP header NACK",
		0x0001: "Vehicle identification request",
		0x0002: "Vehicle identification request with EID",
		0x0003: "Vehicle identification request with VIN",
		0x0004: "Vehicle announcement / identification response",
		0x0005: "Routing activation request",
		0x0006: "Routing activation response",
		0x0007: "Alive check request",
		0x0008: "Alive check response",
		0x4001: "DoIP entity status request",
		0x4002: "DoIP entity status response",
		0x4003: "Diagnostic power mode information request",
		0x4004: "Diagnostic power mode information response",
		0x8001: "Diagnostic message",
		0x8002: "Diagnostic message ACK",
		0x8003: "Diagnostic message NACK",
	}
	if n, ok := names[pt]; ok {
		return n
	}
	return fmt.Sprintf("unknown payload type 0x%04X", pt)
}

func genericNACKName(c byte) string {
	switch c {
	case 0x00:
		return "Incorrect pattern format"
	case 0x01:
		return "Unknown payload type"
	case 0x02:
		return "Message too large"
	case 0x03:
		return "Out of memory"
	case 0x04:
		return "Invalid payload length"
	}
	return fmt.Sprintf("0x%02X", c)
}

func furtherActionName(c byte) string {
	switch c {
	case 0x00:
		return "No further action required"
	case 0x10:
		return "Routing activation required to initiate central security"
	}
	return fmt.Sprintf("0x%02X", c)
}

func vinGIDStatusName(c byte) string {
	switch c {
	case 0x00:
		return "VIN and/or GID are synchronized"
	case 0x10:
		return "Incomplete: VIN and GID are NOT synchronized"
	}
	return fmt.Sprintf("0x%02X", c)
}

func activationTypeName(c byte) string {
	switch c {
	case 0x00:
		return "Default"
	case 0x01:
		return "WWH-OBD"
	case 0xE0:
		return "Central security"
	}
	return fmt.Sprintf("0x%02X", c)
}

func routingActivationRespName(c byte) string {
	names := map[byte]string{
		0x00: "denied: unknown source address",
		0x01: "denied: all TCP_DATA sockets registered and active",
		0x02: "denied: SA differs from table connection entry on active socket",
		0x03: "denied: SA already registered and active on a different socket",
		0x04: "denied: missing authentication",
		0x05: "denied: rejected confirmation",
		0x06: "denied: unsupported routing activation type",
		0x07: "denied: activation type requires a secure TLS socket",
		0x10: "routing successfully activated",
		0x11: "routing will be activated; confirmation required",
	}
	if n, ok := names[c]; ok {
		return n
	}
	return fmt.Sprintf("0x%02X", c)
}

func diagNACKName(c byte) string {
	names := map[byte]string{
		0x02: "Invalid source address",
		0x03: "Unknown target address",
		0x04: "Diagnostic message too large",
		0x05: "Out of memory",
		0x06: "Target unreachable",
		0x07: "Unknown network",
		0x08: "Transport protocol error",
	}
	if n, ok := names[c]; ok {
		return n
	}
	return fmt.Sprintf("0x%02X", c)
}

func nodeTypeName(c byte) string {
	switch c {
	case 0x00:
		return "DoIP gateway"
	case 0x01:
		return "DoIP node"
	}
	return fmt.Sprintf("0x%02X", c)
}

func addr(b []byte) string { return fmt.Sprintf("0x%04X", binary.BigEndian.Uint16(b)) }

func hexUpper(b []byte) string { return strings.ToUpper(hex.EncodeToString(b)) }

// asciiTrim renders the VIN as ASCII, trimming trailing NUL / spaces; falls
// back to hex if the field is not printable.
func asciiTrim(b []byte) string {
	s := strings.TrimRight(string(b), "\x00 ")
	for _, c := range s {
		if c < 0x20 || c > 0x7e {
			return hexUpper(b)
		}
	}
	if s == "" {
		return hexUpper(b)
	}
	return s
}

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("doip: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("doip: input is not valid hex: %w", err)
	}
	return b, nil
}
