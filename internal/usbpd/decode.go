// SPDX-License-Identifier: AGPL-3.0-or-later

// Package usbpd decodes USB Power Delivery (USB-PD) messages — the protocol
// spoken over the USB-C CC line to negotiate power (and to tunnel alternate
// modes and vendor-defined messages). USB-PD is an emerging hardware-attack
// surface: a malicious charger or a PD-capable cable can advertise bogus power
// capabilities, drive a sink to request out-of-spec voltage, or carry
// vendor-defined messages that trigger device-specific behaviour — so a
// captured PD exchange (from a CC-line analyzer) is real recon. A USB-PD
// message identifies the **negotiation step** — a Source/Sink Capabilities
// advertisement (and the offered voltages/currents), a Request, an
// Accept/Reject/PS_RDY, a role swap, a Vendor-Defined Message — which is the
// headline for charger / cable analysis. It joins the project's USB analysis
// stack (internal/usbdesc, internal/hidreport, internal/usbhid).
//
// # Wrap-vs-native judgement
//
//	Native. A USB-PD message is a 16-bit little-endian header (message type,
//	roles, spec revision, message id, data-object count) optionally followed
//	by 32-bit little-endian Data Objects. A bit-field read + a per-message-type
//	walk; stdlib only, no new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The header bit layout, the control- and data-message type tables, and the
//	Fixed / Variable / Battery Power Data Object layouts follow the USB Power
//	Delivery specification — deterministic and byte-checkable against spec-
//	built PDOs (e.g. 5 V @ 3 A). The control-vs-data message-type dispatch is
//	driven by the header's data-object count (no ambiguity). Only the
//	standardised, well-defined fields are decoded: the header, and — for
//	Source/Sink Capabilities — the Fixed (voltage/current + role flags),
//	Variable and Battery PDOs; an Augmented PDO (PPS / AVS) is surfaced by
//	type with its 32-bit value raw, and the Request RDO, BIST, Vendor-Defined
//	and other data messages' objects are surfaced as raw hex (their layouts
//	are position-dependent and would be confidently-wrong without the prior
//	Capabilities context). The input is the raw on-wire bytes (little-endian).
package usbpd

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the decoded view of a USB-PD message.
type Result struct {
	HeaderHex      string       `json:"header_hex"`
	MessageClass   string       `json:"message_class"` // "control" | "data"
	MessageType    int          `json:"message_type"`
	MessageName    string       `json:"message_name"`
	SpecRevision   string       `json:"spec_revision"`
	PortPowerRole  string       `json:"port_power_role"`
	PortDataRole   string       `json:"port_data_role"`
	MessageID      int          `json:"message_id"`
	NumDataObjects int          `json:"num_data_objects"`
	Extended       bool         `json:"extended,omitempty"`
	DataObjects    []DataObject `json:"data_objects,omitempty"`
	Notes          []string     `json:"notes,omitempty"`
}

// DataObject is one 32-bit USB-PD data object.
type DataObject struct {
	Raw         string `json:"raw"`
	Kind        string `json:"kind,omitempty"` // PDO type / "RDO" / "VDO" / etc.
	VoltageV    string `json:"voltage_v,omitempty"`
	MaxCurrentA string `json:"max_current_a,omitempty"`
	Flags       string `json:"flags,omitempty"`
}

// Decode parses a USB-PD message (raw on-wire bytes, little-endian) from hex
// (whitespace / ':' / '-' / '_' separators and a '0x' prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) < 2 {
		return nil, fmt.Errorf("usbpd: %d bytes — too short for the 16-bit message header", len(b))
	}
	h := binary.LittleEndian.Uint16(b[0:2])
	msgType := int(h & 0x1F)
	ndo := int(h>>12) & 0x07
	r := &Result{
		HeaderHex:      fmt.Sprintf("0x%04X", h),
		MessageType:    msgType,
		SpecRevision:   specRev(int(h>>6) & 0x03),
		MessageID:      int(h>>9) & 0x07,
		NumDataObjects: ndo,
		Extended:       h&0x8000 != 0,
	}
	if h&0x20 != 0 {
		r.PortDataRole = "DFP"
	} else {
		r.PortDataRole = "UFP"
	}
	if h&0x100 != 0 {
		r.PortPowerRole = "Source"
	} else {
		r.PortPowerRole = "Sink"
	}
	if ndo == 0 {
		r.MessageClass = "control"
		r.MessageName = controlName(msgType)
	} else {
		r.MessageClass = "data"
		r.MessageName = dataName(msgType)
	}

	// Walk the data objects (32-bit little-endian) after the header.
	objs := b[2:]
	isCaps := r.MessageClass == "data" && (msgType == 1 || msgType == 4) // Source/Sink Capabilities
	for i := 0; i < ndo; i++ {
		off := i * 4
		if off+4 > len(objs) {
			r.Notes = append(r.Notes, fmt.Sprintf("header declares %d data objects but only %d bytes follow", ndo, len(objs)))
			break
		}
		v := binary.LittleEndian.Uint32(objs[off : off+4])
		r.DataObjects = append(r.DataObjects, decodeObject(v, isCaps))
	}

	r.Notes = append(r.Notes, "USB Power Delivery — the message type names the negotiation step; Source/Sink Capabilities advertise the offered power (Fixed/Variable/Battery PDOs decoded), other data objects (Request RDO / VDM / Augmented PDO) are surfaced raw")
	return r, nil
}

// decodeObject decodes a 32-bit data object. For a Capabilities message it is a
// Power Data Object (PDO); otherwise it is surfaced raw.
func decodeObject(v uint32, isCaps bool) DataObject {
	o := DataObject{Raw: fmt.Sprintf("0x%08X", v)}
	if !isCaps {
		o.Kind = "data object (raw)"
		return o
	}
	switch v >> 30 {
	case 0x0: // Fixed Supply
		o.Kind = "Fixed Supply PDO"
		voltage := (v >> 10) & 0x3FF // 50 mV units
		current := v & 0x3FF         // 10 mA units
		o.VoltageV = fmt.Sprintf("%.2f", float64(voltage)*0.05)
		o.MaxCurrentA = fmt.Sprintf("%.2f", float64(current)*0.01)
		o.Flags = fixedFlags(v)
	case 0x1: // Battery
		o.Kind = "Battery PDO"
		maxV := (v >> 20) & 0x3FF // 50 mV
		minV := (v >> 10) & 0x3FF // 50 mV
		o.VoltageV = fmt.Sprintf("%.2f-%.2f", float64(minV)*0.05, float64(maxV)*0.05)
	case 0x2: // Variable Supply (non-battery)
		o.Kind = "Variable Supply PDO"
		maxV := (v >> 20) & 0x3FF // 50 mV
		minV := (v >> 10) & 0x3FF // 50 mV
		current := v & 0x3FF      // 10 mA
		o.VoltageV = fmt.Sprintf("%.2f-%.2f", float64(minV)*0.05, float64(maxV)*0.05)
		o.MaxCurrentA = fmt.Sprintf("%.2f", float64(current)*0.01)
	case 0x3: // Augmented PDO (PPS / AVS)
		o.Kind = "Augmented PDO (PPS/AVS)"
	}
	return o
}

func fixedFlags(v uint32) string {
	var p []string
	if v&(1<<29) != 0 {
		p = append(p, "dual-role-power")
	}
	if v&(1<<28) != 0 {
		p = append(p, "usb-suspend")
	}
	if v&(1<<27) != 0 {
		p = append(p, "unconstrained-power")
	}
	if v&(1<<26) != 0 {
		p = append(p, "usb-comms-capable")
	}
	if v&(1<<25) != 0 {
		p = append(p, "dual-role-data")
	}
	return strings.Join(p, ",")
}

func specRev(r int) string {
	switch r {
	case 0:
		return "1.0"
	case 1:
		return "2.0"
	case 2:
		return "3.0"
	}
	return "reserved"
}

func controlName(t int) string {
	names := map[int]string{
		1: "GoodCRC", 2: "GotoMin", 3: "Accept", 4: "Reject", 5: "Ping",
		6: "PS_RDY", 7: "Get_Source_Cap", 8: "Get_Sink_Cap", 9: "DR_Swap",
		10: "PR_Swap", 11: "VCONN_Swap", 12: "Wait", 13: "Soft_Reset",
		14: "Data_Reset", 15: "Data_Reset_Complete", 16: "Not_Supported",
		17: "Get_Source_Cap_Extended", 18: "Get_Status", 19: "FR_Swap",
		20: "Get_PPS_Status", 21: "Get_Country_Codes", 22: "Get_Sink_Cap_Extended",
		23: "Get_Revision",
	}
	if n, ok := names[t]; ok {
		return n
	}
	return fmt.Sprintf("control message 0x%02X", t)
}

func dataName(t int) string {
	names := map[int]string{
		1: "Source_Capabilities", 2: "Request", 3: "BIST", 4: "Sink_Capabilities",
		5: "Battery_Status", 6: "Alert", 7: "Get_Country_Info", 8: "Enter_USB",
		9: "EPR_Request", 10: "EPR_Mode", 11: "Source_Info", 12: "Revision",
		15: "Vendor_Defined",
	}
	if n, ok := names[t]; ok {
		return n
	}
	return fmt.Sprintf("data message 0x%02X", t)
}

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("usbpd: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("usbpd: input is not valid hex: %w", err)
	}
	return b, nil
}
