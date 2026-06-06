// SPDX-License-Identifier: AGPL-3.0-or-later

// Package rtps decodes the RTPS (Real-Time Publish-Subscribe) wire
// protocol — the on-the-wire protocol of OMG DDS, the publish/subscribe
// middleware that runs **ROS 2 robotics, autonomous vehicles, naval combat
// systems and industrial control**. It joins the project's OT / ICS
// decoder family (modbus, dnp3, iec104, s7comm, enip, profinetdcp, opcua,
// ethercat, knxnetip, hicp) as the DDS member. RTPS is a recon-rich OT
// target: the discovery traffic (SPDP / SEDP) and data flow on a DDS bus
// are unauthenticated by default, so a captured RTPS message fingerprints
// the **DDS vendor** (RTI Connext / eProsima FastDDS / Eclipse Cyclone /
// OpenDDS / …), identifies the **participant** (GUID prefix) and maps the
// submessage flow (discovery vs data, heartbeats, ACKNACKs).
//
// # Wrap-vs-native judgement
//
//	Native. An RTPS message is a 20-byte header ('RTPS' magic, protocol
//	version, vendor id, 12-byte GUID prefix) followed by a list of
//	submessages, each a 4-byte common header (id, flags, octetsToNextHeader)
//	plus a body. A byte-field read + a submessage walk; stdlib only, no new
//	go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The header (magic / version / vendor id / GUID prefix) was verified
//	field-for-field against scapy's RTPS layer (scapy.contrib.rtps), and
//	the vendor-id table is transcribed from scapy's authoritative map. The
//	submessage walk follows the RTPS spec's defined boundary — the
//	per-submessage octetsToNextHeader, read in the submessage's own
//	endianness (the E flag) — so each submessage's kind, endianness and
//	length are deterministic. The submessage **bodies** (the SPDP / SEDP
//	parameter lists, serialized data) are vendor- and QoS-heavy and are
//	surfaced as raw hex rather than decoded into possibly-wrong fields;
//	only the INFO_DST destination GUID prefix (a fixed 12-byte field) is
//	lifted out.
package rtps

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// SubMessage is one decoded RTPS submessage (the framing, not the body).
type SubMessage struct {
	Kind           int    `json:"kind"`
	KindName       string `json:"kind_name"`
	Endianness     string `json:"endianness"`
	FlagsHex       string `json:"flags_hex"`
	OctetsToNext   int    `json:"octets_to_next_header"`
	DestGUIDPrefix string `json:"dest_guid_prefix,omitempty"` // INFO_DST
	BodyHex        string `json:"body_hex,omitempty"`
}

// Result is the decoded view of an RTPS message.
type Result struct {
	ProtocolVersion string       `json:"protocol_version"`
	VendorID        string       `json:"vendor_id"`
	VendorName      string       `json:"vendor_name"`
	GUIDPrefix      string       `json:"guid_prefix"`
	HostID          string       `json:"host_id"`
	AppID           string       `json:"app_id"`
	InstanceID      string       `json:"instance_id"`
	SubMessages     []SubMessage `json:"submessages"`
	Notes           []string     `json:"notes,omitempty"`
}

// Decode parses an RTPS message (the DDS UDP payload) from hex (whitespace
// / ':' / '-' / '_' separators and a '0x' prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) < 20 {
		return nil, fmt.Errorf("rtps: %d bytes — too short for the 20-byte RTPS header", len(b))
	}
	if string(b[0:4]) != "RTPS" && string(b[0:4]) != "RTPX" {
		return nil, fmt.Errorf("rtps: magic %q is not 'RTPS'", string(b[0:4]))
	}
	r := &Result{
		ProtocolVersion: fmt.Sprintf("%d.%d", b[4], b[5]),
		VendorID:        fmt.Sprintf("0x%02X%02X", b[6], b[7]),
		VendorName:      vendorName(binary.BigEndian.Uint16(b[6:8])),
		GUIDPrefix:      hexUpper(b[8:20]),
		HostID:          hexUpper(b[8:12]),
		AppID:           hexUpper(b[12:16]),
		InstanceID:      hexUpper(b[16:20]),
	}
	off := 20
	for off+4 <= len(b) {
		id := int(b[off])
		flags := b[off+1]
		le := flags&0x01 != 0
		var octets int
		if le {
			octets = int(binary.LittleEndian.Uint16(b[off+2 : off+4]))
		} else {
			octets = int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		}
		sm := SubMessage{
			Kind:         id,
			KindName:     subMsgName(id),
			Endianness:   endianStr(le),
			FlagsHex:     fmt.Sprintf("0x%02X", flags),
			OctetsToNext: octets,
		}
		bodyStart := off + 4
		bodyEnd := bodyStart + octets
		if octets == 0 || bodyEnd > len(b) {
			bodyEnd = len(b) // octets==0 means "to end of message"
		}
		body := b[bodyStart:bodyEnd]
		if id == 0x0e && len(body) >= 12 { // INFO_DST carries the destination GUID prefix
			sm.DestGUIDPrefix = hexUpper(body[0:12])
		} else if len(body) > 0 {
			sm.BodyHex = hexUpper(body)
		}
		r.SubMessages = append(r.SubMessages, sm)
		if octets == 0 {
			break // last submessage extended to the end
		}
		off = bodyEnd
	}
	r.Notes = append(r.Notes, "RTPS is the DDS wire protocol (ROS 2 / autonomous / industrial). The vendor id fingerprints the DDS stack and the GUID prefix identifies the participant; DDS discovery + data are unauthenticated by default")
	r.Notes = append(r.Notes, "submessage bodies (SPDP/SEDP parameter lists, serialized data) are surfaced as raw hex — only the framing + INFO_DST GUID are decoded, to avoid confidently-wrong vendor-specific field guesses")
	return r, nil
}

func endianStr(le bool) string {
	if le {
		return "little-endian"
	}
	return "big-endian"
}

func subMsgName(id int) string {
	switch id {
	case 0x01:
		return "PAD"
	case 0x06:
		return "ACKNACK"
	case 0x07:
		return "HEARTBEAT"
	case 0x08:
		return "GAP"
	case 0x09:
		return "INFO_TS"
	case 0x0c:
		return "INFO_SRC"
	case 0x0d:
		return "INFO_REPLY_IP4"
	case 0x0e:
		return "INFO_DST"
	case 0x0f:
		return "INFO_REPLY"
	case 0x12:
		return "NACK_FRAG"
	case 0x13:
		return "HEARTBEAT_FRAG"
	case 0x15:
		return "DATA"
	case 0x16:
		return "DATA_FRAG"
	case 0x30:
		return "SEC_BODY"
	case 0x31:
		return "SEC_PREFIX"
	case 0x32:
		return "SEC_POSTFIX"
	case 0x33:
		return "SRTPS_PREFIX"
	case 0x34:
		return "SRTPS_POSTFIX"
	}
	return fmt.Sprintf("0x%02X", id)
}

// vendorName maps the DDS vendor id (transcribed from scapy's authoritative
// scapy.contrib.rtps vendor table).
func vendorName(v uint16) string {
	switch v {
	case 0x0101:
		return "RTI Connext DDS"
	case 0x0102:
		return "ADLink OpenSplice DDS"
	case 0x0103:
		return "OCI OpenDDS"
	case 0x0104:
		return "MilSoft Mil-DDS"
	case 0x0105:
		return "Kongsberg InterCOM DDS"
	case 0x0106:
		return "Twin Oaks CoreDX DDS"
	case 0x0107:
		return "Lakota Technical Solutions"
	case 0x0108:
		return "ICOUP Consulting"
	case 0x0109:
		return "ETRI Diamond DDS"
	case 0x010a:
		return "RTI Connext DDS Micro"
	case 0x010b:
		return "ADLink VortexCafe"
	case 0x010c:
		return "PrismTech"
	case 0x010d:
		return "ADLink Vortex Lite"
	case 0x010e:
		return "Technicolor Qeo"
	case 0x010f:
		return "eProsima FastDDS / FastRTPS"
	case 0x0110:
		return "Eclipse Cyclone DDS"
	case 0x0111:
		return "GurumNetworks GurumDDS"
	case 0x0112:
		return "Atostek RustDDS"
	case 0x0113:
		return "Nanjing Zhenrong ZRDDS"
	case 0x0114:
		return "S2E Software Systems Dust DDS"
	case 0x0000:
		return "unknown vendor"
	}
	return fmt.Sprintf("0x%04X", v)
}

func hexUpper(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return strings.ToUpper(hex.EncodeToString(b))
}

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("rtps: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("rtps: input is not valid hex: %w", err)
	}
	return b, nil
}
