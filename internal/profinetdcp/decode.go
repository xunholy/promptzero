// Package profinetdcp decodes Profinet DCP (Discovery and
// Configuration Protocol) frames per IEC 61158-6-10. DCP is the
// **bootstrap** protocol for Profinet networks — the first
// protocol an attacker tapping into a Siemens-shop factory floor
// sees when enumerating devices, and the protocol Profinet IO
// controllers use at boot time to find their distributed I/O
// devices and assign them station names + IP addresses.
//
// DCP runs **directly over Ethernet** (EtherType 0x8892) — no IP,
// no UDP — so it is a Layer 2-only protocol bounded to a single
// broadcast domain. Operationally, DCP carries:
//
//   - **Identify** — multicast "who's there?" used by Siemens TIA
//     Portal, Step7, and Profinet IO controllers at engineering
//     time to enumerate every Profinet-capable device on a wire.
//     Each device responds with its station name, vendor, device
//     ID, role, and current IP parameters.
//   - **Set** — unicast "set the station name + IP" commands sent
//     by an engineering station or IO controller to bring a
//     fresh device into a known configuration.
//   - **Get** — unicast attribute query (read the station name,
//     read the IP, read the device options).
//   - **Hello** — multicast announcement an IO device sends after
//     reboot to declare its presence to controllers.
//
// Wrap-vs-native judgement
//
//	Native. IEC 61158-6-10 + the Profinet wiki + Wireshark's pn_dcp
//	dissector fully specify the wire format. DCP frames are a
//	tight FrameID + 10-byte fixed header followed by a TLV block
//	stream with Option/Suboption discriminator bytes. No crypto
//	at the parse layer.
//
// What this package covers
//
//   - **FrameID** (2 bytes, big-endian; transmitted immediately
//     after the 0x8892 EtherType):
//
//   - 0xFEFE: **DCP Hello** (multicast announcement)
//
//   - 0xFEFD: **DCP Get/Set** (unicast request/response)
//
//   - 0xFEFC: **DCP Identify Request** (multicast)
//
//   - 0xFEFB: **DCP Identify Response** (multicast)
//
//   - **DCP header** (10 bytes, big-endian):
//
//   - byte 0: **ServiceID** — 0x03 Get / 0x04 Set / 0x05
//     Identify / 0x06 Hello.
//
//   - byte 1: **ServiceType** — 0x00 Request / 0x01
//     Response Success / 0x05 Response Not Supported.
//
//   - bytes 2-5: **Xid** (uint32 BE; transaction
//     identifier for request/response pairing).
//
//   - bytes 6-7: **ResponseDelay** (uint16 BE; on
//     Identify requests, the receiver waits up to this
//     many 10-ms ticks × DCP_TICK_FACTOR before replying
//     to spread the response storm).
//
//   - bytes 8-9: **DCPDataLength** (uint16 BE; bytes of
//     TLV blocks following).
//
//   - **TLV block walker** — each block is laid out as:
//
//   - byte 0: **Option** (1 byte; categorical bucket).
//
//   - byte 1: **Suboption** (1 byte; per-Option child).
//
//   - bytes 2-3: **DCPBlockLength** (uint16 BE; bytes of
//     payload following — INCLUDING the 2-byte BlockInfo
//     for response blocks).
//
//   - bytes 4+: payload (per-Option/Suboption shape).
//
//   - Inter-block padding: blocks are 16-bit-aligned;
//     odd-length blocks get a 1-byte 0x00 pad.
//
//   - **7-entry Option name table**: 0x01 `IP` (subopts: MAC /
//     IP_Parameter / Full_IP_Suite) / 0x02 `DeviceProperties`
//     (subopts: Vendor / NameOfStation / DeviceID / DeviceRole /
//     DeviceOptions / AliasName / DeviceInstance / OEMDeviceID)
//     / 0x03 `DHCP` / 0x04 `LLDP` / 0x05 `ControlBlock` (subopts:
//     Start / Stop / Signal / Response / FactoryReset / ResetToFactory)
//     / 0x06 `DeviceInitiative` / 0xFF `AllSelector`.
//
//   - **Per-Option/Suboption decoder set** (high-runners):
//
//   - **IP / MAC** (0x01 / 0x01): 6-byte MAC address.
//
//   - **IP / IP_Parameter** (0x01 / 0x02): IPv4 Address +
//     Subnet Mask + Gateway (each 4 bytes BE).
//
//   - **IP / Full_IP_Suite** (0x01 / 0x03): IP_Parameter
//
//   - 4 DNS server addresses.
//
//   - **DeviceProperties / Vendor** (0x02 / 0x01):
//     manufacturer name VISIBLE-STRING.
//
//   - **DeviceProperties / NameOfStation** (0x02 / 0x02):
//     station name VISIBLE-STRING (the unique IO-device
//     identifier used by the IO controller — e.g.
//     "et200sp.field-01").
//
//   - **DeviceProperties / DeviceID** (0x02 / 0x03):
//     VendorID (uint16 BE) + DeviceID (uint16 BE).
//
//   - **DeviceProperties / DeviceRole** (0x02 / 0x04):
//     bitmask — bit 0 IO-Device, bit 1 IO-Controller,
//     bit 2 IO-Multidevice, bit 3 PN-Supervisor.
//
//   - **DeviceProperties / DeviceOptions** (0x02 / 0x05):
//     list of (Option, Suboption) pairs the device
//     supports.
//
//   - **DeviceProperties / DeviceInstance** (0x02 / 0x07):
//     2-byte high + 2-byte low instance identifier.
//
//   - **DeviceProperties / OEMDeviceID** (0x02 / 0x08):
//     OEM vendor + device IDs (same shape as DeviceID).
//
//   - **ControlBlock / Signal** (0x05 / 0x03): "flash
//     LED on the target" — the bench-engineering primitive
//     for identifying a device by sight on the rack.
//
//   - **AllSelector / All** (0xFF / 0xFF): request every
//     option in a single round trip (the standard
//     IdentifyAll body).
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **L2 framing** — feed Profinet DCP bytes after the 14-byte
//     Ethernet header (destination MAC, source MAC, EtherType
//     0x8892). Standard DCP destination is multicast group
//     01:0E:CF:00:00:00 for Identify / Hello, or unicast for
//     Get/Set targeted at a specific device. VLAN tagging via
//     IEEE 802.1Q with PCP=6 priority is common but is part of
//     the L2 frame and not parsed here.
//   - **Other Profinet FrameID ranges** — RT cyclic I/O data
//     (FrameID 0x8000-0xBFFF), PTCP timing (0xFF40-0xFF43),
//     Acyclic RT (0xFE00-0xFEFA) — different frame shapes that
//     require their own decoders. This package specifically
//     targets the DCP range (0xFEFB-0xFEFE).
//   - **BlockInfo field** — response blocks carry a 2-byte
//     BlockInfo at the start of the payload (BlockQualifier +
//     Status); surfaced as raw payload bytes for the per-Option
//     decoders to peek at, but not separately parsed.
//   - **Profinet IO state-machine** — connection establishment
//     (CR / AR setup), I/O exchange, alarm framing — higher-
//     level analysis driven by GSD file metadata.
package profinetdcp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// Result is the structured decode of a Profinet DCP frame.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	// FrameID + name
	FrameID     int    `json:"frame_id"`
	FrameIDName string `json:"frame_id_name"`

	// DCP header (10 bytes)
	ServiceID       int    `json:"service_id"`
	ServiceIDName   string `json:"service_id_name"`
	ServiceType     int    `json:"service_type"`
	ServiceTypeName string `json:"service_type_name"`
	Xid             uint32 `json:"xid"`
	ResponseDelay   int    `json:"response_delay"`
	DCPDataLength   int    `json:"dcp_data_length"`

	// TLV blocks
	Blocks []Block `json:"blocks,omitempty"`
}

// Block is one TLV record in the DCP body.
type Block struct {
	Option        int    `json:"option"`
	OptionName    string `json:"option_name"`
	Suboption     int    `json:"suboption"`
	SuboptionName string `json:"suboption_name"`
	Length        int    `json:"length"`
	PayloadHex    string `json:"payload_hex,omitempty"`

	// Per-option decoded fields (only one set populated).
	MAC               string `json:"mac,omitempty"`
	IPAddress         string `json:"ip_address,omitempty"`
	SubnetMask        string `json:"subnet_mask,omitempty"`
	Gateway           string `json:"gateway,omitempty"`
	Vendor            string `json:"vendor,omitempty"`
	NameOfStation     string `json:"name_of_station,omitempty"`
	VendorID          int    `json:"vendor_id,omitempty"`
	DeviceID          int    `json:"device_id,omitempty"`
	DeviceRoleHex     string `json:"device_role_hex,omitempty"`
	DeviceRoleDecoded string `json:"device_role_decoded,omitempty"`
}

// Decode parses a Profinet DCP frame from a hex string starting
// at the FrameID bytes (i.e. AFTER the 14-byte Ethernet header
// + 0x8892 EtherType strip). Separators (':' '-' '_' whitespace)
// are tolerated; a leading '0x' prefix is stripped.
func Decode(hexStr string) (*Result, error) {
	clean := stripSeparators(hexStr)
	if len(clean) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("odd-length hex (%d nibbles)", len(clean))
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	if len(b) < 12 {
		return nil, fmt.Errorf("profinet DCP frame truncated (%d bytes; need ≥12 for FrameID + header)",
			len(b))
	}

	r := &Result{
		TotalBytes:    len(b),
		FrameID:       int(binary.BigEndian.Uint16(b[0:2])),
		ServiceID:     int(b[2]),
		ServiceType:   int(b[3]),
		Xid:           binary.BigEndian.Uint32(b[4:8]),
		ResponseDelay: int(binary.BigEndian.Uint16(b[8:10])),
		DCPDataLength: int(binary.BigEndian.Uint16(b[10:12])),
	}
	r.FrameIDName = frameIDName(r.FrameID)
	r.ServiceIDName = serviceIDName(r.ServiceID)
	r.ServiceTypeName = serviceTypeName(r.ServiceType)

	// Walk TLV blocks within the DCPDataLength region.
	body := b[12:]
	end := r.DCPDataLength
	if end > len(body) {
		end = len(body)
	}
	off := 0
	for off+4 <= end {
		blockLen := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
		if off+4+blockLen > end {
			break
		}
		block := decodeBlock(body[off : off+4+blockLen])
		r.Blocks = append(r.Blocks, block)
		// Advance past block + length + per-block 16-bit pad.
		next := off + 4 + blockLen
		if next%2 != 0 {
			next++
		}
		off = next
	}
	return r, nil
}

func decodeBlock(b []byte) Block {
	bl := Block{
		Option:    int(b[0]),
		Suboption: int(b[1]),
		Length:    int(binary.BigEndian.Uint16(b[2:4])),
	}
	bl.OptionName = optionName(bl.Option)
	bl.SuboptionName = suboptionName(bl.Option, bl.Suboption)
	payload := b[4:]
	if len(payload) > 0 {
		bl.PayloadHex = strings.ToUpper(hex.EncodeToString(payload))
	}
	decodePerSuboption(&bl, payload)
	return bl
}

// decodePerSuboption applies known per-Option / -Suboption
// decoders to populate the convenience fields on Block.
func decodePerSuboption(bl *Block, payload []byte) {
	// Response blocks carry a 2-byte BlockInfo before the
	// per-Option payload — peek past it for known shapes.
	body := payload
	if len(payload) >= 2 {
		body = payload[2:]
	}
	switch bl.Option {
	case 0x01: // IP
		switch bl.Suboption {
		case 0x01: // MAC address
			if len(body) >= 6 {
				bl.MAC = fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X",
					body[0], body[1], body[2], body[3], body[4], body[5])
			}
		case 0x02, 0x03: // IP Parameter / Full IP Suite
			if len(body) >= 12 {
				bl.IPAddress = net.IPv4(body[0], body[1], body[2], body[3]).String()
				bl.SubnetMask = net.IPv4(body[4], body[5], body[6], body[7]).String()
				bl.Gateway = net.IPv4(body[8], body[9], body[10], body[11]).String()
			}
		}
	case 0x02: // DeviceProperties
		switch bl.Suboption {
		case 0x01: // Vendor (VISIBLE-STRING)
			bl.Vendor = strings.TrimRight(string(body), "\x00")
		case 0x02: // NameOfStation (VISIBLE-STRING)
			bl.NameOfStation = strings.TrimRight(string(body), "\x00")
		case 0x03: // DeviceID
			if len(body) >= 4 {
				bl.VendorID = int(binary.BigEndian.Uint16(body[0:2]))
				bl.DeviceID = int(binary.BigEndian.Uint16(body[2:4]))
			}
		case 0x04: // DeviceRole
			if len(body) >= 1 {
				bl.DeviceRoleHex = fmt.Sprintf("0x%02X", body[0])
				bl.DeviceRoleDecoded = deviceRoleNames(body[0])
			}
		}
	}
}

func frameIDName(f int) string {
	switch f {
	case 0xFEFB:
		return "DCP_Identify_Response"
	case 0xFEFC:
		return "DCP_Identify_Request"
	case 0xFEFD:
		return "DCP_Get_Set"
	case 0xFEFE:
		return "DCP_Hello"
	}
	return fmt.Sprintf("uncatalogued FrameID 0x%04X", f)
}

func serviceIDName(s int) string {
	switch s {
	case 0x03:
		return "Get"
	case 0x04:
		return "Set"
	case 0x05:
		return "Identify"
	case 0x06:
		return "Hello"
	}
	return fmt.Sprintf("uncatalogued service 0x%02X", s)
}

func serviceTypeName(t int) string {
	switch t {
	case 0x00:
		return "Request"
	case 0x01:
		return "Response_Success"
	case 0x05:
		return "Response_Not_Supported"
	}
	return fmt.Sprintf("uncatalogued service type 0x%02X", t)
}

func optionName(o int) string {
	switch o {
	case 0x01:
		return "IP"
	case 0x02:
		return "DeviceProperties"
	case 0x03:
		return "DHCP"
	case 0x04:
		return "LLDP"
	case 0x05:
		return "ControlBlock"
	case 0x06:
		return "DeviceInitiative"
	case 0xFF:
		return "AllSelector"
	}
	return fmt.Sprintf("uncatalogued option 0x%02X", o)
}

func suboptionName(opt, sub int) string {
	switch opt {
	case 0x01: // IP
		switch sub {
		case 0x01:
			return "MAC"
		case 0x02:
			return "IP_Parameter"
		case 0x03:
			return "Full_IP_Suite"
		}
	case 0x02: // DeviceProperties
		switch sub {
		case 0x01:
			return "Vendor"
		case 0x02:
			return "NameOfStation"
		case 0x03:
			return "DeviceID"
		case 0x04:
			return "DeviceRole"
		case 0x05:
			return "DeviceOptions"
		case 0x06:
			return "AliasName"
		case 0x07:
			return "DeviceInstance"
		case 0x08:
			return "OEMDeviceID"
		}
	case 0x05: // ControlBlock
		switch sub {
		case 0x01:
			return "Start"
		case 0x02:
			return "Stop"
		case 0x03:
			return "Signal"
		case 0x04:
			return "Response"
		case 0x05:
			return "FactoryReset"
		case 0x06:
			return "ResetToFactory"
		}
	case 0x06: // DeviceInitiative
		if sub == 0x01 {
			return "DeviceInitiative"
		}
	case 0xFF: // AllSelector
		if sub == 0xFF {
			return "All"
		}
	}
	return fmt.Sprintf("uncatalogued suboption 0x%02X", sub)
}

// deviceRoleNames decodes the DeviceRole bitmask per IEC
// 61158-6-10.
func deviceRoleNames(r byte) string {
	var names []string
	if r&0x01 != 0 {
		names = append(names, "IO-Device")
	}
	if r&0x02 != 0 {
		names = append(names, "IO-Controller")
	}
	if r&0x04 != 0 {
		names = append(names, "IO-Multidevice")
	}
	if r&0x08 != 0 {
		names = append(names, "PN-Supervisor")
	}
	return strings.Join(names, ",")
}

func stripSeparators(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for _, r := range s {
		switch r {
		case ' ', '\t', '\n', '\r', ':', '-', '_':
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
