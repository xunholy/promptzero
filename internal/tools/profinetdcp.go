// profinetdcp.go — host-side Profinet DCP frame decoder Spec.
// Wraps the internal/profinetdcp walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/profinetdcp"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(profinetDCPDecodeSpec)
}

var profinetDCPDecodeSpec = Spec{
	Name: "profinet_dcp_decode",
	Description: "Decode a Profinet DCP (Discovery and Configuration Protocol) frame per " +
		"IEC 61158-6-10. DCP is the **bootstrap** protocol for Profinet networks " +
		"— the first protocol an attacker tapping into a Siemens-shop factory " +
		"floor sees when enumerating devices, and the protocol Profinet IO " +
		"controllers use at boot time to find their distributed I/O devices and " +
		"assign them station names + IP addresses. DCP runs directly over " +
		"Ethernet (EtherType 0x8892) — no IP, no UDP — so it is a Layer 2-only " +
		"protocol bounded to a single broadcast domain. Operationally carries " +
		"Identify (multicast 'who's there?' enumeration), Set (unicast station " +
		"name + IP assignment), Get (unicast attribute query), and Hello " +
		"(multicast announcement an IO device sends after reboot). Decodes:\n\n" +
		"- **FrameID** (2 bytes, big-endian; transmitted immediately after the " +
		"0x8892 EtherType): 0xFEFE DCP Hello / 0xFEFD DCP Get/Set / 0xFEFC DCP " +
		"Identify Request / 0xFEFB DCP Identify Response.\n" +
		"- **DCP header** (10 bytes, big-endian): ServiceID (0x03 Get / 0x04 " +
		"Set / 0x05 Identify / 0x06 Hello) + ServiceType (0x00 Request / 0x01 " +
		"Response_Success / 0x05 Response_Not_Supported) + Xid (uint32 BE " +
		"transaction identifier for request/response pairing) + ResponseDelay " +
		"(uint16 BE; receivers spread the response storm over this many 10-ms " +
		"ticks × DCP_TICK_FACTOR) + DCPDataLength (uint16 BE; bytes of TLV " +
		"blocks following).\n" +
		"- **TLV block walker** — each block: Option (1 byte categorical " +
		"bucket) + Suboption (1 byte per-Option child) + DCPBlockLength (uint16 " +
		"BE; payload bytes INCLUDING the 2-byte BlockInfo for response blocks) " +
		"+ payload. Inter-block padding: blocks are 16-bit-aligned; odd-length " +
		"blocks get a 1-byte 0x00 pad.\n" +
		"- **7-entry Option name table**: 0x01 IP (subopts: MAC / IP_Parameter " +
		"/ Full_IP_Suite) / 0x02 DeviceProperties (subopts: Vendor / " +
		"NameOfStation / DeviceID / DeviceRole / DeviceOptions / AliasName / " +
		"DeviceInstance / OEMDeviceID) / 0x03 DHCP / 0x04 LLDP / 0x05 " +
		"ControlBlock (subopts: Start / Stop / Signal / Response / " +
		"FactoryReset / ResetToFactory) / 0x06 DeviceInitiative / 0xFF " +
		"AllSelector.\n" +
		"- **Per-Option/Suboption decoder set** (high-runners): IP/MAC → 6-byte " +
		"MAC address; IP/IP_Parameter → IPv4 Address + Subnet Mask + Gateway " +
		"(each 4 bytes BE); IP/Full_IP_Suite → IP_Parameter + 4 DNS server " +
		"addresses; DeviceProperties/Vendor → manufacturer name VISIBLE-STRING; " +
		"DeviceProperties/NameOfStation → station name VISIBLE-STRING (the " +
		"unique IO-device identifier used by the IO controller); DeviceProperties" +
		"/DeviceID → VendorID + DeviceID (each uint16 BE); DeviceProperties/" +
		"DeviceRole → bitmask decode (IO-Device / IO-Controller / IO-" +
		"Multidevice / PN-Supervisor); ControlBlock/Signal is the 'flash LED on " +
		"the target' bench-engineering primitive; AllSelector/All is the " +
		"standard IdentifyAll body.\n\n" +
		"Pure offline parser — operators paste Profinet DCP bytes (starting at " +
		"the FrameID, i.e. after the 14-byte Ethernet header + 0x8892 EtherType " +
		"strip) from a Wireshark pn_dcp dissector view or a tshark capture of " +
		"factory-floor traffic and get the documented FrameID + DCP header + " +
		"per-block Option/Suboption breakdown.\n\n" +
		"Out of scope (deferred): L2 framing (feed Profinet DCP bytes after the " +
		"14-byte Ethernet header — destination MAC, source MAC, EtherType " +
		"0x8892; standard DCP destination is multicast group 01:0E:CF:00:00:00 " +
		"for Identify / Hello, or unicast for Get/Set; VLAN tagging via IEEE " +
		"802.1Q with PCP=6 priority is common but part of the L2 frame and not " +
		"parsed here); other Profinet FrameID ranges (RT cyclic I/O data " +
		"FrameID 0x8000-0xBFFF, PTCP timing 0xFF40-0xFF43, Acyclic RT 0xFE00-" +
		"0xFEFA — different frame shapes requiring their own decoders; this " +
		"Spec specifically targets the DCP range 0xFEFB-0xFEFE); BlockInfo " +
		"field (response blocks carry a 2-byte BlockInfo at the start of the " +
		"payload — BlockQualifier + Status; surfaced as raw payload bytes for " +
		"the per-Option decoders to peek at but not separately parsed); " +
		"Profinet IO state-machine (connection establishment CR/AR setup, I/O " +
		"exchange, alarm framing — higher-level analysis driven by GSD file " +
		"metadata).\n\n" +
		"Source: docs/catalog/gap-analysis.md (Siemens factory-floor discovery " +
		"dissector — pairs with s7comm_decode for full Siemens-shop ICS pentest " +
		"coverage; complements goose_decode + iec104_decode for substation + " +
		"factory-floor protocol pairs; targets DEF CON ICS Village CTFs + " +
		"Siemens-shop discovery/enumeration phases). Wrap-vs-native: native — " +
		"IEC 61158-6-10 + the Profinet wiki + Wireshark's pn_dcp dissector " +
		"fully specify the wire format; DCP frames are a tight FrameID + " +
		"10-byte fixed header followed by a TLV block stream with Option/" +
		"Suboption discriminator bytes; no crypto at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Profinet DCP frame bytes starting at the FrameID (after the 14-byte Ethernet header + 0x8892 EtherType strip). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   profinetDCPDecodeHandler,
}

func profinetDCPDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("profinet_dcp_decode: 'hex' is required")
	}
	res, err := profinetdcp.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("profinet_dcp_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
