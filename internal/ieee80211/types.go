package ieee80211

// subtypeNames maps (type, subtype) pairs to the canonical
// IEEE 802.11 subtype name. Covers management subtypes (the
// ones operators most often parse) plus a handful of well-known
// data / control subtypes for context.
var subtypeNames = map[int]map[int]string{
	0: { // Management
		0:  "Association Request",
		1:  "Association Response",
		2:  "Reassociation Request",
		3:  "Reassociation Response",
		4:  "Probe Request",
		5:  "Probe Response",
		8:  "Beacon",
		9:  "ATIM",
		10: "Disassociation",
		11: "Authentication",
		12: "Deauthentication",
		13: "Action",
	},
	1: { // Control
		8:  "Block Ack Request",
		9:  "Block Ack",
		10: "PS-Poll",
		11: "RTS",
		12: "CTS",
		13: "ACK",
		14: "CF-End",
		15: "CF-End + CF-Ack",
	},
	2: { // Data
		0:  "Data",
		1:  "Data + CF-Ack",
		2:  "Data + CF-Poll",
		3:  "Data + CF-Ack + CF-Poll",
		4:  "Null function (no data)",
		5:  "CF-Ack (no data)",
		6:  "CF-Poll (no data)",
		7:  "CF-Ack + CF-Poll (no data)",
		8:  "QoS Data",
		9:  "QoS Data + CF-Ack",
		10: "QoS Data + CF-Poll",
		11: "QoS Data + CF-Ack + CF-Poll",
		12: "QoS Null (no data)",
		14: "QoS CF-Poll (no data)",
		15: "QoS CF-Ack + CF-Poll (no data)",
	},
}

func subtypeName(t, st int) string {
	if subs, ok := subtypeNames[t]; ok {
		if name, ok := subs[st]; ok {
			return name
		}
	}
	return "Unknown"
}

// ieNames maps Information Element IDs to their canonical name
// per IEEE 802.11-2020 §9.4.2 Table 9-92. Limited to the IEs
// operators commonly see in beacon / probe response / assoc
// frames.
var ieNames = map[byte]string{
	0:   "SSID",
	1:   "Supported Rates",
	2:   "FH Parameter Set",
	3:   "DS Parameter Set",
	4:   "CF Parameter Set",
	5:   "TIM",
	6:   "IBSS Parameter Set",
	7:   "Country",
	8:   "Hopping Pattern Parameters",
	11:  "QBSS Load Element",
	12:  "EDCA Parameter Set",
	16:  "Challenge text",
	32:  "Power Constraint",
	33:  "Power Capability",
	34:  "TPC Request",
	35:  "TPC Report",
	36:  "Supported Channels",
	37:  "Channel Switch Announcement",
	38:  "Measurement Request",
	39:  "Measurement Report",
	40:  "Quiet",
	41:  "IBSS DFS",
	42:  "ERP",
	45:  "HT Capabilities",
	46:  "QoS Capability",
	48:  "RSN (WPA2/WPA3)",
	50:  "Extended Supported Rates",
	51:  "AP Channel Report",
	52:  "Neighbor Report",
	61:  "HT Operation",
	62:  "Secondary Channel Offset",
	74:  "Overlapping BSS Scan Parameters",
	107: "Interworking",
	108: "Advertisement Protocol",
	111: "Roaming Consortium",
	127: "Extended Capabilities",
	191: "VHT Capabilities",
	192: "VHT Operation",
	194: "Wide Bandwidth Channel Switch",
	195: "VHT Transmit Power Envelope",
	196: "Channel Switch Wrapper",
	197: "AID",
	221: "Vendor Specific",
	255: "Element ID Extension",
}

func ieName(id byte) string {
	if n, ok := ieNames[id]; ok {
		return n
	}
	return "Unknown"
}

// reasonCodes maps the documented Disassociation /
// Deauthentication reason codes to operator-facing names. Per
// IEEE 802.11-2020 §9.4.1.7 Table 9-49.
var reasonCodes = map[int]string{
	1:  "Unspecified reason",
	2:  "Previous authentication no longer valid",
	3:  "Deauthenticated because sending STA is leaving",
	4:  "Disassociated due to inactivity",
	5:  "Disassociated because AP is unable to handle all currently associated STAs",
	6:  "Class 2 frame received from nonauthenticated STA",
	7:  "Class 3 frame received from nonassociated STA",
	8:  "Disassociated because sending STA is leaving BSS",
	9:  "STA requesting (re)association is not authenticated with responding STA",
	10: "Disassociated because the information in the Power Capability element is unacceptable",
	11: "Disassociated because the information in the Supported Channels element is unacceptable",
	13: "Invalid information element",
	14: "Message integrity code (MIC) failure",
	15: "4-Way Handshake timeout",
	16: "Group Key Handshake timeout",
	17: "Information element in 4-Way Handshake different from (Re)Association Request",
	18: "Invalid group cipher",
	19: "Invalid pairwise cipher",
	20: "Invalid AKMP",
	21: "Unsupported RSN information element version",
	22: "Invalid RSN information element capabilities",
	23: "IEEE 802.1X authentication failed",
	24: "Cipher suite rejected because of the security policy",
	25: "TDLS direct-link teardown due to TDLS peer STA unreachable via the TDLS direct link",
	26: "TDLS direct-link teardown for unspecified reason",
	34: "Disassociated because excessive number of frames need to be acknowledged, but are not acknowledged due to AP transmissions and/or poor channel conditions",
	35: "Disassociated because STA is transmitting outside the limits of its TXOPs",
	39: "Requested from peer STA as it is leaving the BSS (or resetting)",
	40: "Requested from peer STA as it does not want to use the mechanism",
	41: "Requested from peer STA as the STA received frames using the mechanism for which a setup is required",
	42: "Requested from peer STA due to timeout",
	45: "Peer STA does not support the requested cipher suite",
}

func reasonCodeName(rc int) string {
	if n, ok := reasonCodes[rc]; ok {
		return n
	}
	return "Reserved / unknown"
}

// wellKnownVendors maps the most-commonly-seen Vendor Specific
// IE OUIs to vendor names. OUI key is the 3-byte OUI packed as
// uint32 (high byte = first OUI byte). Source: IEEE OUI
// registry — limited to vendors operators commonly see in
// real-world WiFi captures.
var wellKnownVendors = map[uint32]string{
	0x0050F2: "Microsoft (WPA / WPS)",
	0x000B86: "Aruba Networks",
	0x000FAC: "IEEE (RSN)",
	0x00904C: "Epigram (HT pre-N draft)",
	0x001018: "Broadcom",
	0x00037F: "Atheros",
	0x506F9A: "Wi-Fi Alliance (WFA — P2P, MBO, etc.)",
	0x001392: "Cisco",
	0x0024F4: "Apple",
	0x00037A: "BlackBerry",
}
