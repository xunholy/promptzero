// SPDX-License-Identifier: AGPL-3.0-or-later

package gtpv2

import "fmt"

// messageName maps the GTPv2-C message type to its name (3GPP TS 29.274
// Table 6.1-1). The common EPS session / bearer messages are covered.
func messageName(t int) string {
	switch t {
	case 1:
		return "Echo Request"
	case 2:
		return "Echo Response"
	case 3:
		return "Version Not Supported Indication"
	case 32:
		return "Create Session Request"
	case 33:
		return "Create Session Response"
	case 34:
		return "Modify Bearer Request"
	case 35:
		return "Modify Bearer Response"
	case 36:
		return "Delete Session Request"
	case 37:
		return "Delete Session Response"
	case 40:
		return "Remote UE Report Notification"
	case 64:
		return "Modify Bearer Command"
	case 65:
		return "Modify Bearer Failure Indication"
	case 66:
		return "Delete Bearer Command"
	case 67:
		return "Delete Bearer Failure Indication"
	case 68:
		return "Bearer Resource Command"
	case 70:
		return "Bearer Resource Failure Indication"
	case 95:
		return "Create Bearer Request"
	case 96:
		return "Create Bearer Response"
	case 97:
		return "Update Bearer Request"
	case 98:
		return "Update Bearer Response"
	case 99:
		return "Delete Bearer Request"
	case 100:
		return "Delete Bearer Response"
	case 128:
		return "Identification Request"
	case 129:
		return "Identification Response"
	case 130:
		return "Context Request"
	case 131:
		return "Context Response"
	case 132:
		return "Context Acknowledge"
	case 133:
		return "Forward Relocation Request"
	case 134:
		return "Forward Relocation Response"
	case 160:
		return "Create Forwarding Tunnel Request"
	case 170:
		return "Release Access Bearers Request"
	case 171:
		return "Release Access Bearers Response"
	case 176:
		return "Downlink Data Notification"
	case 177:
		return "Downlink Data Notification Acknowledge"
	}
	return fmt.Sprintf("message type %d", t)
}

// ieName maps the GTPv2-C Information Element type to its name (3GPP
// TS 29.274 Table 8.1-1). The common IEs are covered; others are
// surfaced by their numeric type.
func ieName(t int) string {
	switch t {
	case 1:
		return "IMSI"
	case 2:
		return "Cause"
	case 3:
		return "Recovery"
	case 71:
		return "APN"
	case 72:
		return "AMBR"
	case 73:
		return "EPS Bearer ID (EBI)"
	case 74:
		return "IP Address"
	case 75:
		return "MEI"
	case 76:
		return "MSISDN"
	case 77:
		return "Indication"
	case 78:
		return "Protocol Configuration Options (PCO)"
	case 79:
		return "PDN Address Allocation (PAA)"
	case 80:
		return "Bearer QoS"
	case 82:
		return "RAT Type"
	case 83:
		return "Serving Network"
	case 86:
		return "User Location Info (ULI)"
	case 87:
		return "F-TEID"
	case 93:
		return "Bearer Context"
	case 94:
		return "Charging ID"
	case 95:
		return "Charging Characteristics"
	case 99:
		return "PDN Type"
	case 103:
		return "APN Restriction"
	case 107:
		return "MM Context"
	case 109:
		return "PDN Connection"
	case 114:
		return "UE Time Zone"
	case 126:
		return "Port Number"
	case 127:
		return "APN Aggregate Max Bit Rate"
	case 255:
		return "Private Extension"
	}
	return fmt.Sprintf("IE type %d", t)
}
