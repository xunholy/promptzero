// SPDX-License-Identifier: AGPL-3.0-or-later

// Code generated from scapy.contrib.pfcp's IEType / message-type tables
// (3GPP TS 29.244). DO NOT EDIT BY HAND.
package pfcp

import "fmt"

// messageName maps the PFCP message type to its name (TS 29.244).
func messageName(t int) string {
	switch t {
	case 1:
		return "Heartbeat Request"
	case 2:
		return "Heartbeat Response"
	case 3:
		return "PFD Management Request"
	case 4:
		return "PFD Management Response"
	case 5:
		return "Association Setup Request"
	case 6:
		return "Association Setup Response"
	case 7:
		return "Association Update Request"
	case 8:
		return "Association Update Response"
	case 9:
		return "Association Release Request"
	case 10:
		return "Association Release Response"
	case 11:
		return "Version Not Supported Response"
	case 12:
		return "Node Report Request"
	case 13:
		return "Node Report Response"
	case 14:
		return "Session Set Deletion Request"
	case 15:
		return "Session Set Deletion Response"
	case 50:
		return "Session Establishment Request"
	case 51:
		return "Session Establishment Response"
	case 52:
		return "Session Modification Request"
	case 53:
		return "Session Modification Response"
	case 54:
		return "Session Deletion Request"
	case 55:
		return "Session Deletion Response"
	case 56:
		return "Session Report Request"
	case 57:
		return "Session Report Response"
	}
	return fmt.Sprintf("message type %d", t)
}

// ieName maps the PFCP Information Element type to its name (TS 29.244).
func ieName(t int) string {
	switch t {
	case 0:
		return "Reserved"
	case 1:
		return "Create PDR"
	case 2:
		return "PDI"
	case 3:
		return "Create FAR"
	case 4:
		return "Forwarding Parameters"
	case 5:
		return "Duplicating Parameters"
	case 6:
		return "Create URR"
	case 7:
		return "Create QER"
	case 8:
		return "Created PDR"
	case 9:
		return "Update PDR"
	case 10:
		return "Update FAR"
	case 11:
		return "Update Forwarding Parameters"
	case 12:
		return "Update BAR (PFCP Session Report Response)"
	case 13:
		return "Update URR"
	case 14:
		return "Update QER"
	case 15:
		return "Remove PDR"
	case 16:
		return "Remove FAR"
	case 17:
		return "Remove URR"
	case 18:
		return "Remove QER"
	case 19:
		return "Cause"
	case 20:
		return "Source Interface"
	case 21:
		return "F-TEID"
	case 22:
		return "Network Instance"
	case 23:
		return "SDF Filter"
	case 24:
		return "Application ID"
	case 25:
		return "Gate Status"
	case 26:
		return "MBR"
	case 27:
		return "GBR"
	case 28:
		return "QER Correlation ID"
	case 29:
		return "Precedence"
	case 30:
		return "Transport Level Marking"
	case 31:
		return "Volume Threshold"
	case 32:
		return "Time Threshold"
	case 33:
		return "Monitoring Time"
	case 34:
		return "Subsequent Volume Threshold"
	case 35:
		return "Subsequent Time Threshold"
	case 36:
		return "Inactivity Detection Time"
	case 37:
		return "Reporting Triggers"
	case 38:
		return "Redirect Information"
	case 39:
		return "Report Type"
	case 40:
		return "Offending IE"
	case 41:
		return "Forwarding Policy"
	case 42:
		return "Destination Interface"
	case 43:
		return "UP Function Features"
	case 44:
		return "Apply Action"
	case 45:
		return "Downlink Data Service Information"
	case 46:
		return "Downlink Data Notification Delay"
	case 47:
		return "DL Buffering Duration"
	case 48:
		return "DL Buffering Suggested Packet Count"
	case 49:
		return "PFCPSMReq-Flags"
	case 50:
		return "PFCPSRRsp-Flags"
	case 51:
		return "Load Control Information"
	case 52:
		return "Sequence Number"
	case 53:
		return "Metric"
	case 54:
		return "Overload Control Information"
	case 55:
		return "Timer"
	case 56:
		return "PDR ID"
	case 57:
		return "F-SEID"
	case 58:
		return "Application ID's PFDs"
	case 59:
		return "PFD context"
	case 60:
		return "Node ID"
	case 61:
		return "PFD contents"
	case 62:
		return "Measurement Method"
	case 63:
		return "Usage Report Trigger"
	case 64:
		return "Measurement Period"
	case 65:
		return "FQ-CSID"
	case 66:
		return "Volume Measurement"
	case 67:
		return "Duration Measurement"
	case 68:
		return "Application Detection Information"
	case 69:
		return "Time of First Packet"
	case 70:
		return "Time of Last Packet"
	case 71:
		return "Quota Holding Time"
	case 72:
		return "Dropped DL Traffic Threshold"
	case 73:
		return "Volume Quota"
	case 74:
		return "Time Quota"
	case 75:
		return "Start Time"
	case 76:
		return "End Time"
	case 77:
		return "Query URR"
	case 78:
		return "Usage Report (Session Modification Response)"
	case 79:
		return "Usage Report (Session Deletion Response)"
	case 80:
		return "Usage Report (Session Report Request)"
	case 81:
		return "URR ID"
	case 82:
		return "Linked URR ID"
	case 83:
		return "Downlink Data Report"
	case 84:
		return "Outer Header Creation"
	case 85:
		return "Create BAR"
	case 86:
		return "Update BAR (Session Modification Request)"
	case 87:
		return "Remove BAR"
	case 88:
		return "BAR ID"
	case 89:
		return "CP Function Features"
	case 90:
		return "Usage Information"
	case 91:
		return "Application Instance ID"
	case 92:
		return "Flow Information"
	case 93:
		return "UE IP Address"
	case 94:
		return "Packet Rate"
	case 95:
		return "Outer Header Removal"
	case 96:
		return "Recovery Time Stamp"
	case 97:
		return "DL Flow Level Marking"
	case 98:
		return "Header Enrichment"
	case 99:
		return "Error Indication Report"
	case 100:
		return "Measurement Information"
	case 101:
		return "Node Report Type"
	case 102:
		return "User Plane Path Failure Report"
	case 103:
		return "Remote GTP-U Peer"
	case 104:
		return "UR-SEQN"
	case 105:
		return "Update Duplicating Parameters"
	case 106:
		return "Activate Predefined Rules"
	case 107:
		return "Deactivate Predefined Rules"
	case 108:
		return "FAR ID"
	case 109:
		return "QER ID"
	case 110:
		return "OCI Flags"
	case 111:
		return "PFCP Association Release Request"
	case 112:
		return "Graceful Release Period"
	case 113:
		return "PDN Type"
	case 114:
		return "Failed Rule ID"
	case 115:
		return "Time Quota Mechanism"
	case 116:
		return "User Plane IP Resource Information"
	case 117:
		return "User Plane Inactivity Timer"
	case 118:
		return "Aggregated URRs"
	case 119:
		return "Multiplier"
	case 120:
		return "Aggregated URR ID"
	case 121:
		return "Subsequent Volume Quota"
	case 122:
		return "Subsequent Time Quota"
	case 123:
		return "RQI"
	case 124:
		return "QFI"
	case 125:
		return "Query URR Reference"
	case 126:
		return "Additional Usage Reports Information"
	case 127:
		return "Create Traffic Endpoint"
	case 128:
		return "Created Traffic Endpoint"
	case 129:
		return "Update Traffic Endpoint"
	case 130:
		return "Remove Traffic Endpoint"
	case 131:
		return "Traffic Endpoint ID"
	case 132:
		return "Ethernet Packet Filter"
	case 133:
		return "MAC Address"
	case 134:
		return "C-TAG"
	case 135:
		return "S-TAG"
	case 136:
		return "Ethertype"
	case 137:
		return "Proxying"
	case 138:
		return "Ethernet Filter ID"
	case 139:
		return "Ethernet Filter Properties"
	case 140:
		return "Suggested Buffering Packets Count"
	case 141:
		return "User ID"
	case 142:
		return "Ethernet PDU Session Information"
	case 143:
		return "Ethernet Traffic Information"
	case 144:
		return "MAC Addresses Detected"
	case 145:
		return "MAC Addresses Removed"
	case 146:
		return "Ethernet Inactivity Timer"
	case 147:
		return "Additional Monitoring Time"
	case 148:
		return "Event Quota"
	case 149:
		return "Event Threshold"
	case 150:
		return "Subsequent Event Quota"
	case 151:
		return "Subsequent Event Threshold"
	case 152:
		return "Trace Information"
	case 153:
		return "Framed-Route"
	case 154:
		return "Framed-Routing"
	case 155:
		return "Framed-IPv6-Route"
	case 156:
		return "Event Time Stamp"
	case 157:
		return "Averaging Window"
	case 158:
		return "Paging Policy Indicator"
	case 159:
		return "APN/DNN"
	case 160:
		return "3GPP Interface Type"
	}
	return fmt.Sprintf("IE type %d", t)
}
