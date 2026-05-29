// SPDX-License-Identifier: AGPL-3.0-or-later

package knxnetip

// Service type identifiers (KNX Standard 3/8/2 §4.2). Grouped by
// service family in the high byte.
const (
	// Core (0x02xx)
	stSearchRequest          = 0x0201
	stSearchResponse         = 0x0202
	stDescriptionRequest     = 0x0203
	stDescriptionResponse    = 0x0204
	stConnectRequest         = 0x0205
	stConnectResponse        = 0x0206
	stConnectionStateRequest = 0x0207
	stConnectionStateResp    = 0x0208
	stDisconnectRequest      = 0x0209
	stDisconnectResponse     = 0x020A
	stSearchRequestExt       = 0x020B
	stSearchResponseExt      = 0x020C

	// Device Management (0x03xx)
	stDeviceConfigurationRequest = 0x0310
	stDeviceConfigurationAck     = 0x0311

	// Tunnelling (0x04xx)
	stTunnellingRequest     = 0x0420
	stTunnellingAck         = 0x0421
	stTunnellingFeatureGet  = 0x0430
	stTunnellingFeatureResp = 0x0431
	stTunnellingFeatureSet  = 0x0432
	stTunnellingFeatureInfo = 0x0433

	// Routing (0x05xx)
	stRoutingIndication  = 0x0530
	stRoutingLostMessage = 0x0531
	stRoutingBusy        = 0x0532

	// KNXnet/IP Secure (0x09xx)
	stSecureWrapper       = 0x0950
	stSecureSessionReq    = 0x0951
	stSecureSessionResp   = 0x0952
	stSecureSessionAuth   = 0x0953
	stSecureSessionStatus = 0x0954
	stSecureTimerNotify   = 0x0955
)

var serviceTypeNames = map[int]string{
	stSearchRequest:              "SEARCH_REQUEST",
	stSearchResponse:             "SEARCH_RESPONSE",
	stDescriptionRequest:         "DESCRIPTION_REQUEST",
	stDescriptionResponse:        "DESCRIPTION_RESPONSE",
	stConnectRequest:             "CONNECT_REQUEST",
	stConnectResponse:            "CONNECT_RESPONSE",
	stConnectionStateRequest:     "CONNECTIONSTATE_REQUEST",
	stConnectionStateResp:        "CONNECTIONSTATE_RESPONSE",
	stDisconnectRequest:          "DISCONNECT_REQUEST",
	stDisconnectResponse:         "DISCONNECT_RESPONSE",
	stSearchRequestExt:           "SEARCH_REQUEST_EXTENDED",
	stSearchResponseExt:          "SEARCH_RESPONSE_EXTENDED",
	stDeviceConfigurationRequest: "DEVICE_CONFIGURATION_REQUEST",
	stDeviceConfigurationAck:     "DEVICE_CONFIGURATION_ACK",
	stTunnellingRequest:          "TUNNELLING_REQUEST",
	stTunnellingAck:              "TUNNELLING_ACK",
	stTunnellingFeatureGet:       "TUNNELLING_FEATURE_GET",
	stTunnellingFeatureResp:      "TUNNELLING_FEATURE_RESPONSE",
	stTunnellingFeatureSet:       "TUNNELLING_FEATURE_SET",
	stTunnellingFeatureInfo:      "TUNNELLING_FEATURE_INFO",
	stRoutingIndication:          "ROUTING_INDICATION",
	stRoutingLostMessage:         "ROUTING_LOST_MESSAGE",
	stRoutingBusy:                "ROUTING_BUSY",
	stSecureWrapper:              "SECURE_WRAPPER",
	stSecureSessionReq:           "SESSION_REQUEST",
	stSecureSessionResp:          "SESSION_RESPONSE",
	stSecureSessionAuth:          "SESSION_AUTHENTICATE",
	stSecureSessionStatus:        "SESSION_STATUS",
	stSecureTimerNotify:          "TIMER_NOTIFY",
}

func serviceTypeName(st int) string {
	if n, ok := serviceTypeNames[st]; ok {
		return n
	}
	return "UNKNOWN"
}

func serviceFamily(st int) string {
	switch st >> 8 {
	case 0x02:
		return "Core"
	case 0x03:
		return "Device Management"
	case 0x04:
		return "Tunnelling"
	case 0x05:
		return "Routing"
	case 0x06:
		return "Remote Logging"
	case 0x07:
		return "Remote Configuration & Diagnosis"
	case 0x08:
		return "Object Server"
	case 0x09:
		return "KNXnet/IP Secure"
	default:
		return "Unknown"
	}
}

func hostProtocolName(code int) string {
	switch code {
	case 0x01:
		return "IPv4 UDP"
	case 0x02:
		return "IPv4 TCP"
	default:
		return "Unknown"
	}
}

// cEMI message codes (KNX Standard 3/6/3 §4.1.3.3).
const (
	cemiLDataReq = 0x11 // L_Data.req — request onto the bus
	cemiLDataCon = 0x2E // L_Data.con — confirmation
	cemiLDataInd = 0x29 // L_Data.ind — indication (received)
)

var cemiMessageCodeNames = map[int]string{
	0x11: "L_Data.req",
	0x2E: "L_Data.con",
	0x29: "L_Data.ind",
	0x10: "L_Raw.req",
	0x2D: "L_Raw.ind",
	0x2F: "L_Raw.con",
	0x13: "L_Poll_Data.req",
	0x25: "L_Poll_Data.con",
	0xFC: "M_PropRead.req",
	0xFB: "M_PropRead.con",
	0xF6: "M_PropWrite.req",
	0xF5: "M_PropWrite.con",
	0xF7: "M_PropInfo.ind",
	0xF8: "M_FuncPropCommand.req",
	0xFA: "M_FuncPropStateRead.req",
	0xF9: "M_FuncPropCommand/StateRead.con",
	0xF1: "M_Reset.req",
	0xF0: "M_Reset.ind",
}

func cemiMessageCodeName(mc int) string {
	if n, ok := cemiMessageCodeNames[mc]; ok {
		return n
	}
	return "unknown"
}

// apciName classifies a 10-bit APCI (Application-layer Protocol
// Control Information) value. The four-bit and ten-bit encodings
// overlap by range, so the common GroupValue services are matched
// by their value windows (KNX Standard 3/3/7 §3).
func apciName(apci int) string {
	switch {
	case apci == 0x000:
		return "A_GroupValue_Read"
	case apci >= 0x040 && apci <= 0x07F:
		return "A_GroupValue_Response"
	case apci >= 0x080 && apci <= 0x0BF:
		return "A_GroupValue_Write"
	case apci == 0x0C0:
		return "A_IndividualAddress_Write"
	case apci == 0x100:
		return "A_IndividualAddress_Read"
	case apci == 0x140:
		return "A_IndividualAddress_Response"
	case apci == 0x1C0:
		return "A_ADC_Read"
	case apci >= 0x200 && apci <= 0x23F:
		return "A_Memory_Read"
	case apci >= 0x240 && apci <= 0x27F:
		return "A_Memory_Response"
	case apci >= 0x280 && apci <= 0x2BF:
		return "A_Memory_Write"
	case apci == 0x300:
		return "A_DeviceDescriptor_Read"
	case apci == 0x340:
		return "A_DeviceDescriptor_Response"
	case apci == 0x380:
		return "A_Restart"
	case apci == 0x3D1:
		return "A_Authorize_Request"
	case apci == 0x3D3:
		return "A_Key_Write"
	default:
		return "unknown"
	}
}
