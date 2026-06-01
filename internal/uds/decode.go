// SPDX-License-Identifier: AGPL-3.0-or-later

// Package uds decodes UDS (Unified Diagnostic Services, ISO 14229-1)
// application-layer messages — the protocol behind modern ECU diagnostics
// and attacks (session control, security access, routine control, memory
// read/write, firmware transfer). It names the service, classifies the
// message as a request / positive response / negative response, decodes the
// negative-response code, and surfaces the sub-function and data identifier
// where they apply.
//
// # Wrap-vs-native judgement
//
// Native. The UDS service-ID assignments, the positive-response convention
// (response SID = request SID + 0x40), the 0x7F negative-response framing,
// and the negative-response-code (NRC) table are a public ISO standard
// (ISO 14229-1), reproduced identically by python-udsoncan, CaringCaribou,
// and Wireshark's UDS dissector. Decoding is a static lookup over the
// reassembled application PDU — no ISO-TP reassembly, no bus, no hardware at
// analysis time (the caller brings the assembled message, e.g. from a
// canbus capture). The j1850 decoder explicitly covers only legacy OBD-II
// modes 1-9 and notes UDS as out of scope; this fills that gap.
//
// # No confidently-wrong output
//
// Only ISO-14229-assigned service IDs, NRCs, and the common sub-function
// enums are named; an unknown service / NRC / sub-function value, and every
// manufacturer-specific data identifier, is surfaced with its raw hex and
// numeric value, never guessed. ISO-TP framing, the security-access seed/key
// crypto, and full per-service payload dissection are deliberately left to
// the raw payload bytes.
package uds

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// NegativeResponseSID is the service-ID byte that introduces a negative
// response: 0x7F <originalSID> <NRC>.
const NegativeResponseSID = 0x7F

// UDS is the decoded view of a UDS message.
type UDS struct {
	Direction                string   `json:"direction"` // request | positive_response | negative_response
	ServiceID                int      `json:"service_id"`
	ServiceIDHex             string   `json:"service_id_hex"`
	Service                  string   `json:"service"`
	SubFunction              *int     `json:"sub_function,omitempty"`
	SubFunctionName          string   `json:"sub_function_name,omitempty"`
	SuppressPositiveResponse bool     `json:"suppress_positive_response,omitempty"`
	DataIdentifier           *int     `json:"data_identifier,omitempty"`
	DataIdentifierName       string   `json:"data_identifier_name,omitempty"`
	NRC                      *int     `json:"nrc,omitempty"`
	NRCName                  string   `json:"nrc_name,omitempty"`
	PayloadHex               string   `json:"payload_hex,omitempty"`
	Notes                    []string `json:"notes,omitempty"`
}

var serviceNames = map[int]string{
	0x10: "DiagnosticSessionControl",
	0x11: "ECUReset",
	0x14: "ClearDiagnosticInformation",
	0x19: "ReadDTCInformation",
	0x22: "ReadDataByIdentifier",
	0x23: "ReadMemoryByAddress",
	0x24: "ReadScalingDataByIdentifier",
	0x27: "SecurityAccess",
	0x28: "CommunicationControl",
	0x29: "Authentication",
	0x2A: "ReadDataByPeriodicIdentifier",
	0x2C: "DynamicallyDefineDataIdentifier",
	0x2E: "WriteDataByIdentifier",
	0x2F: "InputOutputControlByIdentifier",
	0x31: "RoutineControl",
	0x34: "RequestDownload",
	0x35: "RequestUpload",
	0x36: "TransferData",
	0x37: "RequestTransferExit",
	0x38: "RequestFileTransfer",
	0x3D: "WriteMemoryByAddress",
	0x3E: "TesterPresent",
	0x83: "AccessTimingParameter",
	0x84: "SecuredDataTransmission",
	0x85: "ControlDTCSetting",
	0x86: "ResponseOnEvent",
	0x87: "LinkControl",
}

var nrcNames = map[int]string{
	0x10: "generalReject",
	0x11: "serviceNotSupported",
	0x12: "subFunctionNotSupported",
	0x13: "incorrectMessageLengthOrInvalidFormat",
	0x14: "responseTooLong",
	0x21: "busyRepeatRequest",
	0x22: "conditionsNotCorrect",
	0x24: "requestSequenceError",
	0x25: "noResponseFromSubnetComponent",
	0x26: "failurePreventsExecutionOfRequestedAction",
	0x31: "requestOutOfRange",
	0x33: "securityAccessDenied",
	0x34: "authenticationRequired",
	0x35: "invalidKey",
	0x36: "exceededNumberOfAttempts",
	0x37: "requiredTimeDelayNotExpired",
	0x70: "uploadDownloadNotAccepted",
	0x71: "transferDataSuspended",
	0x72: "generalProgrammingFailure",
	0x73: "wrongBlockSequenceCounter",
	0x78: "requestCorrectlyReceived-ResponsePending",
	0x7E: "subFunctionNotSupportedInActiveSession",
	0x7F: "serviceNotSupportedInActiveSession",
	0x81: "rpmTooHigh",
	0x82: "rpmTooLow",
	0x83: "engineIsRunning",
	0x84: "engineIsNotRunning",
	0x85: "engineRunTimeTooLow",
	0x86: "temperatureTooHigh",
	0x87: "temperatureTooLow",
	0x88: "vehicleSpeedTooHigh",
	0x89: "vehicleSpeedTooLow",
	0x8A: "throttle/PedalTooHigh",
	0x8B: "throttle/PedalTooLow",
	0x8C: "transmissionRangeNotInNeutral",
	0x8D: "transmissionRangeNotInGear",
	0x8F: "brakeSwitchesNotClosed",
	0x90: "shifterLeverNotInPark",
	0x91: "torqueConverterClutchLocked",
	0x92: "voltageTooHigh",
	0x93: "voltageTooLow",
}

// subFnDecoders maps services that carry a sub-function to an enum decoder
// for the common values; nil-result values fall back to the raw byte.
var subFnDecoders = map[int]map[int]string{
	0x10: {0x01: "defaultSession", 0x02: "programmingSession", 0x03: "extendedDiagnosticSession", 0x04: "safetySystemDiagnosticSession"},
	0x11: {0x01: "hardReset", 0x02: "keyOffOnReset", 0x03: "softReset", 0x04: "enableRapidPowerShutDown", 0x05: "disableRapidPowerShutDown"},
	0x31: {0x01: "startRoutine", 0x02: "stopRoutine", 0x03: "requestRoutineResults"},
	0x85: {0x01: "on", 0x02: "off"},
	0x28: {0x00: "enableRxAndTx", 0x01: "enableRxAndDisableTx", 0x02: "disableRxAndEnableTx", 0x03: "disableRxAndTx"},
	0x3E: {0x00: "zeroSubFunction"},
}

// hasSubFunction reports whether a service's first data byte is a
// sub-function (with the suppressPositiveResponse bit in bit 7).
var hasSubFunction = map[int]bool{
	0x10: true, 0x11: true, 0x19: true, 0x27: true, 0x28: true,
	0x29: true, 0x31: true, 0x3E: true, 0x83: true, 0x85: true,
	0x86: true, 0x87: true,
}

// hasDID reports whether a service's first two data bytes are a 16-bit
// data identifier.
var hasDID = map[int]bool{0x22: true, 0x2E: true, 0x2C: true}

var knownDIDs = map[int]string{
	0xF180: "BootSoftwareIdentification",
	0xF186: "ActiveDiagnosticSession",
	0xF187: "VehicleManufacturerSparePartNumber",
	0xF188: "VehicleManufacturerECUSoftwareNumber",
	0xF18C: "ECUSerialNumber",
	0xF190: "VIN",
	0xF191: "VehicleManufacturerECUHardwareNumber",
	0xF195: "SystemSupplierECUSoftwareVersionNumber",
	0xF1A0: "VehicleManufacturerSpecific",
}

// Decode parses a hex-encoded UDS application PDU (the reassembled message,
// without ISO-TP framing). Separators and a 0x prefix are tolerated.
func Decode(hexStr string) (*UDS, error) {
	clean := strings.NewReplacer(" ", "", ":", "", "-", "", "_", "", "\n", "", "\t", "").Replace(strings.TrimSpace(hexStr))
	if strings.HasPrefix(strings.ToLower(clean), "0x") {
		clean = clean[2:]
	}
	if clean == "" {
		return nil, fmt.Errorf("uds: empty input")
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("uds: invalid hex: %w", err)
	}
	return DecodeBytes(b)
}

// DecodeBytes parses a UDS application PDU from raw bytes.
func DecodeBytes(b []byte) (*UDS, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("uds: empty message")
	}
	sid := int(b[0])

	// Negative response: 0x7F <originalSID> <NRC>.
	if sid == NegativeResponseSID {
		out := &UDS{Direction: "negative_response", ServiceID: NegativeResponseSID, ServiceIDHex: "0x7F", Service: "NegativeResponse"}
		if len(b) < 3 {
			out.Notes = append(out.Notes, "negative response truncated; want 0x7F <SID> <NRC>")
			return out, nil
		}
		reqSID := int(b[1])
		out.ServiceID = reqSID
		out.ServiceIDHex = fmt.Sprintf("0x%02X", reqSID)
		out.Service = serviceName(reqSID)
		nrc := int(b[2])
		out.NRC = &nrc
		out.NRCName = nrcName(nrc)
		if len(b) > 3 {
			out.PayloadHex = hexUpper(b[3:])
		}
		return out, nil
	}

	// Positive response: SID = request SID + 0x40.
	if _, ok := serviceNames[sid-0x40]; ok {
		return decodeServicePDU(sid-0x40, "positive_response", b), nil
	}
	// Request.
	return decodeServicePDU(sid, "request", b), nil
}

// decodeServicePDU fills the common fields for a request / positive
// response, where svc is the request service ID and b starts at the actual
// SID byte (request SID, or response SID = svc+0x40).
func decodeServicePDU(svc int, dir string, b []byte) *UDS {
	out := &UDS{
		Direction:    dir,
		ServiceID:    svc,
		ServiceIDHex: fmt.Sprintf("0x%02X", svc),
		Service:      serviceName(svc),
	}
	data := b[1:]
	off := 0

	if hasSubFunction[svc] && off < len(data) {
		raw := int(data[off])
		sf := raw & 0x7F
		out.SubFunction = &sf
		out.SuppressPositiveResponse = raw&0x80 != 0
		if m, ok := subFnDecoders[svc]; ok {
			if name, ok := m[sf]; ok {
				out.SubFunctionName = name
			}
		}
		off++
	}

	if hasDID[svc] && off+1 < len(data) {
		did := int(data[off])<<8 | int(data[off+1])
		out.DataIdentifier = &did
		out.DataIdentifierName = knownDIDs[did]
		off += 2
	}

	if off < len(data) {
		out.PayloadHex = hexUpper(data[off:])
	}
	if serviceNames[svc] == "" {
		out.Notes = append(out.Notes, fmt.Sprintf("service 0x%02X not in the ISO 14229 table (manufacturer-specific?)", svc))
	}
	return out
}

func serviceName(sid int) string {
	if n, ok := serviceNames[sid]; ok {
		return n
	}
	return fmt.Sprintf("Unknown service 0x%02X", sid)
}

func nrcName(nrc int) string {
	if n, ok := nrcNames[nrc]; ok {
		return n
	}
	if nrc >= 0x38 && nrc <= 0x4F {
		return fmt.Sprintf("reservedByExtendedDataLinkSecurityDocument (0x%02X)", nrc)
	}
	return fmt.Sprintf("Unknown/ISOSAEReserved (0x%02X)", nrc)
}

func hexUpper(b []byte) string { return strings.ToUpper(hex.EncodeToString(b)) }
