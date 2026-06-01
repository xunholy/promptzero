// SPDX-License-Identifier: AGPL-3.0-or-later

// Package kwp decodes KWP2000 (Keyword Protocol 2000, ISO 14230-3)
// diagnostic messages — the predecessor to UDS still spoken by many
// pre-CAN / early-CAN ECUs and ELM327 adapters. It names the service,
// classifies the message as a request / positive response / negative
// response, and decodes the negative-response code.
//
// # Wrap-vs-native judgement
//
// Native. KWP2000 shares UDS's application framing (positive response =
// request SID + 0x40; negative response = 0x7F <SID> <NRC>) but has a
// DISTINCT service-ID table — the local-identifier services (0x21
// ReadDataByLocalIdentifier, 0x30 InputOutputControlByLocalIdentifier, 0x31
// StartRoutineByLocalIdentifier, 0x3B WriteDataByLocalIdentifier, …) and the
// communication-control services (0x81 StartCommunication, 0x82
// StopCommunication) do not exist in UDS, and some shared SID numbers carry
// different meanings. Decoding KWP traffic with uds_decode would therefore
// mislabel it; this is the dedicated, correct table. The service-ID and NRC
// assignments are a public ISO standard (ISO 14230-3), reproduced
// identically by ELM327 tooling, CaringCaribou and Wireshark. It is a
// static lookup over the application PDU — no bus, no ISO-TP reassembly, no
// hardware (the caller brings the assembled message, e.g. from a canbus /
// isotp capture). The j1850 decoder explicitly lists KWP2000 as out of
// scope; this fills that gap.
//
// # No confidently-wrong output
//
// Only ISO-14230-assigned service IDs and NRCs are named; an unknown service
// or NRC is surfaced with its raw hex and numeric value, never guessed. The
// byte after the SID is surfaced with a per-service label (diagnostic
// session, local identifier, access mode, …) but its value enum is NOT
// guessed — KWP sub-function/identifier values are largely
// manufacturer-defined, so the raw byte plus the remaining payload are
// surfaced for the operator to interpret.
package kwp

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// NegativeResponseSID introduces a negative response: 0x7F <SID> <NRC>.
const NegativeResponseSID = 0x7F

// KWP is the decoded view of a KWP2000 message.
type KWP struct {
	Direction    string   `json:"direction"` // request | positive_response | negative_response
	ServiceID    int      `json:"service_id"`
	ServiceIDHex string   `json:"service_id_hex"`
	Service      string   `json:"service"`
	ParamByte    *int     `json:"param_byte,omitempty"`
	ParamLabel   string   `json:"param_label,omitempty"`
	NRC          *int     `json:"nrc,omitempty"`
	NRCName      string   `json:"nrc_name,omitempty"`
	PayloadHex   string   `json:"payload_hex,omitempty"`
	Notes        []string `json:"notes,omitempty"`
}

var serviceNames = map[int]string{
	0x10: "StartDiagnosticSession",
	0x11: "ECUReset",
	0x14: "ClearDiagnosticInformation",
	0x18: "ReadDTCByStatus",
	0x1A: "ReadECUIdentification",
	0x21: "ReadDataByLocalIdentifier",
	0x22: "ReadDataByCommonIdentifier",
	0x23: "ReadMemoryByAddress",
	0x27: "SecurityAccess",
	0x28: "DisableNormalMessageTransmission",
	0x29: "EnableNormalMessageTransmission",
	0x2C: "DynamicallyDefineLocalIdentifier",
	0x2E: "WriteDataByCommonIdentifier",
	0x2F: "InputOutputControlByCommonIdentifier",
	0x30: "InputOutputControlByLocalIdentifier",
	0x31: "StartRoutineByLocalIdentifier",
	0x32: "StopRoutineByLocalIdentifier",
	0x33: "RequestRoutineResultsByLocalIdentifier",
	0x34: "RequestDownload",
	0x35: "RequestUpload",
	0x36: "TransferData",
	0x37: "RequestTransferExit",
	0x38: "StartRoutineByAddress",
	0x39: "StopRoutineByAddress",
	0x3A: "RequestRoutineResultsByAddress",
	0x3B: "WriteDataByLocalIdentifier",
	0x3D: "WriteMemoryByAddress",
	0x3E: "TesterPresent",
	0x81: "StartCommunication",
	0x82: "StopCommunication",
	0x83: "AccessTimingParameter",
	0x84: "NetworkConfiguration",
	0x85: "ControlDTCSetting",
	0x86: "ResponseOnEvent",
}

// paramLabels names the byte after the SID for services that carry one.
var paramLabels = map[int]string{
	0x10: "diagnostic_session_type",
	0x11: "reset_mode",
	0x18: "dtc_status_group",
	0x21: "local_identifier",
	0x27: "access_mode",
	0x28: "transmission_control",
	0x29: "transmission_control",
	0x30: "local_identifier",
	0x31: "routine_local_identifier",
	0x32: "routine_local_identifier",
	0x33: "routine_local_identifier",
	0x3B: "local_identifier",
	0x85: "dtc_setting_type",
}

var nrcNames = map[int]string{
	0x10: "generalReject",
	0x11: "serviceNotSupported",
	0x12: "subFunctionNotSupported-invalidFormat",
	0x21: "busyRepeatRequest",
	0x22: "conditionsNotCorrectOrRequestSequenceError",
	0x23: "routineNotCompleteOrServiceInProgress",
	0x31: "requestOutOfRange",
	0x33: "securityAccessDenied",
	0x35: "invalidKey",
	0x36: "exceedNumberOfAttempts",
	0x37: "requiredTimeDelayNotExpired",
	0x40: "downloadNotAccepted",
	0x41: "improperDownloadType",
	0x42: "cantDownloadToSpecifiedAddress",
	0x43: "cantDownloadNumberOfBytesRequested",
	0x50: "uploadNotAccepted",
	0x71: "transferSuspended",
	0x78: "requestCorrectlyReceived-ResponsePending",
	0x80: "serviceNotSupportedInActiveSession",
	0x9A: "dataDecompressionFailed",
	0x9B: "dataDecryptionFailed",
	0xA0: "ecuNotResponding",
	0xA1: "ecuAddressUnknown",
}

// Decode parses a hex-encoded KWP2000 application PDU. Separators and a 0x
// prefix are tolerated.
func Decode(hexStr string) (*KWP, error) {
	clean := strings.NewReplacer(" ", "", ":", "", "-", "", "_", "", "\n", "", "\t", "").Replace(strings.TrimSpace(hexStr))
	if strings.HasPrefix(strings.ToLower(clean), "0x") {
		clean = clean[2:]
	}
	if clean == "" {
		return nil, fmt.Errorf("kwp: empty input")
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("kwp: invalid hex: %w", err)
	}
	return DecodeBytes(b)
}

// DecodeBytes parses a KWP2000 application PDU from raw bytes.
func DecodeBytes(b []byte) (*KWP, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("kwp: empty message")
	}
	sid := int(b[0])

	if sid == NegativeResponseSID {
		out := &KWP{Direction: "negative_response", ServiceID: NegativeResponseSID, ServiceIDHex: "0x7F", Service: "NegativeResponse"}
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

	if _, ok := serviceNames[sid-0x40]; ok {
		return decodeServicePDU(sid-0x40, "positive_response", b), nil
	}
	return decodeServicePDU(sid, "request", b), nil
}

func decodeServicePDU(svc int, dir string, b []byte) *KWP {
	out := &KWP{
		Direction:    dir,
		ServiceID:    svc,
		ServiceIDHex: fmt.Sprintf("0x%02X", svc),
		Service:      serviceName(svc),
	}
	data := b[1:]
	off := 0
	if label, ok := paramLabels[svc]; ok && off < len(data) {
		p := int(data[off])
		out.ParamByte = &p
		out.ParamLabel = label
		off++
	}
	if off < len(data) {
		out.PayloadHex = hexUpper(data[off:])
	}
	if serviceNames[svc] == "" {
		out.Notes = append(out.Notes, fmt.Sprintf("service 0x%02X not in the ISO 14230 table (manufacturer-specific?)", svc))
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
	return fmt.Sprintf("Unknown/ISOSAEReserved (0x%02X)", nrc)
}

func hexUpper(b []byte) string { return strings.ToUpper(hex.EncodeToString(b)) }
