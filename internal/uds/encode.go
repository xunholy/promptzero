// SPDX-License-Identifier: AGPL-3.0-or-later

package uds

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// EncodeRequest describes a UDS message to build.
type EncodeRequest struct {
	// Direction selects the message shape: "request" (default),
	// "positive_response" (SID + 0x40), or "negative_response"
	// (0x7F <SID> <NRC>).
	Direction string
	// Service is the request service ID (e.g. 0x10, 0x22, 0x27). For a
	// positive response the +0x40 is applied automatically.
	Service int
	// SubFunction, when non-nil, is emitted as the byte after the SID
	// (with the SuppressPositiveResponse bit OR-ed in for a request).
	SubFunction *int
	// SuppressPositiveResponse sets bit 7 of the sub-function byte
	// (request only; ignored without a sub-function).
	SuppressPositiveResponse bool
	// DataIdentifier, when non-nil, is emitted as a 2-byte big-endian DID
	// after the sub-function (Read/Write DataByIdentifier services).
	DataIdentifier *int
	// NRC is the negative-response code (required for negative_response).
	NRC *int
	// Payload is trailing data appended after the structured fields.
	Payload []byte
}

// Encode builds the bytes of a UDS application PDU — the inverse of
// DecodeBytes. The byte order matches what the decoder expects (SID,
// optional sub-function, optional 16-bit DID, then payload), so it
// round-trips through DecodeBytes. This is the application-layer top of the
// inject pipeline: build the request here, segment it with isotp_encode,
// wrap each frame with canbus_fd_encode, and send via canbus_inject.
//
// # Wrap-vs-native judgement
//
// Native, and the inverse of the decoder: pure byte assembly over the
// public ISO 14229 framing (+0x40 positive response, 0x7F negative
// response). Generation only — it produces a PDU and transmits nothing.
// Correctness is verifiable by round-trip against DecodeBytes plus
// hand-computed request bytes (e.g. ReadDataByIdentifier(VIN) = 22 F1 90).
func Encode(r EncodeRequest) ([]byte, error) {
	if r.Service < 0 || r.Service > 0xFF {
		return nil, fmt.Errorf("uds: service 0x%X out of byte range", r.Service)
	}
	switch strings.ToLower(strings.TrimSpace(r.Direction)) {
	case "", "request":
		return encodeServicePDU(r.Service, false, r)
	case "positive_response":
		return encodeServicePDU((r.Service+0x40)&0xFF, true, r)
	case "negative_response":
		if r.NRC == nil {
			return nil, fmt.Errorf("uds: negative_response requires an nrc")
		}
		if *r.NRC < 0 || *r.NRC > 0xFF {
			return nil, fmt.Errorf("uds: nrc 0x%X out of byte range", *r.NRC)
		}
		out := []byte{NegativeResponseSID, byte(r.Service), byte(*r.NRC)}
		return append(out, r.Payload...), nil
	default:
		return nil, fmt.Errorf("uds: unknown direction %q (request, positive_response, negative_response)", r.Direction)
	}
}

// encodeServicePDU assembles a request / positive response. sidByte is the
// on-wire SID (request SID, or SID+0x40 for a response); isResponse drops
// the SuppressPositiveResponse bit (it is a request-only flag).
func encodeServicePDU(sidByte int, isResponse bool, r EncodeRequest) ([]byte, error) {
	out := []byte{byte(sidByte)}
	if r.SubFunction != nil {
		sf := *r.SubFunction
		if sf < 0 || sf > 0x7F {
			return nil, fmt.Errorf("uds: sub_function 0x%X out of 7-bit range", sf)
		}
		b := byte(sf)
		if r.SuppressPositiveResponse && !isResponse {
			b |= 0x80
		}
		out = append(out, b)
	}
	if r.DataIdentifier != nil {
		did := *r.DataIdentifier
		if did < 0 || did > 0xFFFF {
			return nil, fmt.Errorf("uds: data_identifier 0x%X out of 16-bit range", did)
		}
		out = append(out, byte(did>>8), byte(did&0xFF))
	}
	out = append(out, r.Payload...)
	return out, nil
}

// EncodeHex is a convenience wrapper returning the PDU as an uppercase hex
// string.
func EncodeHex(r EncodeRequest) (string, error) {
	b, err := Encode(r)
	if err != nil {
		return "", err
	}
	return strings.ToUpper(hex.EncodeToString(b)), nil
}
