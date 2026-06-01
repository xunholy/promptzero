// SPDX-License-Identifier: AGPL-3.0-or-later

package kwp

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// EncodeRequest describes a KWP2000 message to build.
type EncodeRequest struct {
	// Direction: "request" (default), "positive_response" (SID + 0x40), or
	// "negative_response" (0x7F <SID> <NRC>).
	Direction string
	// Service is the request service ID (e.g. 0x10, 0x21, 0x81). For a
	// positive response the +0x40 is applied automatically.
	Service int
	// Param, when non-nil, is the byte after the SID — a local identifier,
	// session/access/reset type, etc. (KWP does not use UDS's
	// suppress-positive-response sub-function bit).
	Param *int
	// NRC is the negative-response code (required for negative_response).
	NRC *int
	// Payload is trailing data appended after the SID/param.
	Payload []byte
}

// Encode builds the bytes of a KWP2000 (ISO 14230) application PDU — the
// inverse of DecodeBytes. The byte order matches the decoder (SID, optional
// param byte, then payload), so it round-trips through DecodeBytes. KWP
// shares UDS's +0x40 / 0x7F framing but its own service-ID semantics (a
// 1-byte local-identifier/param byte, not a 16-bit DID or a suppress bit),
// so this is distinct from uds.Encode. Generation only — produces a PDU,
// transmits nothing.
//
// # Wrap-vs-native judgement
//
// Native, and the inverse of the decoder: pure byte assembly over the
// public ISO 14230 framing. Correctness is verifiable by round-trip against
// DecodeBytes plus hand-computed request bytes (e.g.
// ReadDataByLocalIdentifier 0x21 + local id 0x01 = 21 01).
func Encode(r EncodeRequest) ([]byte, error) {
	if r.Service < 0 || r.Service > 0xFF {
		return nil, fmt.Errorf("kwp: service 0x%X out of byte range", r.Service)
	}
	switch strings.ToLower(strings.TrimSpace(r.Direction)) {
	case "", "request":
		return encodeServicePDU(r.Service, r)
	case "positive_response":
		return encodeServicePDU((r.Service+0x40)&0xFF, r)
	case "negative_response":
		if r.NRC == nil {
			return nil, fmt.Errorf("kwp: negative_response requires an nrc")
		}
		if *r.NRC < 0 || *r.NRC > 0xFF {
			return nil, fmt.Errorf("kwp: nrc 0x%X out of byte range", *r.NRC)
		}
		out := []byte{NegativeResponseSID, byte(r.Service), byte(*r.NRC)}
		return append(out, r.Payload...), nil
	default:
		return nil, fmt.Errorf("kwp: unknown direction %q (request, positive_response, negative_response)", r.Direction)
	}
}

func encodeServicePDU(sidByte int, r EncodeRequest) ([]byte, error) {
	out := []byte{byte(sidByte)}
	if r.Param != nil {
		if *r.Param < 0 || *r.Param > 0xFF {
			return nil, fmt.Errorf("kwp: param 0x%X out of byte range", *r.Param)
		}
		out = append(out, byte(*r.Param))
	}
	out = append(out, r.Payload...)
	return out, nil
}

// EncodeHex returns the PDU as an uppercase hex string.
func EncodeHex(r EncodeRequest) (string, error) {
	b, err := Encode(r)
	if err != nil {
		return "", err
	}
	return strings.ToUpper(hex.EncodeToString(b)), nil
}
