// SPDX-License-Identifier: AGPL-3.0-or-later

// Package smp decodes the Bluetooth LE Security Manager Protocol (SMP, Core
// spec Vol 3 Part H) — the pairing-and-key-distribution layer carried on L2CAP
// CID 0x0006. SMP is where BLE security is established (or fails to be): the
// Pairing Request / Response exchange negotiates the pairing **method** and
// the keys to distribute, and the choice of method determines whether the link
// is protected against a man-in-the-middle. A captured SMP exchange is the
// recon headline for BLE-pairing security: it reveals each side's **IO
// capability**, whether **MITM protection** is requested, whether **LE Secure
// Connections** (vs the weaker Legacy pairing) is used, the **max encryption
// key size**, and which long-term / identity / signing keys are distributed —
// so it answers "is this pairing **Just Works** (no MITM protection, trivially
// interceptable) or authenticated?". It completes the project's Bluetooth-stack
// decode chain (bt_hci_decode → bt_l2cap_decode → here).
//
// # Wrap-vs-native judgement
//
//	Native. An SMP PDU is a 1-byte code then a fixed body — the Pairing
//	Request/Response is six bytes of bit-fields (IO cap, OOB, AuthReq, key
//	size, two key-distribution masks); the key PDUs are fixed-length keys. A
//	byte read + bit-field decode + small tables; stdlib only, no new go.mod
//	dep.
//
// # Verifiable / no confidently-wrong output
//
//	The SMP codes, the IO-capability values, the AuthReq bit-fields, the
//	key-distribution flags and the Pairing-Failed reasons follow the Bluetooth
//	Core specification (Vol 3 Part H) — deterministic and byte-checkable. The
//	pairing-method note is derived only from the unambiguous AuthReq bits
//	(MITM / Secure Connections) on the decoded PDU; the exact Legacy
//	method (Just Works vs Passkey vs OOB) also depends on BOTH sides' IO
//	capabilities, so the note states the single-PDU security posture (MITM
//	requested or not, SC or Legacy) rather than over-claiming. The fixed-length
//	key material (LTK / IRK / CSRK / Confirm / Random) is surfaced as raw hex.
package smp

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the decoded view of an SMP PDU.
type Result struct {
	Code     int    `json:"code"`
	CodeHex  string `json:"code_hex"`
	CodeName string `json:"code_name"`

	// Pairing Request / Response (and, partly, Security Request)
	IOCapability      string   `json:"io_capability,omitempty"`
	OOBDataPresent    *bool    `json:"oob_data_present,omitempty"`
	Bonding           *bool    `json:"bonding,omitempty"`
	MITM              *bool    `json:"mitm_protection,omitempty"`
	SecureConnections *bool    `json:"secure_connections,omitempty"`
	Keypress          *bool    `json:"keypress,omitempty"`
	MaxKeySize        *int     `json:"max_encryption_key_size,omitempty"`
	InitiatorKeyDist  []string `json:"initiator_key_distribution,omitempty"`
	ResponderKeyDist  []string `json:"responder_key_distribution,omitempty"`
	PairingPosture    string   `json:"pairing_security_posture,omitempty"`

	// Pairing Failed
	FailReason string `json:"fail_reason,omitempty"`

	// Identity Address Information
	AddressType string `json:"address_type,omitempty"`
	Address     string `json:"address,omitempty"`

	PayloadHex string   `json:"payload_hex,omitempty"`
	Notes      []string `json:"notes,omitempty"`
}

// Decode parses an SMP PDU (the L2CAP CID-0x0006 payload, starting at the SMP
// code byte) from hex (whitespace / ':' / '-' / '_' separators and a '0x'
// prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) < 1 {
		return nil, fmt.Errorf("smp: empty input")
	}
	code := b[0]
	r := &Result{Code: int(code), CodeHex: fmt.Sprintf("0x%02X", code), CodeName: codeName(code)}
	body := b[1:]

	switch code {
	case 0x01, 0x02: // Pairing Request / Response
		if len(body) >= 6 {
			r.IOCapability = ioCapability(body[0])
			oob := body[1] != 0
			r.OOBDataPresent = &oob
			decodeAuthReq(r, body[2])
			ks := int(body[3])
			r.MaxKeySize = &ks
			r.InitiatorKeyDist = keyDist(body[4])
			r.ResponderKeyDist = keyDist(body[5])
			r.PairingPosture = posture(r)
		} else {
			r.PayloadHex = hexUpper(body)
		}
	case 0x0B: // Security Request — just an AuthReq byte
		if len(body) >= 1 {
			decodeAuthReq(r, body[0])
			r.PairingPosture = posture(r)
		}
	case 0x05: // Pairing Failed — reason byte
		if len(body) >= 1 {
			r.FailReason = failReason(body[0])
		}
	case 0x09: // Identity Address Information — addr type + BD_ADDR
		if len(body) >= 7 {
			if body[0] == 0 {
				r.AddressType = "public"
			} else {
				r.AddressType = "random"
			}
			r.Address = bdaddr(body[1:7])
		} else {
			r.PayloadHex = hexUpper(body)
		}
	default:
		// Pairing Confirm/Random (16 B), Encryption/Identity/Signing Information
		// (keys), Central Identification, public key, DHKey check — fixed-length
		// key material surfaced raw.
		if len(body) > 0 {
			r.PayloadHex = hexUpper(body)
		}
	}

	r.Notes = append(r.Notes, "Bluetooth LE SMP (pairing) — the Pairing Request/Response AuthReq reveals the security posture; 'Just Works' (no MITM protection) is trivially interceptable; key material is surfaced raw")
	return r, nil
}

func decodeAuthReq(r *Result, a byte) {
	bonding := a&0x03 == 0x01
	mitm := a&0x04 != 0
	sc := a&0x08 != 0
	kp := a&0x10 != 0
	r.Bonding = &bonding
	r.MITM = &mitm
	r.SecureConnections = &sc
	r.Keypress = &kp
}

// posture states the single-PDU security posture from the AuthReq bits. The
// exact Legacy method also needs both sides' IO capabilities, so this does not
// over-claim the method.
func posture(r *Result) string {
	if r.MITM == nil {
		return ""
	}
	gen := "LE Legacy pairing"
	if r.SecureConnections != nil && *r.SecureConnections {
		gen = "LE Secure Connections"
	}
	if !*r.MITM {
		return gen + " — MITM protection NOT requested (Just Works unless overridden by the peer's IO capability — no MITM protection)"
	}
	return gen + " — MITM protection requested (authenticated: Passkey / Numeric Comparison / OOB per the IO capabilities)"
}

func codeName(c byte) string {
	switch c {
	case 0x01:
		return "Pairing Request"
	case 0x02:
		return "Pairing Response"
	case 0x03:
		return "Pairing Confirm"
	case 0x04:
		return "Pairing Random"
	case 0x05:
		return "Pairing Failed"
	case 0x06:
		return "Encryption Information (LTK)"
	case 0x07:
		return "Central Identification (EDIV+Rand)"
	case 0x08:
		return "Identity Information (IRK)"
	case 0x09:
		return "Identity Address Information"
	case 0x0A:
		return "Signing Information (CSRK)"
	case 0x0B:
		return "Security Request"
	case 0x0C:
		return "Pairing Public Key"
	case 0x0D:
		return "Pairing DHKey Check"
	case 0x0E:
		return "Pairing Keypress Notification"
	}
	return fmt.Sprintf("SMP code 0x%02X", c)
}

func ioCapability(c byte) string {
	switch c {
	case 0x00:
		return "DisplayOnly"
	case 0x01:
		return "DisplayYesNo"
	case 0x02:
		return "KeyboardOnly"
	case 0x03:
		return "NoInputNoOutput"
	case 0x04:
		return "KeyboardDisplay"
	}
	return fmt.Sprintf("0x%02X", c)
}

func keyDist(b byte) []string {
	var out []string
	if b&0x01 != 0 {
		out = append(out, "EncKey (LTK)")
	}
	if b&0x02 != 0 {
		out = append(out, "IdKey (IRK)")
	}
	if b&0x04 != 0 {
		out = append(out, "SignKey (CSRK)")
	}
	if b&0x08 != 0 {
		out = append(out, "LinkKey (CT)")
	}
	return out
}

func failReason(c byte) string {
	names := map[byte]string{
		0x01: "Passkey Entry Failed", 0x02: "OOB Not Available",
		0x03: "Authentication Requirements", 0x04: "Confirm Value Failed",
		0x05: "Pairing Not Supported", 0x06: "Encryption Key Size",
		0x07: "Command Not Supported", 0x08: "Unspecified Reason",
		0x09: "Repeated Attempts", 0x0A: "Invalid Parameters",
		0x0B: "DHKey Check Failed", 0x0C: "Numeric Comparison Failed",
		0x0D: "BR/EDR Pairing In Progress", 0x0E: "Cross-transport Key Derivation Not Allowed",
		0x0F: "Key Rejected",
	}
	if n, ok := names[c]; ok {
		return n
	}
	return fmt.Sprintf("0x%02X", c)
}

func bdaddr(b []byte) string {
	// BD_ADDR is little-endian on the wire; render MSB-first.
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", b[5], b[4], b[3], b[2], b[1], b[0])
}

func hexUpper(b []byte) string { return strings.ToUpper(hex.EncodeToString(b)) }

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("smp: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("smp: input is not valid hex: %w", err)
	}
	return b, nil
}
