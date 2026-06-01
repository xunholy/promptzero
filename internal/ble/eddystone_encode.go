// SPDX-License-Identifier: AGPL-3.0-or-later

package ble

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strings"
)

// EddystoneEncodeRequest describes one Eddystone frame to build. Kind
// selects the frame type: "uid", "url", "tlm", or "eid". Only the fields
// relevant to that kind are read.
//
//   - uid: TxPower + Namespace (10-byte hex) + Instance (6-byte hex).
//   - url: TxPower + URL (the scheme prefix and TLD expansions are
//     abbreviated to their Eddystone codes automatically).
//   - tlm: BatteryMV + TemperatureC + AdvCount + Uptime100ms (version 0x00,
//     the unencrypted form).
//   - eid: TxPower + EphemeralID (8-byte hex; the operator supplies the
//     rotating token — this builder does not derive it).
type EddystoneEncodeRequest struct {
	Kind    string `json:"kind"`
	TxPower int    `json:"tx_power_dbm,omitempty"`

	URL string `json:"url,omitempty"`

	Namespace string `json:"namespace,omitempty"`
	Instance  string `json:"instance,omitempty"`

	BatteryMV    int     `json:"battery_mv,omitempty"`
	TemperatureC float64 `json:"temperature_c,omitempty"`
	AdvCount     int     `json:"adv_count,omitempty"`
	Uptime100ms  int     `json:"uptime_100ms,omitempty"`

	EphemeralID string `json:"ephemeral_id,omitempty"`

	// Wrap controls the framing of the returned bytes:
	//   "" / "frame" — the bare Eddystone frame (starts with the
	//                   frame-type byte); the default.
	//   "uuid"        — prefixed with the 0xAA 0xFE service UUID.
	//   "ad"          — the full BLE Service-Data AD structure
	//                   (length, 0x16, 0xAA, 0xFE, frame) ready to drop
	//                   into an advertising payload.
	Wrap string `json:"wrap,omitempty"`
}

// EncodeEddystone builds the raw bytes of an Eddystone frame — the inverse
// of DecodeEddystone. The four open frame types (UID / URL / TLM / EID) are
// supported, each round-trip-verified against the decoder.
//
// # Wrap-vs-native judgement
//
// Native, and the inverse of the existing decoder. The Eddystone frame
// layouts plus the URL scheme-prefix and TLD-expansion tables are public
// (Google's open Eddystone protocol specification); encoding is pure byte
// assembly + a prefix/expansion lookup — no crypto, no hardware. It
// produces the service-data payload an operator advertises from a beacon
// (e.g. a spoofed URL beacon for a phishing / proximity test); generation
// only, no BLE TX, so it is Low risk like the decoder. Correctness is
// verifiable two ways: round-trip against DecodeEddystone and the
// byte-exact examples in the Eddystone-URL spec.
//
// # Deliberately deferred
//
// eTLM (encrypted telemetry, TLM version 0x01) and EID derivation require
// the per-beacon identity key and AES, which the operator owns out-of-band;
// EID here only frames a caller-supplied token. The URL encoder abbreviates
// using the documented scheme/expansion tables and otherwise passes printable
// ASCII through; a byte the spec cannot represent is rejected rather than
// silently dropped.
func EncodeEddystone(r EddystoneEncodeRequest) ([]byte, error) {
	var frame []byte
	var err error
	switch strings.ToLower(strings.TrimSpace(r.Kind)) {
	case "uid":
		frame, err = encodeEddystoneUID(r)
	case "url":
		frame, err = encodeEddystoneURL(r)
	case "tlm":
		frame, err = encodeEddystoneTLM(r)
	case "eid":
		frame, err = encodeEddystoneEID(r)
	default:
		return nil, fmt.Errorf("eddystone: unsupported kind %q (supported: uid, url, tlm, eid)", r.Kind)
	}
	if err != nil {
		return nil, err
	}
	return wrapEddystone(frame, r.Wrap)
}

// wrapEddystone applies the requested framing around a bare Eddystone frame.
func wrapEddystone(frame []byte, wrap string) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(wrap)) {
	case "", "frame":
		return frame, nil
	case "uuid":
		out := []byte{0xAA, 0xFE}
		return append(out, frame...), nil
	case "ad":
		// length = type(1) + UUID(2) + frame; then 0x16 AA FE frame.
		out := []byte{byte(3 + len(frame)), 0x16, 0xAA, 0xFE}
		return append(out, frame...), nil
	default:
		return nil, fmt.Errorf("eddystone: unknown wrap %q (frame, uuid, ad)", wrap)
	}
}

func txPowerByte(dbm int) (byte, error) {
	if dbm < -128 || dbm > 127 {
		return 0, fmt.Errorf("eddystone: tx_power_dbm %d out of int8 range (-128..127)", dbm)
	}
	return byte(int8(dbm)), nil
}

func encodeEddystoneUID(r EddystoneEncodeRequest) ([]byte, error) {
	ns, err := parseFixedHex(r.Namespace, 10, "namespace")
	if err != nil {
		return nil, err
	}
	inst, err := parseFixedHex(r.Instance, 6, "instance")
	if err != nil {
		return nil, err
	}
	tx, err := txPowerByte(r.TxPower)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 18)
	out = append(out, byte(FrameUID), tx)
	out = append(out, ns...)
	out = append(out, inst...)
	out = append(out, 0x00, 0x00) // reserved (RFU)
	return out, nil
}

func encodeEddystoneURL(r EddystoneEncodeRequest) ([]byte, error) {
	tx, err := txPowerByte(r.TxPower)
	if err != nil {
		return nil, err
	}
	scheme, body, err := encodeEddystoneURLBody(r.URL)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 3+len(body))
	out = append(out, byte(FrameURL), tx, scheme)
	out = append(out, body...)
	return out, nil
}

// encodeEddystoneURLBody returns the scheme byte and the encoded URL tail,
// the inverse of decodeEddystoneURL: it abbreviates the longest matching
// scheme prefix, then greedily abbreviates the longest matching TLD
// expansion at each position, passing other printable-ASCII bytes through.
func encodeEddystoneURLBody(url string) (byte, []byte, error) {
	if strings.TrimSpace(url) == "" {
		return 0, nil, fmt.Errorf("eddystone: url is required for kind=url")
	}
	scheme := -1
	schemeLen := 0
	for i, p := range urlSchemes {
		if len(p) > schemeLen && strings.HasPrefix(url, p) {
			scheme = i
			schemeLen = len(p)
		}
	}
	if scheme < 0 {
		return 0, nil, fmt.Errorf("eddystone: url %q must start with one of http://www. https://www. http:// https://", url)
	}
	rest := url[schemeLen:]

	// Expansions sorted by descending length for greedy longest-match.
	type exp struct {
		s string
		b byte
	}
	exps := make([]exp, 0, len(urlExpansions))
	for b, s := range urlExpansions {
		exps = append(exps, exp{s, b})
	}
	sort.Slice(exps, func(i, j int) bool {
		if len(exps[i].s) != len(exps[j].s) {
			return len(exps[i].s) > len(exps[j].s)
		}
		return exps[i].b < exps[j].b
	})

	var body []byte
	for i := 0; i < len(rest); {
		matched := false
		for _, e := range exps {
			if strings.HasPrefix(rest[i:], e.s) {
				body = append(body, e.b)
				i += len(e.s)
				matched = true
				break
			}
		}
		if matched {
			continue
		}
		c := rest[i]
		// Decoder passes through printable ASCII (0x21-0x7E); anything
		// else is a reserved/unencodable byte we refuse rather than drop.
		if c <= 0x20 || c >= 0x7F {
			return 0, nil, fmt.Errorf("eddystone: url byte 0x%02X at offset %d is not encodable (printable ASCII only)", c, schemeLen+i)
		}
		body = append(body, c)
		i++
	}
	return byte(scheme), body, nil
}

func encodeEddystoneTLM(r EddystoneEncodeRequest) ([]byte, error) {
	if r.BatteryMV < 0 || r.BatteryMV > 0xFFFF {
		return nil, fmt.Errorf("eddystone: battery_mv %d out of range (0..65535)", r.BatteryMV)
	}
	if r.AdvCount < 0 || int64(r.AdvCount) > math.MaxUint32 {
		return nil, fmt.Errorf("eddystone: adv_count %d out of uint32 range", r.AdvCount)
	}
	if r.Uptime100ms < 0 || int64(r.Uptime100ms) > math.MaxUint32 {
		return nil, fmt.Errorf("eddystone: uptime_100ms %d out of uint32 range", r.Uptime100ms)
	}
	tempScaled := math.Round(r.TemperatureC * 256.0)
	if tempScaled < math.MinInt16 || tempScaled > math.MaxInt16 {
		return nil, fmt.Errorf("eddystone: temperature_c %g out of 8.8 fixed-point range (-128..127.996)", r.TemperatureC)
	}
	out := make([]byte, 14)
	out[0] = byte(FrameTLM)
	out[1] = 0x00 // version 0 (unencrypted)
	binary.BigEndian.PutUint16(out[2:4], uint16(r.BatteryMV))
	binary.BigEndian.PutUint16(out[4:6], uint16(int16(tempScaled)))
	binary.BigEndian.PutUint32(out[6:10], uint32(r.AdvCount))
	binary.BigEndian.PutUint32(out[10:14], uint32(r.Uptime100ms))
	return out, nil
}

func encodeEddystoneEID(r EddystoneEncodeRequest) ([]byte, error) {
	eid, err := parseFixedHex(r.EphemeralID, 8, "ephemeral_id")
	if err != nil {
		return nil, err
	}
	tx, err := txPowerByte(r.TxPower)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 10)
	out = append(out, byte(FrameEID), tx)
	out = append(out, eid...)
	return out, nil
}

// parseFixedHex decodes a hex string (separators / 0x prefix tolerated)
// and requires exactly n bytes.
func parseFixedHex(s string, n int, field string) ([]byte, error) {
	clean := strings.NewReplacer(" ", "", ":", "", "-", "", "_", "").Replace(strings.TrimSpace(s))
	if strings.HasPrefix(strings.ToLower(clean), "0x") {
		clean = clean[2:]
	}
	if clean == "" {
		return nil, fmt.Errorf("eddystone: %s is required (%d bytes hex)", field, n)
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("eddystone: %s is not valid hex: %w", field, err)
	}
	if len(b) != n {
		return nil, fmt.Errorf("eddystone: %s must be exactly %d bytes; got %d", field, n, len(b))
	}
	return b, nil
}
