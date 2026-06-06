// SPDX-License-Identifier: AGPL-3.0-or-later

// Package homepluggp decodes HomePlug Green PHY SLAC management messages —
// the Signal Level Attenuation Characterization protocol that pairs an
// electric vehicle to a charging station over the CCS / ISO 15118 (DIN
// 70121) Combined Charging System pilot line. Before any high-level EV ↔
// EVSE communication, the two sides run SLAC over HomePlug Green PHY (a
// powerline / PLC link on the Control Pilot) to work out which charger the
// car is physically plugged into and to establish a private logical network
// (a Network Membership Key, NMK). SLAC is a hot EV-charging-security topic:
// the handshake is unauthenticated, the matching is attenuation-based (so it
// is attackable by signal injection), and the CM_SLAC_MATCH.CNF / CM_SET_KEY
// messages carry the NMK in the clear — capturing one yields the charging
// link's network credential. A captured SLAC frame identifies the **step**
// of the pairing handshake in flight and surfaces the session Run ID, the EV
// / EVSE MAC addresses and IDs, and — for the match / key-set messages — the
// NID + NMK key material, which is the recon headline.
//
// It extends the powerline domain opened by internal/homeplugav: those are
// the 0xAxxx vendor MMEs (HomePlug AV adapters); these are the 0x60xx CCo
// SLAC MMEs (HomePlug Green PHY EV charging). Both ride EtherType 0x88E1.
//
// # Wrap-vs-native judgement
//
//	Native. A 1-byte MM version + a 2-byte little-endian MMTYPE envelope
//	(shared with HomePlug AV) then a fixed-layout SLAC body. A byte-slice
//	walk + an MMTYPE lookup; stdlib only, no new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The envelope and the SLAC body layouts were verified field-for-field
//	against scapy's HomePlug Green PHY layer (scapy.contrib.homepluggp) and
//	the ISO 15118-3 / HomePlug GP specification. Unlike the vendor-specific
//	HomePlug AV bodies (which homeplugav surfaces raw), the SLAC bodies are
//	standardised and stable, so the recon-relevant fields are decoded. Each
//	message decode is length-gated: a body that does not match the expected
//	SLAC layout is surfaced as raw hex with a note rather than guessed, and
//	an MMTYPE outside the SLAC set is rejected.
package homepluggp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the decoded view of a HomePlug Green PHY SLAC management message.
type Result struct {
	Version     int    `json:"version"`
	VersionName string `json:"version_name"`
	MMType      int    `json:"mmtype"`
	MMTypeHex   string `json:"mmtype_hex"`
	MMTypeName  string `json:"mmtype_name"`
	SubType     string `json:"sub_type"`
	Step        string `json:"step"`

	// SLAC body fields (populated per message type; omitted when absent).
	ApplicationType     *int   `json:"application_type,omitempty"`
	ApplicationTypeName string `json:"application_type_name,omitempty"`
	SecurityType        *int   `json:"security_type,omitempty"`
	SecurityTypeName    string `json:"security_type_name,omitempty"`
	RunID               string `json:"run_id,omitempty"`
	SenderID            string `json:"sender_id,omitempty"`
	SourceAddress       string `json:"source_address,omitempty"`
	ForwardingSTA       string `json:"forwarding_sta,omitempty"`
	MSoundTargetMAC     string `json:"msound_target_mac,omitempty"`
	NumberOfSounds      *int   `json:"number_of_sounds,omitempty"`
	EVMAC               string `json:"ev_mac,omitempty"`
	EVID                string `json:"ev_id,omitempty"`
	EVSEMAC             string `json:"evse_mac,omitempty"`
	EVSEID              string `json:"evse_id,omitempty"`
	KeyType             string `json:"key_type,omitempty"`
	NID                 string `json:"nid,omitempty"`
	NMK                 string `json:"nmk,omitempty"`

	BodyHex string   `json:"body_hex,omitempty"`
	Notes   []string `json:"notes,omitempty"`
}

// Decode parses a HomePlug Green PHY SLAC management message (the
// EtherType-0x88E1 payload) from hex (whitespace / ':' / '-' / '_'
// separators and a '0x' prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) < 3 {
		return nil, fmt.Errorf("homepluggp: %d bytes — too short for the version + MMTYPE header", len(b))
	}
	if versionName(b[0]) == "" {
		return nil, fmt.Errorf("homepluggp: MM version %d is not 0 (1.0) or 1 (1.1)", b[0])
	}
	mm := binary.LittleEndian.Uint16(b[1:3])
	name := slacName(mm)
	if name == "" {
		return nil, fmt.Errorf("homepluggp: MMTYPE 0x%04X is not a HomePlug Green PHY SLAC message (the 0x60xx CCo SLAC set)", mm)
	}
	r := &Result{
		Version:     int(b[0]),
		VersionName: versionName(b[0]),
		MMType:      int(mm),
		MMTypeHex:   fmt.Sprintf("0x%04X", mm),
		MMTypeName:  name,
		SubType:     subType(mm),
		Step:        slacStep(mm),
	}
	body := b[3:]
	r.Notes = append(r.Notes, "HomePlug Green PHY SLAC — the EV ↔ EVSE pairing handshake on the CCS / ISO 15118 Control Pilot; the message names the step (parm → start-atten → sound → atten-char → match → set-key)")
	decodeBody(r, mm, body)
	return r, nil
}

// decodeBody fills the SLAC body fields for the known message types. Each
// branch is length-gated; a body that does not match the expected SLAC
// layout falls through to a raw-hex surface with a note (no field guessing).
func decodeBody(r *Result, mm uint16, body []byte) {
	switch mm {
	case 0x6064: // CM_SLAC_PARM_REQ: app(1) sec(1) runid(8)
		if len(body) >= 10 {
			appSec(r, body[0], body[1])
			r.RunID = hexUpper(body[2:10])
			return
		}
	case 0x6065: // CM_SLAC_PARM_CNF: msound_mac(6) nsounds(1) timeout(1) resptype(1) fwd_sta(6) app(1) sec(1) runid(8)
		if len(body) >= 25 {
			r.MSoundTargetMAC = macStr(body[0:6])
			n := int(body[6])
			r.NumberOfSounds = &n
			r.ForwardingSTA = macStr(body[9:15])
			appSec(r, body[15], body[16])
			r.RunID = hexUpper(body[17:25])
			return
		}
	case 0x606a: // CM_START_ATTEN_CHAR_IND: app(1) sec(1) nsounds(1) timeout(1) resptype(1) fwd_sta(6) runid(8)
		if len(body) >= 19 {
			appSec(r, body[0], body[1])
			n := int(body[2])
			r.NumberOfSounds = &n
			r.ForwardingSTA = macStr(body[5:11])
			r.RunID = hexUpper(body[11:19])
			return
		}
	case 0x6076: // CM_MNBC_SOUND_IND: app(1) sec(1) sender_id(17) countdown(1) runid(8) rsvd(8) random(16)
		if len(body) >= 52 {
			appSec(r, body[0], body[1])
			r.SenderID = hexUpper(body[2:19])
			r.RunID = hexUpper(body[20:28])
			return
		}
	case 0x606e: // CM_ATTEN_CHAR_IND: app(1) sec(1) src_mac(6) runid(8) src_id(17) resp_id(17) nsounds(1) ngroups(1) groups[]
		if len(body) >= 52 {
			appSec(r, body[0], body[1])
			r.SourceAddress = macStr(body[2:8])
			r.RunID = hexUpper(body[8:16])
			n := int(body[50])
			r.NumberOfSounds = &n
			return
		}
	case 0x606f: // CM_ATTEN_CHAR_RSP: app(1) sec(1) src_mac(6) runid(8) src_id(17) resp_id(17) result(1)
		if len(body) >= 51 {
			appSec(r, body[0], body[1])
			r.SourceAddress = macStr(body[2:8])
			r.RunID = hexUpper(body[8:16])
			return
		}
	case 0x607c: // CM_SLAC_MATCH_REQ: app(1) sec(1) mvflen(2 LE) varfield{evid(17) evmac(6) evseid(17) evsemac(6) runid(8) rsvd(8)}
		if len(body) >= 66 {
			appSec(r, body[0], body[1])
			matchCommon(r, body[4:])
			r.Notes = append(r.Notes, "CM_SLAC_MATCH.REQ: the EV asks the matched EVSE to form the logical network — the EV / EVSE MACs and the session Run ID identify the pairing")
			return
		}
	case 0x607d: // CM_SLAC_MATCH_CNF: + nid(7) reserved(1) nmk(16) after the 62-byte common varfield
		if len(body) >= 90 {
			appSec(r, body[0], body[1])
			matchCommon(r, body[4:])
			r.NID = hexUpper(body[4+62 : 4+69])
			r.NMK = hexUpper(body[4+70 : 4+86])
			r.Notes = append(r.Notes, "CM_SLAC_MATCH.CNF carries the NID + NMK in the clear — the Network Membership Key is the charging link's network credential; capturing it compromises the EV ↔ EVSE logical network")
			return
		}
	case 0x6008, 0x6009: // CM_SET_KEY_REQ/CNF: keytype(1) mynonce(4) yournonce(4) pid(1) protorun(2) protomsg(1) ccocap(1) nid(7) newenckeysel(1) newkey(16)
		if len(body) >= 38 {
			r.KeyType = keyTypeName(body[0])
			r.NID = hexUpper(body[14:21])
			r.NMK = hexUpper(body[22:38])
			r.Notes = append(r.Notes, "CM_SET_KEY carries the NID + NMK (NewKey) — the powerline network key being set on the link; key material in the clear")
			return
		}
	}
	// Fell through: body absent or shorter than the SLAC layout — surface raw.
	if len(body) > 0 {
		r.BodyHex = hexUpper(body)
		r.Notes = append(r.Notes, fmt.Sprintf("body is %d bytes, shorter than the standard %s layout — surfaced as raw hex, not decoded", len(body), r.MMTypeName))
	}
}

// matchCommon decodes the 62-byte SLAC match variable field common to the
// MATCH.REQ and MATCH.CNF: evid(17) evmac(6) evseid(17) evsemac(6) runid(8) rsvd(8).
func matchCommon(r *Result, vf []byte) {
	if len(vf) < 62 {
		return
	}
	r.EVID = printableID(vf[0:17])
	r.EVMAC = macStr(vf[17:23])
	r.EVSEID = printableID(vf[23:40])
	r.EVSEMAC = macStr(vf[40:46])
	r.RunID = hexUpper(vf[46:54])
}

// appSec decodes the ApplicationType / SecurityType byte pair shared by most
// SLAC messages.
func appSec(r *Result, app, sec byte) {
	a := int(app)
	s := int(sec)
	r.ApplicationType = &a
	r.SecurityType = &s
	if app == 0 {
		r.ApplicationTypeName = "PEV-EVSE matching"
	}
	if sec == 0 {
		r.SecurityTypeName = "no security"
	}
}

func keyTypeName(b byte) string {
	switch b {
	case 0:
		return "DAK (Device Access Key)"
	case 1:
		return "NMK (Network Membership Key)"
	}
	return fmt.Sprintf("0x%02X", b)
}

func versionName(v byte) string {
	switch v {
	case 0:
		return "1.0"
	case 1:
		return "1.1"
	}
	return ""
}

// subType is the message sub-type carried in the two LSBs of the MMTYPE.
func subType(mm uint16) string {
	switch mm & 0x3 {
	case 0:
		return "Request"
	case 1:
		return "Confirmation"
	case 2:
		return "Indication"
	case 3:
		return "Response"
	}
	return ""
}

// slacStep is the human-readable position of the message in the SLAC
// pairing handshake.
func slacStep(mm uint16) string {
	switch mm {
	case 0x6064, 0x6065:
		return "1. SLAC parameters — the EV initiates pairing, the EVSE replies with the sounding parameters"
	case 0x606a:
		return "2. Start attenuation characterization — the EVSE tells the EV to begin sending sounding bursts"
	case 0x6076:
		return "3. M-Sound — the EV emits the sounding bursts used to measure signal attenuation"
	case 0x606e, 0x606f:
		return "4. Attenuation characterization — the measured attenuation profile that selects the physically-connected EVSE"
	case 0x607c, 0x607d:
		return "5. SLAC match — the EV and matched EVSE form the logical network (the CNF carries the NMK)"
	case 0x6008, 0x6009:
		return "6. Set key — the powerline network key (NMK) is set on the link"
	case 0x6086:
		return "Attenuation characteristics MME"
	}
	return ""
}

// slacName maps the MMTYPE to its SLAC message name (the 0x60xx CCo SLAC
// set, from scapy.contrib.homepluggp + ISO 15118-3; the scapy "CM_ATTEN_CHAR_IN"
// typo is corrected to the spec name CM_ATTEN_CHAR_IND).
func slacName(mm uint16) string {
	switch mm {
	case 0x6008:
		return "CM_SET_KEY_REQ"
	case 0x6009:
		return "CM_SET_KEY_CNF"
	case 0x6064:
		return "CM_SLAC_PARM_REQ"
	case 0x6065:
		return "CM_SLAC_PARM_CNF"
	case 0x606a:
		return "CM_START_ATTEN_CHAR_IND"
	case 0x606e:
		return "CM_ATTEN_CHAR_IND"
	case 0x606f:
		return "CM_ATTEN_CHAR_RSP"
	case 0x6076:
		return "CM_MNBC_SOUND_IND"
	case 0x607c:
		return "CM_SLAC_MATCH_REQ"
	case 0x607d:
		return "CM_SLAC_MATCH_CNF"
	case 0x6086:
		return "CM_ATTENUATION_CHARACTERISTICS_MME"
	}
	return ""
}

func hexUpper(b []byte) string {
	return strings.ToUpper(hex.EncodeToString(b))
}

func macStr(b []byte) string {
	if len(b) != 6 {
		return hexUpper(b)
	}
	parts := make([]string, 6)
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02X", v)
	}
	return strings.Join(parts, ":")
}

// printableID renders a SLAC EV/EVSE ID: the ID is a fixed 17-byte field
// that may carry an ASCII identifier (NUL-padded) or be all-zero. Trailing
// NULs are trimmed; if the trimmed result is empty or non-printable it falls
// back to hex.
func printableID(b []byte) string {
	trimmed := strings.TrimRight(string(b), "\x00")
	if trimmed == "" {
		return hexUpper(b)
	}
	for _, c := range trimmed {
		if c < 0x20 || c > 0x7e {
			return hexUpper(b)
		}
	}
	return trimmed
}

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("homepluggp: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("homepluggp: input is not valid hex: %w", err)
	}
	return b, nil
}
