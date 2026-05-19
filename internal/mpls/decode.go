// Package mpls decodes MPLS label stacks per RFC 3032 (stack
// encoding) + RFC 5462 (TC field rename from EXP) + the
// reserved-label catalogue from RFC 4182 / 5586 / 6790 / 7274.
//
// Wrap-vs-native judgement
//
//	Native. All the RFCs are fully public; the MPLS label
//	stack is a tight 4-byte-per-entry bit-packed field
//	(Label 20-bit + TC 3-bit + S 1-bit + TTL 8-bit) iterated
//	until the bottom-of-stack flag is set. No crypto, no
//	compression, no varints. Operators paste MPLS frame
//	bytes (after the EtherType 0x8847 / 0x8848 strip, or
//	after the outer IP+UDP for MPLS-over-UDP) from a
//	`tcpdump -X ether proto 0x8847` line, a Wireshark
//	Follow-Frame view, or any MPLS-emitting tool and get
//	the documented label stack plus an inner-payload
//	heuristic.
//
// What this package covers
//
//   - **4-byte-per-label entry**:
//
//   - bits 0-19: Label (20 bits, big-endian)
//
//   - bits 20-22: TC (Traffic Class, 3 bits) — formerly
//     EXP (Experimental); QoS class indicator.
//
//   - bit 23: S (Bottom of Stack) — 1 = innermost label.
//
//   - bits 24-31: TTL (Time to Live, 8 bits)
//
//   - **Stack walker** — iterates 4-byte entries until S=1
//     is reached, then surfaces the remaining bytes as the
//     payload.
//
//   - **Reserved label name table** (RFC 3032 + extensions):
//
//   - 0 IPv4 Explicit NULL (RFC 3032 §2.1)
//
//   - 1 Router Alert (RFC 3032 — must NEVER be at bottom
//     of stack)
//
//   - 2 IPv6 Explicit NULL (RFC 3032 §2.1)
//
//   - 3 Implicit NULL (used in signalling, never on wire)
//
//   - 7 Entropy Label Indicator (ELI, RFC 6790)
//
//   - 13 Generic Associated Channel Label (GAL, RFC 5586)
//
//   - 14 OAM Alert Label (RFC 3429)
//
//   - 15 Extension Label (RFC 7274)
//
//   - **Inner payload heuristic** — after the bottom-of-
//     stack label, the payload's protocol isn't explicitly
//     encoded. Convention:
//
//   - first nibble 4 → IPv4
//
//   - first nibble 6 → IPv6
//
//   - first nibble 0 and the label-stack ended on label 0
//     (IPv4 Explicit NULL) → IPv4
//
//   - otherwise → unknown (likely Ethernet for EoMPLS /
//     VPLS pseudowires, or a control word)
//
//   - **Conformance check** — Router Alert label (1) at
//     the bottom of stack surfaces a Note as it violates
//     RFC 3032 §2.1.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - Ethernet framing — feed the MPLS bytes after the
//     EtherType 0x8847 (unicast) / 0x8848 (multicast) strip.
//     For MPLS-over-UDP (RFC 7510) or MPLS-over-GRE, strip
//     those outer headers first.
//
//   - Inner payload decoding — operators pipe the payload
//     to `ip_packet_decode` for IPv4/IPv6, or to a future
//     Ethernet decoder for EoMPLS pseudowires.
//
//   - MPLS Control Word (RFC 4385) and Pseudowire Type
//     dispatch — when EoMPLS pseudowires use a control
//     word, the operator can recognise it by the leading
//     0000 nibble in the payload. We surface the raw bytes
//     so dispatch belongs in a session-tracker.
//
//   - LDP / RSVP-TE / BGP-LU label-distribution protocols —
//     these are control-plane and a separate Spec.
package mpls

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the top-level decoded view.
type Result struct {
	Labels        []Label  `json:"labels"`
	LabelCount    int      `json:"label_count"`
	HeaderBytes   int      `json:"header_bytes"`
	PayloadGuess  string   `json:"payload_guess"`
	PayloadLength int      `json:"payload_length"`
	PayloadHex    string   `json:"payload_hex,omitempty"`
	TotalBytes    int      `json:"total_bytes"`
	Notes         []string `json:"notes,omitempty"`
}

// Label is one entry in the MPLS label stack.
type Label struct {
	Label         int    `json:"label"`
	LabelHex      string `json:"label_hex"`
	LabelName     string `json:"label_name,omitempty"`
	TC            int    `json:"tc"`
	BottomOfStack bool   `json:"bottom_of_stack"`
	TTL           int    `json:"ttl"`
}

// Decode parses an MPLS label stack from hex.
func Decode(hexStr string) (*Result, error) {
	clean := stripSeparators(hexStr)
	if clean == "" {
		return nil, fmt.Errorf("empty input")
	}
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("hex must have even length, got %d", len(clean))
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	if len(b) < 4 {
		return nil, fmt.Errorf("MPLS label entry truncated (%d bytes; need ≥4)", len(b))
	}

	r := &Result{TotalBytes: len(b)}
	off := 0
	for off+4 <= len(b) {
		w := binary.BigEndian.Uint32(b[off : off+4])
		l := Label{
			Label:         int(w >> 12),
			TC:            int((w >> 9) & 0x07),
			BottomOfStack: (w>>8)&0x01 == 1,
			TTL:           int(w & 0xFF),
		}
		l.LabelHex = fmt.Sprintf("0x%05X", l.Label)
		l.LabelName = reservedLabelName(l.Label)
		r.Labels = append(r.Labels, l)
		off += 4
		if l.BottomOfStack {
			break
		}
	}
	if len(r.Labels) == 0 {
		return nil, fmt.Errorf("no MPLS label decoded")
	}

	// Did we reach bottom of stack?
	if !r.Labels[len(r.Labels)-1].BottomOfStack {
		return nil, fmt.Errorf("label stack ran past buffer without S=1 bottom-of-stack flag")
	}

	r.LabelCount = len(r.Labels)
	r.HeaderBytes = off

	// Router Alert at bottom of stack is illegal.
	bottom := r.Labels[len(r.Labels)-1]
	if bottom.Label == 1 {
		r.Notes = append(r.Notes,
			"Router Alert label (1) is at the bottom of the stack — RFC 3032 §2.1 "+
				"requires it to NEVER be at the bottom of the stack")
	}

	// Inner payload heuristic.
	payload := b[off:]
	r.PayloadLength = len(payload)
	r.PayloadGuess = guessPayload(bottom.Label, payload)
	if len(payload) > 0 {
		if len(payload) > 256 {
			r.PayloadHex = strings.ToUpper(hex.EncodeToString(payload[:256])) + "..."
		} else {
			r.PayloadHex = strings.ToUpper(hex.EncodeToString(payload))
		}
	}

	return r, nil
}

func reservedLabelName(label int) string {
	switch label {
	case 0:
		return "IPv4 Explicit NULL (RFC 3032)"
	case 1:
		return "Router Alert (RFC 3032)"
	case 2:
		return "IPv6 Explicit NULL (RFC 3032)"
	case 3:
		return "Implicit NULL (signalling only, never on wire)"
	case 7:
		return "Entropy Label Indicator (ELI, RFC 6790)"
	case 13:
		return "Generic Associated Channel Label (GAL, RFC 5586)"
	case 14:
		return "OAM Alert Label (RFC 3429)"
	case 15:
		return "Extension Label (RFC 7274)"
	}
	if label >= 4 && label <= 15 {
		return fmt.Sprintf("reserved (label %d)", label)
	}
	return ""
}

func guessPayload(bottomLabel int, b []byte) string {
	if len(b) == 0 {
		return "empty (S=1 with no following payload)"
	}
	// IPv4 Explicit NULL ⇒ payload is IPv4.
	if bottomLabel == 0 {
		return "IPv4 (from IPv4 Explicit NULL bottom label)"
	}
	if bottomLabel == 2 {
		return "IPv6 (from IPv6 Explicit NULL bottom label)"
	}
	// First-nibble version heuristic.
	switch b[0] >> 4 {
	case 4:
		return "IPv4 (first nibble 0x4)"
	case 6:
		return "IPv6 (first nibble 0x6)"
	case 0:
		// MPLS control word starts with 0000 nibble; could be
		// pseudowire or EoMPLS with leading 0-padded control
		// word.
		return "EoMPLS / pseudowire control word (first nibble 0x0) or unknown"
	}
	return "unknown (likely Ethernet for EoMPLS / VPLS pseudowires)"
}

func stripSeparators(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	var sb strings.Builder
	for _, r := range s {
		switch r {
		case ':', '-', '_', ' ', '\t', '\n', '\r':
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
