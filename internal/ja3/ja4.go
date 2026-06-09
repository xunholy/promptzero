package ja3

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// JA4Result is the outcome of a JA4 computation.
type JA4Result struct {
	// JA4 is the fingerprint: ja4_a_ja4_b_ja4_c.
	JA4 string `json:"ja4"`
	// JA4R is the raw (un-hashed) form: a_<ciphers>_<exts>_<sigalgs>, useful
	// for debugging and exact cross-checking against reference tooling.
	JA4R string `json:"ja4_r"`
	// A, B, C are the three sections.
	A string `json:"ja4_a"`
	B string `json:"ja4_b"`
	C string `json:"ja4_c"`
	// TLSVersion is the negotiated TLS version label (e.g. "13", "12", "10").
	TLSVersion string `json:"tls_version"`
	// SNI / ALPN are surfaced for context.
	SNI  string `json:"sni,omitempty"`
	ALPN string `json:"alpn,omitempty"`
	// Note carries interpretation guidance.
	Note string `json:"note,omitempty"`
}

// JA4Decode accepts a ClientHello as hex (a full TLS record or a bare
// handshake) and returns its JA4 fingerprint.
func JA4Decode(hexInput string) (*JA4Result, error) {
	clean := strings.NewReplacer(" ", "", "\n", "", "\t", "", "\r", "", ":", "").Replace(hexInput)
	if clean == "" {
		return nil, errors.New("empty input")
	}
	raw, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("input is not valid hex: %w", err)
	}
	return JA4FromClientHello(raw)
}

// JA4FromClientHello computes the JA4 (FoxIO JA4.md) from raw ClientHello bytes.
// Scope: TLS-over-TCP (protocol "t"); QUIC/DTLS framing is not unwrapped here.
func JA4FromClientHello(b []byte) (*JA4Result, error) {
	h, err := parse(b)
	if err != nil {
		return nil, err
	}

	verLabel := tlsVersionLabel(ja4Version(h))
	sniFlag := "i"
	if h.SNIPresent {
		sniFlag = "d"
	}
	ciphers := filterGREASE(h.CiphersRaw)
	exts := filterGREASE(h.ExtOrder)
	alpn := ja4ALPN(h.ALPN)

	// JA4_a: t<ver><d|i><cc2><ec2><alpn2>. cc capped at 99; ec counts all
	// non-GREASE extensions (SNI/ALPN included).
	a := fmt.Sprintf("t%s%s%02d%02d%s", verLabel, sniFlag, capCount(len(ciphers)), capCount(len(exts)), alpn)

	// JA4_b: sha256 of the sorted cipher list (4-hex, comma-joined), 12 chars.
	bRaw := hexListSorted(ciphers)
	b12 := truncHash(bRaw)

	// JA4_c: sha256 of the sorted extension list (SNI 0x0000 and ALPN 0x0010
	// excluded) + "_" + signature_algorithms in order, 12 chars.
	cExts := excludeForC(exts)
	cExtRaw := hexListSorted(cExts)
	sigRaw := hexListInOrder(filterGREASE(h.SigAlgs))
	cInput := cExtRaw
	if sigRaw != "" {
		cInput += "_" + sigRaw
	}
	var c12 string
	if cExtRaw == "" {
		c12 = "000000000000"
	} else {
		c12 = truncHash(cInput)
	}

	res := &JA4Result{
		JA4:        a + "_" + b12 + "_" + c12,
		JA4R:       a + "_" + bRaw + "_" + cInput,
		A:          a,
		B:          b12,
		C:          c12,
		TLSVersion: verLabel,
		SNI:        h.SNI,
		Note: "JA4 client fingerprint (FoxIO). GREASE removed; ciphers and the JA4_c extension " +
			"list are sorted (SNI/ALPN excluded from JA4_c); signature_algorithms kept in order.",
	}
	if len(h.ALPN) > 0 {
		res.ALPN = h.ALPN[0]
	}
	return res, nil
}

// ja4Version returns the version value JA4_a uses: the highest non-GREASE
// supported_versions entry if present, else the legacy ClientHello version.
func ja4Version(h *Hello) int {
	best := -1
	for _, v := range h.SupportedVersions {
		if isGREASE(v) {
			continue
		}
		if int(v) > best {
			best = int(v)
		}
	}
	if best >= 0 {
		return best
	}
	return h.LegacyVersion
}

// tlsVersionLabel maps a TLS/DTLS version word to its JA4 two-char label.
func tlsVersionLabel(v int) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	case 0xfeff:
		return "d1"
	case 0xfefd:
		return "d2"
	case 0xfefc:
		return "d3"
	default:
		return "00"
	}
}

// ja4ALPN encodes the first ALPN value as JA4's two-char field: the first and
// last ASCII-alphanumeric characters of the first protocol. If absent/empty,
// "00". If the first or last byte is non-alphanumeric, JA4 falls back to the
// first nibble of the first byte's hex and the last nibble of the last byte's
// hex.
func ja4ALPN(alpn []string) string {
	if len(alpn) == 0 || alpn[0] == "" {
		return "00"
	}
	s := alpn[0]
	first, last := s[0], s[len(s)-1]
	if isAlnum(first) && isAlnum(last) {
		return string(first) + string(last)
	}
	hf := fmt.Sprintf("%02x", first)
	hl := fmt.Sprintf("%02x", last)
	return string(hf[0]) + string(hl[1])
}

func isAlnum(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// excludeForC drops SNI (0x0000) and ALPN (0x0010) from the JA4_c extension
// list per the spec.
func excludeForC(exts []int) []int {
	out := make([]int, 0, len(exts))
	for _, e := range exts {
		if e == 0x0000 || e == 0x0010 {
			continue
		}
		out = append(out, e)
	}
	return out
}

// capCount clamps a count to JA4's two-digit field (max 99).
func capCount(n int) int {
	if n > 99 {
		return 99
	}
	return n
}

// hexListSorted renders a uint16 list as sorted, comma-joined, 4-char lowercase
// hex.
func hexListSorted(xs []int) string {
	cp := append([]int(nil), xs...)
	sort.Ints(cp)
	return hexListInOrder(cp)
}

// hexListInOrder renders a uint16 list in the given order as comma-joined
// 4-char lowercase hex.
func hexListInOrder(xs []int) string {
	if len(xs) == 0 {
		return ""
	}
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = fmt.Sprintf("%04x", x)
	}
	return strings.Join(parts, ",")
}

// truncHash returns the first 12 chars of the lowercase SHA-256 hex of s.
func truncHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}
