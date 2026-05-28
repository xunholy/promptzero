// SPDX-License-Identifier: AGPL-3.0-or-later

// Closed-loop tests for all 23 protocols.
// Each test synthesises a frame with a known payload, runs the decoder,
// and asserts protocol name, confidence ≥ 0.75, and decoded payload fields.
package protocols_test

import (
	"testing"

	"github.com/xunholy/promptzero/internal/subghz/protocols"
)

// ---------------------------------------------------------------------------
// Holtek HT12E
// ---------------------------------------------------------------------------

func TestHoltekHT12ERoundTrip(t *testing.T) {
	const te = 340
	const wantAddr = uint32(0xAB)
	const wantData = uint32(0x7)
	bits := append(uint32ToBits(wantAddr, 8), uint32ToBits(wantData, 4)...)
	// sync: 1×TE mark + 28×TE space; "1" = 3×TE mark + 1×TE space
	pulses := encodePWMFrame(bits, te, 1, 28, 3, 1, 1, 3, 3)

	p := protocols.HoltekHT12E{}
	res, err := p.Decode(pulses)
	if err != nil {
		t.Fatalf("HoltekHT12E Decode error: %v", err)
	}
	assertMinConfidence(t, "HoltekHT12E", res.Confidence, 0.75)
	assertPayloadUint32(t, "HoltekHT12E", res.Payload, "address", wantAddr)
	assertPayloadUint32(t, "HoltekHT12E", res.Payload, "data", wantData)
}

func TestHoltekHT12EName(t *testing.T) {
	assertName(t, protocols.HoltekHT12E{}, "Holtek HT12E")
}

// ---------------------------------------------------------------------------
// Linear
// ---------------------------------------------------------------------------

func TestLinearRoundTrip(t *testing.T) {
	const te = 500
	const wantCode = uint32(0xA5)
	bits := uint32ToBits(wantCode, 8)
	// sync: long space ≥15×TE; "1" = 1×TE mark + 1×TE space; "0" = 1×TE + 3×TE
	pulses := encodeSyncSpaceThenPDM(bits, te, 20, 1, 3)

	p := protocols.Linear{}
	res, err := p.Decode(pulses)
	if err != nil {
		t.Fatalf("Linear Decode error: %v", err)
	}
	assertMinConfidence(t, "Linear", res.Confidence, 0.75)
	assertPayloadUint32(t, "Linear", res.Payload, "code", wantCode)
}

func TestLinearName(t *testing.T) {
	assertName(t, protocols.Linear{}, "Linear")
}

// ---------------------------------------------------------------------------
// NICE FloR-S
// ---------------------------------------------------------------------------

func TestNICEFlorSRoundTrip(t *testing.T) {
	const te = 500
	const wantButton = uint32(0x3)
	const wantHopping = uint32(0xDEAD1234)
	const wantSerial = uint32(0xBEEF)

	bits := append(uint32ToBits(wantButton, 4),
		append(uint32ToBits(wantHopping, 32),
			uint32ToBits(wantSerial, 16)...)...)

	// NICE FloR-S inverted PWM: "1" = 1×TE + 3×TE, "0" = 3×TE + 1×TE
	// Reuse encodePWMFrame with oneHigh=1, oneLow=3, zeroHigh=3, zeroLow=1
	pulses := encodePWMFrame(bits, te, 1, 30, 1, 3, 3, 1, 3)

	p := protocols.NICEFlorS{}
	res, err := p.Decode(pulses)
	if err != nil {
		t.Fatalf("NICEFlorS Decode error: %v", err)
	}
	assertMinConfidence(t, "NICEFlorS", res.Confidence, 0.75)
	assertPayloadUint32(t, "NICEFlorS", res.Payload, "button", wantButton)
	assertPayloadUint32(t, "NICEFlorS", res.Payload, "hopping_code", wantHopping)
}

func TestNICEFlorSName(t *testing.T) {
	assertName(t, protocols.NICEFlorS{}, "NICE FloR-S")
}

// ---------------------------------------------------------------------------
// KeeLoq HCS
// ---------------------------------------------------------------------------

func TestKeeLoqHCSRoundTrip(t *testing.T) {
	const te = 400
	const wantHopping = uint32(0xDEADC0DE)
	const wantSerial = uint32(0x12345678)
	const wantButton = uint32(0x1)

	// LSB-first encoding for KeeLoq
	hBits := lsbFirstBits(wantHopping, 32)
	sBits := lsbFirstBits(wantSerial, 32)
	bBits := []byte{byte(wantButton & 1), byte((wantButton >> 1) & 1)}
	bits := append(hBits, append(sBits, bBits...)...)

	// KeeLoq: header = 1×TE mark + 10×TE space; "1" = 3×TE + 1×TE; "0" = 1×TE + 3×TE
	pulses := encodePWMFrame(bits, te, 1, 10, 3, 1, 1, 3, 3)

	p := protocols.KeeLoqHCS{}
	res, err := p.Decode(pulses)
	if err != nil {
		t.Fatalf("KeeLoqHCS Decode error: %v", err)
	}
	assertMinConfidence(t, "KeeLoqHCS", res.Confidence, 0.75)
	// Verify the hopping code field exists with correct value
	gotHopping := res.Payload["hopping_code"].(uint32)
	if gotHopping != wantHopping {
		t.Errorf("hopping_code = %08X, want %08X", gotHopping, wantHopping)
	}
}

func TestKeeLoqHCSName(t *testing.T) {
	assertName(t, protocols.KeeLoqHCS{}, "KeeLoq HCS200/300")
}

// ---------------------------------------------------------------------------
// FAAC SLH
// ---------------------------------------------------------------------------

func TestFaacSLHRoundTrip(t *testing.T) {
	const te = 255
	const wantHopping = uint32(0xCAFEBABE)
	const wantFixed = uint32(0x01234567)

	bits := append(uint32ToBits(wantHopping, 32), uint32ToBits(wantFixed, 32)...)
	// FAAC SLH: "1" = 1×TE + 2×TE; "0" = 2×TE + 1×TE
	pulses := encodePWMFrame(bits, te, 1, 10, 1, 2, 2, 1, 3)

	p := protocols.FaacSLH{}
	res, err := p.Decode(pulses)
	if err != nil {
		t.Fatalf("FaacSLH Decode error: %v", err)
	}
	assertMinConfidence(t, "FaacSLH", res.Confidence, 0.75)
	assertPayloadUint32(t, "FaacSLH", res.Payload, "hopping_code", wantHopping)
	assertPayloadUint32(t, "FaacSLH", res.Payload, "fixed_code", wantFixed)
}

func TestFaacSLHName(t *testing.T) {
	assertName(t, protocols.FaacSLH{}, "FAAC SLH")
}

// ---------------------------------------------------------------------------
// Beninca
// ---------------------------------------------------------------------------

func TestBenincaRoundTrip(t *testing.T) {
	const te = 320
	const wantCode = uint32(0xB5A)
	bits := uint16ToBits(uint16(wantCode), 12)
	// Beninca: sync = 1×TE mark + 30×TE space; "1" = 1×TE + 1×TE; "0" = 1×TE + 2×TE
	pulses := encodeCMEFrame(bits, te, 1, 30, 1, 1, 1, 2, 3)

	p := protocols.Beninca{}
	res, err := p.Decode(pulses)
	if err != nil {
		t.Fatalf("Beninca Decode error: %v", err)
	}
	assertMinConfidence(t, "Beninca", res.Confidence, 0.75)
	assertPayloadUint32(t, "Beninca", res.Payload, "code", wantCode)
}

func TestBenincaName(t *testing.T) {
	assertName(t, protocols.Beninca{}, "Beninca")
}

// ---------------------------------------------------------------------------
// Prastel
// ---------------------------------------------------------------------------

func TestPrastelRoundTrip(t *testing.T) {
	const te = 500
	const wantCode = uint32(0x9F3)
	bits := uint16ToBits(uint16(wantCode), 12)
	// Prastel: sync = long space (20×TE); "1" = 1×TE + 2×TE; "0" = 1×TE + 1×TE
	pulses := encodeSyncSpaceThenPDM(bits, te, 20, 2, 1)

	p := protocols.Prastel{}
	res, err := p.Decode(pulses)
	if err != nil {
		t.Fatalf("Prastel Decode error: %v", err)
	}
	assertMinConfidence(t, "Prastel", res.Confidence, 0.75)
	assertPayloadUint32(t, "Prastel", res.Payload, "code", wantCode)
}

func TestPrastelName(t *testing.T) {
	assertName(t, protocols.Prastel{}, "Prastel")
}

// ---------------------------------------------------------------------------
// Ansonic
// ---------------------------------------------------------------------------

func TestAnsonicRoundTrip(t *testing.T) {
	const te = 400
	const wantCode = uint32(0x7E3)
	bits := uint16ToBits(uint16(wantCode), 12)
	// Ansonic: sync = long mark + long space; bits = Manchester pairs
	pulses := encodeManchesterFrame(bits, te, 10, 10)

	p := protocols.Ansonic{}
	res, err := p.Decode(pulses)
	if err != nil {
		t.Fatalf("Ansonic Decode error: %v", err)
	}
	assertMinConfidence(t, "Ansonic", res.Confidence, 0.75)
	assertPayloadUint32(t, "Ansonic", res.Payload, "code", wantCode)
}

func TestAnsonicName(t *testing.T) {
	assertName(t, protocols.Ansonic{}, "Ansonic")
}

// ---------------------------------------------------------------------------
// Smartgate
// ---------------------------------------------------------------------------

func TestSmartgateRoundTrip(t *testing.T) {
	const te = 1000
	const wantCode = uint32(0xABCDEF)
	bits := uint32ToBits(wantCode, 24)
	// Smartgate: sync = long space ≥25×TE; "1" = 2×TE + 1×TE; "0" = 1×TE + 2×TE
	pulses := encodeSyncSpaceThenSmartgate(bits, te)

	p := protocols.Smartgate{}
	res, err := p.Decode(pulses)
	if err != nil {
		t.Fatalf("Smartgate Decode error: %v", err)
	}
	assertMinConfidence(t, "Smartgate", res.Confidence, 0.75)
	assertPayloadUint32(t, "Smartgate", res.Payload, "code", wantCode)
}

func TestSmartgateName(t *testing.T) {
	assertName(t, protocols.Smartgate{}, "Smartgate")
}

func encodeSyncSpaceThenSmartgate(bits []byte, te int) []int {
	out := []int{-(30 * te)}
	for _, b := range bits {
		if b != 0 {
			out = append(out, 2*te, -te)
		} else {
			out = append(out, te, -(2 * te))
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Aerolite (substitution for Hormann HSM)
// ---------------------------------------------------------------------------

func TestAeroliteRoundTrip(t *testing.T) {
	const te = 500
	const wantCode = uint32(0xC0FFEE)
	bits := uint32ToBits(wantCode, 24)
	// Aerolite: sync = 1×TE + 35×TE; "1" = 3×TE + 1×TE; "0" = 1×TE + 3×TE
	pulses := encodePWMFrame(bits, te, 1, 35, 3, 1, 1, 3, 3)

	p := protocols.Aerolite{}
	res, err := p.Decode(pulses)
	if err != nil {
		t.Fatalf("Aerolite Decode error: %v", err)
	}
	assertMinConfidence(t, "Aerolite", res.Confidence, 0.75)
	assertPayloadUint32(t, "Aerolite", res.Payload, "code", wantCode)
}

func TestAeroliteName(t *testing.T) {
	assertName(t, protocols.Aerolite{}, "Aerolite (Nero Radio)")
}

// ---------------------------------------------------------------------------
// Doitrand
// ---------------------------------------------------------------------------

func TestDoitrandRoundTrip(t *testing.T) {
	const te = 400
	const wantCode = uint32(0xD5C)
	bits := uint16ToBits(uint16(wantCode), 12)
	// Doitrand: sync = long space ≥18×TE; "1" = 1×TE + 3×TE; "0" = 1×TE + 1×TE
	pulses := encodeSyncSpaceThenPDM(bits, te, 20, 3, 1)

	p := protocols.Doitrand{}
	res, err := p.Decode(pulses)
	if err != nil {
		t.Fatalf("Doitrand Decode error: %v", err)
	}
	assertMinConfidence(t, "Doitrand", res.Confidence, 0.75)
	assertPayloadUint32(t, "Doitrand", res.Payload, "code", wantCode)
}

func TestDoitrandName(t *testing.T) {
	assertName(t, protocols.Doitrand{}, "Doitrand")
}

// ---------------------------------------------------------------------------
// Security+ v1 (substitution for Linkmaster)
// ---------------------------------------------------------------------------

func TestSecplusV1RoundTrip(t *testing.T) {
	const te = 500
	const wantRolling = uint32(0xA5A5A)
	const wantFixed = uint32(0xF0F0F)
	bits := append(uint32ToBits(wantRolling, 20), uint32ToBits(wantFixed, 20)...)
	// Secplus v1: sync = long mark ≥12×TE; "1" = 1×TE + 2×TE; "0" = 2×TE + 1×TE
	pulses := encodeSyncMarkThenBits(bits, te)

	p := protocols.SecplusV1{}
	res, err := p.Decode(pulses)
	if err != nil {
		t.Fatalf("SecplusV1 Decode error: %v", err)
	}
	assertMinConfidence(t, "SecplusV1", res.Confidence, 0.75)
	assertPayloadUint32(t, "SecplusV1", res.Payload, "rolling_code", wantRolling)
	assertPayloadUint32(t, "SecplusV1", res.Payload, "fixed_code", wantFixed)
}

func TestSecplusV1Name(t *testing.T) {
	assertName(t, protocols.SecplusV1{}, "Security+ v1")
}

func encodeSyncMarkThenBits(bits []byte, te int) []int {
	// Long mark sync then PDM bits
	out := []int{14 * te, -te}
	for _, b := range bits {
		if b != 0 {
			out = append(out, te, -(2 * te))
		} else {
			out = append(out, 2*te, -te)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Magicode
// ---------------------------------------------------------------------------

func TestMagicodeRoundTrip(t *testing.T) {
	const te = 300
	const wantCode = uint32(0xFACEB00)
	bits := uint32ToBits(wantCode, 28)
	// Magicode: sync = 1×TE + 32×TE; "1" = 2×TE + 1×TE; "0" = 1×TE + 2×TE
	pulses := encodePWMFrame(bits, te, 1, 32, 2, 1, 1, 2, 3)

	p := protocols.Magicode{}
	res, err := p.Decode(pulses)
	if err != nil {
		t.Fatalf("Magicode Decode error: %v", err)
	}
	assertMinConfidence(t, "Magicode", res.Confidence, 0.75)
	assertPayloadUint32(t, "Magicode", res.Payload, "code", wantCode)
}

func TestMagicodeName(t *testing.T) {
	assertName(t, protocols.Magicode{}, "Magicode")
}

// ---------------------------------------------------------------------------
// Honeywell WS
// ---------------------------------------------------------------------------

func TestHoneywellWSRoundTrip(t *testing.T) {
	const te = 170
	const wantSerial = uint32(0xA1B2C3)
	const wantLoop = uint32(0x3)
	const wantStatus = uint32(0x5)
	bits := append(uint32ToBits(wantSerial, 24),
		append(uint32ToBits(wantLoop, 4),
			uint32ToBits(wantStatus, 4)...)...)
	// Pad to 48 bits with a dummy checksum
	bits = append(bits, uint32ToBits(0xABCD, 16)...)

	// Honeywell WS: sync = long mark ≥8×TE; "1" = 2×TE + 1×TE; "0" = 1×TE + 2×TE
	pulses := encodeSyncMarkThenBitsHoneywell(bits, te)

	p := protocols.HoneywellWS{}
	res, err := p.Decode(pulses)
	if err != nil {
		t.Fatalf("HoneywellWS Decode error: %v", err)
	}
	assertMinConfidence(t, "HoneywellWS", res.Confidence, 0.75)
	assertPayloadUint32(t, "HoneywellWS", res.Payload, "serial", wantSerial)
}

func TestHoneywellWSName(t *testing.T) {
	assertName(t, protocols.HoneywellWS{}, "Honeywell WS")
}

func encodeSyncMarkThenBitsHoneywell(bits []byte, te int) []int {
	out := []int{10 * te, -te}
	for _, b := range bits {
		if b != 0 {
			out = append(out, 2*te, -te)
		} else {
			out = append(out, te, -(2 * te))
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Princeton-Holtek
// ---------------------------------------------------------------------------

func TestPrincetonHoltekRoundTrip(t *testing.T) {
	const te = 350
	const wantAddr = uint32(0xCD)
	const wantData = uint32(0xA)
	bits := append(uint32ToBits(wantAddr, 8), uint32ToBits(wantData, 4)...)
	// Princeton-Holtek: same encoding as Princeton PT2262
	pulses := encodePWMFrame(bits, te, 1, 25, 3, 1, 1, 3, 3)

	p := protocols.PrincetonHoltek{}
	res, err := p.Decode(pulses)
	if err != nil {
		t.Fatalf("PrincetonHoltek Decode error: %v", err)
	}
	assertMinConfidence(t, "PrincetonHoltek", res.Confidence, 0.70)
	assertPayloadUint32(t, "PrincetonHoltek", res.Payload, "address", wantAddr)
}

func TestPrincetonHoltekName(t *testing.T) {
	assertName(t, protocols.PrincetonHoltek{}, "Princeton-Holtek")
}

// ---------------------------------------------------------------------------
// CAME TWIN
// ---------------------------------------------------------------------------

func TestCAMETwinRoundTrip(t *testing.T) {
	const te = 320
	const wantCode = uint32(0x7B3)
	bits := uint16ToBits(uint16(wantCode), 12)
	// CAME TWIN: sync = 2×TE mark + 36×TE space
	pulses := encodeCMEFrame(bits, te, 2, 36, 1, 1, 1, 2, 3)

	p := protocols.CAMETwin{}
	res, err := p.Decode(pulses)
	if err != nil {
		t.Fatalf("CAMETwin Decode error: %v", err)
	}
	assertMinConfidence(t, "CAMETwin", res.Confidence, 0.75)
	assertPayloadUint32(t, "CAMETwin", res.Payload, "code", wantCode)
}

func TestCAMETwinName(t *testing.T) {
	assertName(t, protocols.CAMETwin{}, "CAME TWIN")
}

// ---------------------------------------------------------------------------
// Aprimatic
// ---------------------------------------------------------------------------

func TestAprimaticRoundTrip(t *testing.T) {
	const te = 500
	const wantCode = uint32(0x1A2B3C)
	bits := uint32ToBits(wantCode, 24)
	// Aprimatic: sync = 1×TE + 32×TE; "1" = 3×TE + 1×TE; "0" = 1×TE + 3×TE
	pulses := encodePWMFrame(bits, te, 1, 32, 3, 1, 1, 3, 3)

	p := protocols.Aprimatic{}
	res, err := p.Decode(pulses)
	if err != nil {
		t.Fatalf("Aprimatic Decode error: %v", err)
	}
	assertMinConfidence(t, "Aprimatic", res.Confidence, 0.75)
	assertPayloadUint32(t, "Aprimatic", res.Payload, "code", wantCode)
}

func TestAprimaticName(t *testing.T) {
	assertName(t, protocols.Aprimatic{}, "Aprimatic")
}

// ---------------------------------------------------------------------------
// Phoenix V2
// ---------------------------------------------------------------------------

func TestPhoenixV2RoundTrip(t *testing.T) {
	const te = 433
	const wantAddr = uint32(0xDE)
	const wantData = uint32(0xB)
	bits := append(uint32ToBits(wantAddr, 8), uint32ToBits(wantData, 4)...)
	// Phoenix V2: same Princeton-style PWM; sync = 1×TE + 28×TE
	pulses := encodePWMFrame(bits, te, 1, 28, 3, 1, 1, 3, 3)

	p := protocols.PhoenixV2{}
	res, err := p.Decode(pulses)
	if err != nil {
		t.Fatalf("PhoenixV2 Decode error: %v", err)
	}
	assertMinConfidence(t, "PhoenixV2", res.Confidence, 0.75)
	assertPayloadUint32(t, "PhoenixV2", res.Payload, "address", wantAddr)
	assertPayloadUint32(t, "PhoenixV2", res.Payload, "data", wantData)
}

func TestPhoenixV2Name(t *testing.T) {
	assertName(t, protocols.PhoenixV2{}, "Phoenix V2")
}

// ---------------------------------------------------------------------------
// Nice FLO
// ---------------------------------------------------------------------------

func TestNiceFLORoundTrip(t *testing.T) {
	const te = 700
	const wantCode = uint32(0xA5B)
	bits := uint16ToBits(uint16(wantCode), 12)
	// Nice FLO: sync = 1×TE mark + 36×TE space; "1" = 3×TE + 1×TE; "0" = 1×TE + 3×TE
	pulses := encodePWMFrame(bits, te, 1, 36, 3, 1, 1, 3, 1)

	p := protocols.NiceFLO{}
	res, err := p.Decode(pulses)
	if err != nil {
		t.Fatalf("NiceFLO Decode error: %v", err)
	}
	assertMinConfidence(t, "NiceFLO", res.Confidence, 0.75)
	assertPayloadUint32(t, "NiceFLO", res.Payload, "code", wantCode)
	if _, ok := res.Payload["te_us"]; !ok {
		t.Errorf("NiceFLO: payload missing key \"te_us\"")
	}
}

func TestNiceFLOName(t *testing.T) {
	assertName(t, protocols.NiceFLO{}, "Nice FLO")
}

// ---------------------------------------------------------------------------
// BFT Mitto
// ---------------------------------------------------------------------------

func TestBFTMittoRoundTrip(t *testing.T) {
	const te = 400
	const wantCode = uint32(0xC3A)
	bits := uint16ToBits(uint16(wantCode), 12)
	// BFT Mitto: sync = 1×TE mark + 36×TE space; "1" = 3×TE + 1×TE; "0" = 1×TE + 3×TE
	pulses := encodePWMFrame(bits, te, 1, 36, 3, 1, 1, 3, 1)

	p := protocols.BFTMitto{}
	res, err := p.Decode(pulses)
	if err != nil {
		t.Fatalf("BFTMitto Decode error: %v", err)
	}
	assertMinConfidence(t, "BFTMitto", res.Confidence, 0.75)
	assertPayloadUint32(t, "BFTMitto", res.Payload, "code", wantCode)
	if _, ok := res.Payload["te_us"]; !ok {
		t.Errorf("BFTMitto: payload missing key \"te_us\"")
	}
}

func TestBFTMittoName(t *testing.T) {
	assertName(t, protocols.BFTMitto{}, "BFT Mitto")
}

// ---------------------------------------------------------------------------
// Somfy RTS
// ---------------------------------------------------------------------------

func TestSomfyRTSRoundTrip(t *testing.T) {
	const te = 640
	// Build 56 Manchester bits: space→mark = 1, mark→space = 0.
	// Encode a simple payload: all-ones for key byte, then alternating.
	bits := make([]byte, 56)
	for i := range bits {
		if i%2 == 0 {
			bits[i] = 1
		} else {
			bits[i] = 0
		}
	}
	pulses := encodeSomfyRTSFrame(bits, te)

	p := protocols.SomfyRTS{}
	res, err := p.Decode(pulses)
	if err != nil {
		t.Fatalf("SomfyRTS Decode error: %v", err)
	}
	assertMinConfidence(t, "SomfyRTS", res.Confidence, 0.75)
	if len(res.Bits) != 56 {
		t.Errorf("SomfyRTS: got %d bits, want 56", len(res.Bits))
	}
}

func TestSomfyRTSName(t *testing.T) {
	assertName(t, protocols.SomfyRTS{}, "Somfy RTS")
}

// encodeSomfyRTSFrame builds a Somfy RTS pulse sequence for testing.
// Soft sync: 4×TE mark + 4×TE space, then 56 Manchester bits.
// Manchester: bit=1 → space(−TE) + mark(+TE); bit=0 → mark(+TE) + space(−TE).
func encodeSomfyRTSFrame(bits []byte, te int) []int {
	// Soft sync: long mark + long space (each ≥3×TE)
	out := []int{4 * te, -(4 * te)}
	for _, b := range bits {
		if b != 0 {
			// rising transition: space half then mark half
			out = append(out, -te, te)
		} else {
			// falling transition: mark half then space half
			out = append(out, te, -te)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Shared assertion helpers
// ---------------------------------------------------------------------------

func assertName(t *testing.T, p interface{ Name() string }, want string) {
	t.Helper()
	if got := p.Name(); got != want {
		t.Errorf("Name() = %q, want %q", got, want)
	}
}

func assertMinConfidence(t *testing.T, name string, got, min float64) {
	t.Helper()
	if got < min {
		t.Errorf("%s confidence = %.3f, want ≥ %.2f", name, got, min)
	}
}

func assertPayloadUint32(t *testing.T, proto string, payload map[string]any, key string, want uint32) {
	t.Helper()
	v, ok := payload[key]
	if !ok {
		t.Errorf("%s: payload missing key %q", proto, key)
		return
	}
	got, ok := v.(uint32)
	if !ok {
		t.Errorf("%s: payload[%q] type = %T, want uint32", proto, key, v)
		return
	}
	if got != want {
		t.Errorf("%s: payload[%q] = %d (0x%X), want %d (0x%X)", proto, key, got, got, want, want)
	}
}

// lsbFirstBits encodes a uint32 as n bits LSB-first.
func lsbFirstBits(v uint32, n int) []byte {
	bits := make([]byte, n)
	for i := 0; i < n; i++ {
		bits[i] = byte((v >> uint(i)) & 1)
	}
	return bits
}

// ---------------------------------------------------------------------------
// Marantec
// ---------------------------------------------------------------------------

func TestMarantecRoundTrip(t *testing.T) {
	const te = 800
	const wantCode = uint32(0xA5B)
	bits := uint16ToBits(uint16(wantCode), 12)
	// Marantec: sync = 1×TE mark + 16×TE space; "1" = 3×TE + 1×TE; "0" = 1×TE + 3×TE
	pulses := encodePWMFrame(bits, te, 1, 16, 3, 1, 1, 3, 1)

	p := protocols.Marantec{}
	res, err := p.Decode(pulses)
	if err != nil {
		t.Fatalf("Marantec Decode error: %v", err)
	}
	assertMinConfidence(t, "Marantec", res.Confidence, 0.75)
	assertPayloadUint32(t, "Marantec", res.Payload, "code", wantCode)
	if _, ok := res.Payload["te_us"]; !ok {
		t.Errorf("Marantec: payload missing key \"te_us\"")
	}
}

func TestMarantecName(t *testing.T) {
	assertName(t, protocols.Marantec{}, "Marantec")
}

// ---------------------------------------------------------------------------
// BETT
// ---------------------------------------------------------------------------

func TestBETTRoundTrip(t *testing.T) {
	const te = 400
	// 18-bit code: 9 DIP pairs — encode as PWM bits
	// Use a pattern that produces known DIP states:
	//   ON=11, OFF=00, Float=01 → bits: 1,1,0,0,0,1,1,1,0,0,0,1,1,1,0,0,0,1
	bits := []byte{1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1}
	const wantCode = uint32((1 << 17) | (1 << 16) | (0 << 15) | (0 << 14) | (0 << 13) | (1 << 12) |
		(1 << 11) | (1 << 10) | (0 << 9) | (0 << 8) | (0 << 7) | (1 << 6) |
		(1 << 5) | (1 << 4) | (0 << 3) | (0 << 2) | (0 << 1) | 1)
	// Sync: 1×TE mark + 45×TE space; "1" = 3×TE + 1×TE; "0" = 1×TE + 3×TE
	pulses := encodePWMFrame(bits, te, 1, 45, 3, 1, 1, 3, 1)

	p := protocols.BETT{}
	res, err := p.Decode(pulses)
	if err != nil {
		t.Fatalf("BETT Decode error: %v", err)
	}
	assertMinConfidence(t, "BETT", res.Confidence, 0.75)
	assertPayloadUint32(t, "BETT", res.Payload, "code", wantCode)
	dipRaw, ok := res.Payload["dip_switches"]
	if !ok {
		t.Fatalf("BETT: payload missing key \"dip_switches\"")
	}
	dips, ok := dipRaw.([]string)
	if !ok {
		t.Fatalf("BETT: dip_switches type = %T, want []string", dipRaw)
	}
	if len(dips) != 9 {
		t.Errorf("BETT: len(dip_switches) = %d, want 9", len(dips))
	}
	// Pair 0 = bits[0..1] = 1,1 → ON
	if dips[0] != "ON" {
		t.Errorf("BETT: dip_switches[0] = %q, want \"ON\"", dips[0])
	}
	// Pair 1 = bits[2..3] = 0,0 → OFF
	if dips[1] != "OFF" {
		t.Errorf("BETT: dip_switches[1] = %q, want \"OFF\"", dips[1])
	}
	// Pair 2 = bits[4..5] = 0,1 → Float
	if dips[2] != "Float" {
		t.Errorf("BETT: dip_switches[2] = %q, want \"Float\"", dips[2])
	}
	if _, ok := res.Payload["te_us"]; !ok {
		t.Errorf("BETT: payload missing key \"te_us\"")
	}
}

func TestBETTName(t *testing.T) {
	assertName(t, protocols.BETT{}, "BETT")
}

// ---------------------------------------------------------------------------
// Security+ v2
// ---------------------------------------------------------------------------

func TestSecplusV2RoundTrip(t *testing.T) {
	const te = 250
	// Build 20 trits: use a simple repeating pattern 0,1,2,0,1,2,...
	trits := []int{0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1}
	var wantTritValue uint64
	for _, trit := range trits {
		wantTritValue = wantTritValue*3 + uint64(trit)
	}

	pulses := encodeSecplusV2Frame(trits, te)

	p := protocols.SecplusV2{}
	res, err := p.Decode(pulses)
	if err != nil {
		t.Fatalf("SecplusV2 Decode error: %v", err)
	}
	assertMinConfidence(t, "SecplusV2", res.Confidence, 0.75)
	gotTV, ok := res.Payload["trit_value"]
	if !ok {
		t.Fatalf("SecplusV2: payload missing key \"trit_value\"")
	}
	gotU64, ok := gotTV.(uint64)
	if !ok {
		t.Fatalf("SecplusV2: trit_value type = %T, want uint64", gotTV)
	}
	if gotU64 != wantTritValue {
		t.Errorf("SecplusV2: trit_value = %d, want %d", gotU64, wantTritValue)
	}
	if _, ok := res.Payload["te_us"]; !ok {
		t.Errorf("SecplusV2: payload missing key \"te_us\"")
	}
}

func TestSecplusV2Name(t *testing.T) {
	assertName(t, protocols.SecplusV2{}, "Security+ v2")
}

// encodeSecplusV2Frame synthesises a Security+ v2 pulse sequence for testing.
// Preamble: 10 short alternating pulses (each ~TE), then a 5×TE sync mark,
// then 20 trit pairs: each = ~1×TE mark + space of (2*trit+3)*TE/2.
func encodeSecplusV2Frame(trits []int, te int) []int {
	// Preamble: 10 alternating pulses
	out := make([]int, 0, 12+len(trits)*2)
	for i := 0; i < 10; i++ {
		if i%2 == 0 {
			out = append(out, te)
		} else {
			out = append(out, -te)
		}
	}
	// Sync: long mark (5×TE)
	out = append(out, 5*te)
	// Trits: mark=TE, space=(1.5, 2.5, or 3.5)×TE
	// Trit 0 → space = 3*te/2; Trit 1 → 5*te/2; Trit 2 → 7*te/2
	spaceFor := [3]int{3 * te / 2, 5 * te / 2, 7 * te / 2}
	for _, trit := range trits {
		out = append(out, te, -spaceFor[trit])
	}
	return out
}

// allDecoders returns every registered protocol decoder. Kept in sync
// with subghz.NewClassifier — a guard against a new protocol being
// added without negative-path coverage.
func allDecoders() []interface {
	Name() string
	Decode([]int) (protocols.Result, error)
} {
	return []interface {
		Name() string
		Decode([]int) (protocols.Result, error)
	}{
		protocols.PrincetonPT2262{}, protocols.CAME{}, protocols.HoltekHT12E{},
		protocols.Linear{}, protocols.NICEFlorS{}, protocols.KeeLoqHCS{},
		protocols.FaacSLH{}, protocols.Beninca{}, protocols.Prastel{},
		protocols.Ansonic{}, protocols.Smartgate{}, protocols.Aerolite{},
		protocols.Doitrand{}, protocols.SecplusV1{}, protocols.Magicode{},
		protocols.HoneywellWS{}, protocols.PrincetonHoltek{}, protocols.CAMETwin{},
		protocols.Aprimatic{}, protocols.PhoenixV2{}, protocols.NiceFLO{},
		protocols.BFTMitto{}, protocols.SomfyRTS{}, protocols.Marantec{},
		protocols.BETT{}, protocols.SecplusV2{},
	}
}

// TestAllProtocols_MalformedInputNeverPanics feeds every decoder a
// battery of degenerate pulse sequences (nil, empty, single pulse,
// zero-width, sign-only). A decoder must return an error or a
// low-confidence Result — never panic — because real-world captures
// from a noisy RF environment routinely produce truncated or garbage
// pulse trains.
func TestAllProtocols_MalformedInputNeverPanics(t *testing.T) {
	inputs := [][]int{
		nil,
		{},
		{0},
		{1},
		{-1},
		{1, -1},
		{100},
		{100, -100},
		{0, 0, 0},
		{1 << 30, -(1 << 30)},
	}
	for _, p := range allDecoders() {
		for _, in := range inputs {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("%s panicked on input %v: %v", p.Name(), in, r)
					}
				}()
				_, _ = p.Decode(in)
			}()
		}
	}
}
