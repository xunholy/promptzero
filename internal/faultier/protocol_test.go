package faultier

import (
	"encoding/binary"
	"testing"
)

// TestFrameChecksum verifies that frameChecksum is the XOR of opcode and all
// payload bytes.
func TestFrameChecksum(t *testing.T) {
	// Zero payload: checksum == opcode.
	if got := frameChecksum(OpArm, nil); got != OpArm {
		t.Errorf("frameChecksum(OpArm, nil) = 0x%02X, want 0x%02X", got, OpArm)
	}

	// Checksum is XOR of all bytes.
	payload := []byte{0x01, 0x02, 0x03}
	want := OpConfigure ^ byte(0x01) ^ byte(0x02) ^ byte(0x03)
	if got := frameChecksum(OpConfigure, payload); got != want {
		t.Errorf("frameChecksum = 0x%02X, want 0x%02X", got, want)
	}
}

// TestEncodeDecodeConfigPayload verifies round-trip symmetry for GlitcherConfig
// serialisation.
func TestEncodeDecodeConfigPayload(t *testing.T) {
	cases := []GlitcherConfig{
		{
			TriggerType:   TriggerNone,
			TriggerSource: TriggerSrcNone,
			GlitchOutput:  OutCrowbar,
			DelayUS:       0,
			PulseUS:       0,
			PowerCycle:    false,
			PowerCycleLen: 0,
		},
		{
			TriggerType:   TriggerRisingEdge,
			TriggerSource: TriggerSrcExt0,
			GlitchOutput:  OutMux0,
			DelayUS:       1234567,
			PulseUS:       42,
			PowerCycle:    true,
			PowerCycleLen: 200,
		},
		{
			TriggerType:   TriggerFallingEdge,
			TriggerSource: TriggerSrcExt1,
			GlitchOutput:  OutNone,
			DelayUS:       0xFFFFFFFF,
			PulseUS:       0,
			PowerCycle:    false,
			PowerCycleLen: 255,
		},
	}

	for i, want := range cases {
		p := encodeConfigPayload(want)
		if len(p) != ConfigurePayloadLen {
			t.Errorf("case %d: encoded length %d, want %d", i, len(p), ConfigurePayloadLen)
			continue
		}
		got, err := decodeConfigPayload(p)
		if err != nil {
			t.Errorf("case %d: decodeConfigPayload: %v", i, err)
			continue
		}
		if got != want {
			t.Errorf("case %d:\n got  %+v\n want %+v", i, got, want)
		}
	}
}

// TestDecodeConfigPayloadTooShort verifies that decodeConfigPayload rejects
// under-length slices.
func TestDecodeConfigPayloadTooShort(t *testing.T) {
	short := make([]byte, ConfigurePayloadLen-1)
	if _, err := decodeConfigPayload(short); err == nil {
		t.Error("expected error for too-short payload, got nil")
	}
}

// TestConfigurePayloadFieldPositions checks that each field is encoded at the
// documented byte offset so the firmware side can parse them correctly.
func TestConfigurePayloadFieldPositions(t *testing.T) {
	cfg := GlitcherConfig{
		TriggerType:   TriggerHigh,
		TriggerSource: TriggerSrcExt1,
		GlitchOutput:  OutMux2,
		DelayUS:       0x01020304,
		PulseUS:       0x05060708,
		PowerCycle:    true,
		PowerCycleLen: 0xAB,
	}
	p := encodeConfigPayload(cfg)

	if p[0] != byte(TriggerHigh) {
		t.Errorf("p[0] (trigger_type) = 0x%02X, want 0x%02X", p[0], byte(TriggerHigh))
	}
	if p[1] != byte(TriggerSrcExt1) {
		t.Errorf("p[1] (trigger_source) = 0x%02X, want 0x%02X", p[1], byte(TriggerSrcExt1))
	}
	if p[2] != byte(OutMux2) {
		t.Errorf("p[2] (glitch_output) = 0x%02X, want 0x%02X", p[2], byte(OutMux2))
	}
	if d := binary.LittleEndian.Uint32(p[3:7]); d != 0x01020304 {
		t.Errorf("p[3:7] (delay_us) = 0x%08X, want 0x01020304", d)
	}
	if w := binary.LittleEndian.Uint32(p[7:11]); w != 0x05060708 {
		t.Errorf("p[7:11] (pulse_us) = 0x%08X, want 0x05060708", w)
	}
	if p[11] != 0x01 {
		t.Errorf("p[11] (power_cycle) = 0x%02X, want 0x01", p[11])
	}
	if p[12] != 0xAB {
		t.Errorf("p[12] (power_cycle_len) = 0x%02X, want 0xAB", p[12])
	}
}

// TestOpcodeConstants verifies that the opcode values are as documented.
func TestOpcodeConstants(t *testing.T) {
	cases := []struct {
		name string
		got  byte
		want byte
	}{
		{"OpConfigure", OpConfigure, 0x01},
		{"OpArm", OpArm, 0x02},
		{"OpFire", OpFire, 0x03},
		{"OpDisarm", OpDisarm, 0x04},
		{"OpStatus", OpStatus, 0x05},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s = 0x%02X, want 0x%02X", tc.name, tc.got, tc.want)
		}
	}
}

// TestResponseCodeConstants verifies the response code values.
func TestResponseCodeConstants(t *testing.T) {
	cases := []struct {
		name string
		got  byte
		want byte
	}{
		{"RespOK", RespOK, 0x4B},
		{"RespError", RespError, 0x45},
		{"RespStatus", RespStatus, 0x53},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s = 0x%02X, want 0x%02X", tc.name, tc.got, tc.want)
		}
	}
}

// TestOutcomeString ensures OutcomeString covers all defined outcome codes.
func TestOutcomeString(t *testing.T) {
	cases := []struct {
		code byte
		want string
	}{
		{OutcomeNone, "none"},
		{OutcomeSkip, "skip"},
		{OutcomeCrash, "crash"},
		{OutcomeGlitch, "glitch"},
		{OutcomeOK, "ok"},
		{0xFF, "unknown(0xFF)"},
	}
	for _, tc := range cases {
		if got := OutcomeString(tc.code); got != tc.want {
			t.Errorf("OutcomeString(0x%02X) = %q, want %q", tc.code, got, tc.want)
		}
	}
}

// TestErrCodeString ensures ErrCodeString covers all defined error codes.
func TestErrCodeString(t *testing.T) {
	cases := []struct {
		code byte
		want string
	}{
		{ErrNotArmed, "not armed"},
		{ErrInvalidParam, "invalid param"},
		{ErrBusy, "busy"},
		{ErrHWFault, "hardware fault"},
		{0xEE, "unknown error 0xEE"},
	}
	for _, tc := range cases {
		if got := ErrCodeString(tc.code); got != tc.want {
			t.Errorf("ErrCodeString(0x%02X) = %q, want %q", tc.code, got, tc.want)
		}
	}
}

// TestFrameMagicConstants verifies the magic bytes.
func TestFrameMagicConstants(t *testing.T) {
	if FrameMagic0 != 0xFA {
		t.Errorf("FrameMagic0 = 0x%02X, want 0xFA", FrameMagic0)
	}
	if FrameMagic1 != 0x57 {
		t.Errorf("FrameMagic1 = 0x%02X, want 0x57", FrameMagic1)
	}
}

// TestStatusBlockLen verifies the documented constant matches the struct fields.
func TestStatusBlockLen(t *testing.T) {
	// armed(1) + last_delay_us(4) + last_outcome(1) + reserved(1) = 7
	const want = 7
	if StatusBlockLen != want {
		t.Errorf("StatusBlockLen = %d, want %d", StatusBlockLen, want)
	}
}
