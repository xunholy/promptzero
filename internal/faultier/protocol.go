package faultier

import "fmt"

// Wire-protocol constants for the Faultier serial-bridge interface.
//
// The upstream faultier-python library (github.com/hextreeio/faultier-python)
// uses USB bulk transfer with a "FLTR"-framed Protobuf encoding over endpoint
// pair 0x02/0x83.  Because CGO_ENABLED=0 forbids a Go USB HID driver, this
// package instead targets the secondary CDC-ACM serial bridge exposed by the
// same hardware and defines a semantically-equivalent framed binary protocol.
//
// Frame layout:
//   [magic0:1][magic1:1][opcode:1][payload_len:2 LE][payload:N][checksum:1]
//
// Response layout:
//   [magic0:1][magic1:1][resp_code:1][...optional payload...]

const (
	// FrameMagic0 and FrameMagic1 are the two-byte frame preamble (0xFA 0x57).
	FrameMagic0 byte = 0xFA
	FrameMagic1 byte = 0x57

	// FrameHeaderLen is the number of bytes before the payload:
	//   magic(2) + opcode(1) + payload_len(2) = 5.
	FrameHeaderLen = 5

	// FrameChecksumLen is the single XOR checksum byte appended after payload.
	FrameChecksumLen = 1
)

// Opcodes sent from host to device.
const (
	// OpConfigure (0x01) transmits a CommandConfigureGlitcher-equivalent payload
	// (trigger type, trigger source, glitch output, delay, pulse, power-cycle).
	OpConfigure byte = 0x01

	// OpArm (0x02) arms the configured trigger.  Maps to the Python-side
	// glitch_non_blocking pattern (send configure + glitch command, await trigger).
	OpArm byte = 0x02

	// OpFire (0x03) fires the glitch immediately without waiting for a hardware
	// trigger.  Maps to Faultier.glitch(delay=0) with TRIGGER_NONE.
	OpFire byte = 0x03

	// OpDisarm (0x04) cancels an armed trigger.  No direct upstream equivalent;
	// the Python library resets settings via default_settings() for the same effect.
	OpDisarm byte = 0x04

	// OpStatus (0x05) queries current armed state and last glitch outcome.
	OpStatus byte = 0x05
)

// Response codes returned by the device.
const (
	// RespOK (0x4B 'K') — operation completed successfully.
	RespOK byte = 0x4B

	// RespError (0x45 'E') — operation failed; next byte is an ErrCode.
	RespError byte = 0x45

	// RespStatus (0x53 'S') — response to OpStatus; followed by a StatusBlock.
	RespStatus byte = 0x53
)

// Error codes that follow a RespError byte.
const (
	ErrNotArmed     byte = 0x01 // OpFire called when not armed
	ErrInvalidParam byte = 0x02 // payload rejected (range, format)
	ErrBusy         byte = 0x03 // prior operation not yet complete
	ErrHWFault      byte = 0x04 // hardware fault (crowbar, MUX driver)
)

// Outcome values in the StatusBlock.LastOutcome field.
const (
	OutcomeNone   byte = 0x00 // no glitch attempted yet this session
	OutcomeSkip   byte = 0x01 // trigger armed but no edge seen (disarmed)
	OutcomeCrash  byte = 0x02 // target crashed (power lost / no comms)
	OutcomeGlitch byte = 0x03 // glitch pulse delivered
	OutcomeOK     byte = 0x04 // target survived (power OK after glitch)
)

// TriggerType selects the hardware-trigger condition wired to the Faultier EXT
// inputs.  Mirrors faultier_pb2.TriggersType in the upstream Python library.
type TriggerType byte

const (
	TriggerNone         TriggerType = 0x00 // immediate — no trigger wait
	TriggerRisingEdge   TriggerType = 0x01 // TRIGGER_RISING_EDGE
	TriggerFallingEdge  TriggerType = 0x02 // TRIGGER_FALLING_EDGE
	TriggerHigh         TriggerType = 0x03 // TRIGGER_HIGH
	TriggerLow          TriggerType = 0x04 // TRIGGER_LOW
)

// TriggerSource selects which physical input pin to watch.
// Mirrors faultier_pb2.TriggerSource.
type TriggerSource byte

const (
	TriggerSrcNone TriggerSource = 0x00 // TRIGGER_IN_NONE
	TriggerSrcExt0 TriggerSource = 0x01 // TRIGGER_IN_EXT0
	TriggerSrcExt1 TriggerSource = 0x02 // TRIGGER_IN_EXT1
)

// GlitchOutput selects which hardware output is toggled during the glitch
// pulse.  Mirrors faultier_pb2.GlitchOutput.
type GlitchOutput byte

const (
	OutCrowbar GlitchOutput = 0x00 // OUT_CROWBAR — gate of the crowbar MOSFET
	OutMux0    GlitchOutput = 0x01 // OUT_MUX0    — SMA connector (ch 0/X)
	OutMux1    GlitchOutput = 0x02 // OUT_MUX1    — 20-pin header (ch 1/Y)
	OutMux2    GlitchOutput = 0x03 // OUT_MUX2    — 20-pin header (ch 2/Z)
	OutExt0    GlitchOutput = 0x04 // OUT_EXT0    — EXT0 header
	OutExt1    GlitchOutput = 0x05 // OUT_EXT1    — EXT1 header
	OutNone    GlitchOutput = 0x06 // OUT_NONE    — disabled (test/ADC only)
)

// ConfigurePayloadLen is the byte length of the OpConfigure payload.
//
//	trigger_type(1) + trigger_source(1) + glitch_output(1) +
//	delay_us(4) + pulse_us(4) + power_cycle(1) + power_cycle_len(1) = 13
const ConfigurePayloadLen = 13

// StatusBlockLen is the byte length of the status payload following RespStatus.
//
//	armed(1) + last_delay_us(4) + last_outcome(1) + reserved(1) = 7
const StatusBlockLen = 7

// StatusBlock holds the parsed status response payload.
type StatusBlock struct {
	Armed        bool
	LastDelayUS  uint32
	LastOutcome  byte
	Reserved     byte
}

// OutcomeString returns a human-readable description of an Outcome constant.
func OutcomeString(o byte) string {
	switch o {
	case OutcomeNone:
		return "none"
	case OutcomeSkip:
		return "skip"
	case OutcomeCrash:
		return "crash"
	case OutcomeGlitch:
		return "glitch"
	case OutcomeOK:
		return "ok"
	default:
		return fmt.Sprintf("unknown(0x%02X)", o)
	}
}

// ErrCodeString returns a human-readable description of a device error code.
func ErrCodeString(code byte) string {
	switch code {
	case ErrNotArmed:
		return "not armed"
	case ErrInvalidParam:
		return "invalid param"
	case ErrBusy:
		return "busy"
	case ErrHWFault:
		return "hardware fault"
	default:
		return fmt.Sprintf("unknown error 0x%02X", code)
	}
}
