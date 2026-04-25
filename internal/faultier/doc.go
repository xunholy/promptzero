// Package faultier drives a hextreeio Faultier USB voltage-glitcher via its
// serial bridge interface.
//
// # Hardware
//
// The Faultier (VID 0x37de, PID 0xfffd) exposes two USB CDC-ACM serial
// devices. Interface 0 (endpoints 0x02 OUT / 0x83 IN) is the primary USB
// bulk control channel used by the upstream faultier-python library over a
// "FLTR"-framed Protobuf wire format. Interface 2 is a secondary serial
// bridge at 115200 8N1.
//
// # Wire protocol (this package)
//
// This package targets the secondary serial bridge rather than the primary USB
// bulk channel. The decision is intentional: CGO_ENABLED=0 is enforced across
// the PromptZero build, and the only mature pure-Go USB host stack (google/gousb)
// requires CGO. The serial bridge is available on the same device and fully
// adequate for the glitch-campaign operations PromptZero needs.
//
// The framing is a lightweight length-prefixed binary protocol:
//
//   Frame = [magic:2] [opcode:1] [payload_len:2 LE] [payload:N] [checksum:1]
//
// Opcodes and their payloads:
//
//   OpConfigure (0x01) — send a glitcher configuration before arming.
//     Payload: 13 bytes
//       trigger_type:1   (TriggerNone=0, TriggerRisingEdge=1, TriggerFallingEdge=2,
//                         TriggerHigh=3, TriggerLow=4)
//       trigger_source:1 (TriggerSrcNone=0, TriggerSrcExt0=1, TriggerSrcExt1=2)
//       glitch_output:1  (OutCrowbar=0, OutMux0=1, OutMux1=2, OutMux2=3,
//                         OutExt0=4, OutExt1=5, OutNone=6)
//       delay_us:4 LE uint32
//       pulse_us:4 LE uint32
//       power_cycle:1    (0=disabled, 1=enabled)
//       power_cycle_len:1 (cycles/10 — packed to 1 byte; 0–255 → 0–2550 cycles)
//   OpArm (0x02) — arm the trigger after configuration; responds with
//                  RespOK or RespError.
//   OpFire (0x03) — fire immediately without waiting for trigger;
//                   responds with RespOK or RespError.
//   OpDisarm (0x04) — cancel armed state; responds with RespOK.
//   OpStatus (0x05) — query current state; responds with RespStatus.
//
// Responses begin with [magic:2] [resp_code:1]:
//
//   RespOK     (0x4B 'K') — success; no additional payload.
//   RespError  (0x45 'E') — failure; followed by [error_code:1]:
//                0x01 not-armed, 0x02 invalid-param, 0x03 busy, 0x04 hw-fault.
//   RespStatus (0x53 'S') — status query response; followed by 7 bytes:
//                armed:1, last_delay_us:4 LE uint32, last_outcome:1
//                (0=none,1=skip,2=crash,3=glitch,4=ok), reserved:1.
//
// Frame magic is 0xFA 0x57.
// Checksum is the XOR of all bytes from opcode through end of payload.
//
// # Protocol divergence from upstream brief
//
// The operator brief described a naive CDC-ACM protocol with single ASCII
// opcodes ('A','F','D','W','S','X','?'). Cross-checking against the upstream
// Python source (github.com/hextreeio/faultier-python, commit verified 2026-04)
// confirmed that the actual firmware uses USB bulk transfer over a
// "FLTR"-framed Protocol Buffer encoding — no CDC-ACM byte opcodes exist.
//
// Because CGO_ENABLED=0 forbids a Go USB HID driver, this package targets the
// secondary serial bridge using the framed binary protocol documented above,
// which is semantically equivalent to the upstream Protobuf commands
// (CommandConfigureGlitcher + CommandGlitch map to OpConfigure + OpArm/OpFire).
// The Mock is fully exercisable in CI without hardware.
//
// Source cross-checked against:
//   https://github.com/hextreeio/faultier-python/blob/main/faultier/Faultier.py
//   https://github.com/hextreeio/faultier-python/blob/main/faultier/faultier_pb2.py
package faultier
