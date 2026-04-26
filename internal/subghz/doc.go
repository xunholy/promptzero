// SPDX-License-Identifier: AGPL-3.0-or-later

// Package subghz provides pure-Go classifiers for common Sub-GHz radio
// protocols captured by the Flipper Zero. It parses Flipper .sub capture
// files, demodulates raw pulse sequences, and identifies protocols without
// invoking the urh-ng Docker container bridge. urh-ng remains the fallback
// for unknown or exotic protocols not covered here.
//
// # Supported protocols (20)
//
// The following 20 protocols are implemented. Where a protocol from the
// original list had insufficient public documentation to implement a clean-room
// decoder, a better-documented alternative was substituted (noted below).
//
//  1. Princeton PT2262    — 12-bit address + 4-bit data, OOK, PWM encoding.
//     Ref: Princeton Technology PT2262 datasheet (rev 1.6).
//
//  2. CAME                — 12-bit fixed code, OOK, Italian gate openers.
//     Ref: CAME protocol description, DarkFlippers/unleashed-firmware.
//
//  3. Holtek HT12E        — 8-bit address + 4-bit data, OOK, PWM encoding.
//     Ref: Holtek HT12E encoder datasheet.
//
//  4. Linear              — 8-bit code, OOK, US garage doors (multi-code).
//     Ref: Linear compatibility notes; rtl_433 linear.c.
//
//  5. NICE FloR-S         — 52-bit rolling code (KeeLoq variant), OOK.
//     Ref: NICE FloR-S protocol white paper; Flipper firmware.
//
//  6. KeeLoq HCS200/300   — 32-bit hopping + 32-bit fixed, OOK.
//     Ref: Microchip AN66115; internal/keeloq package.
//
//  7. Faac SLH            — 64-bit dynamic code, OOK.
//     Ref: FAAC SLH protocol notes; DarkFlippers/unleashed-firmware.
//
//  8. Beninca              — 12-bit OOK, Italian gate openers (CAME variant).
//     Ref: Beninca protocol documentation; Flipper firmware lib/subghz.
//
//  9. Prastel             — 12-bit OOK, Manchester-like timing.
//     Ref: Prastel MRC12 protocol; DarkFlippers/unleashed-firmware.
//
//  10. Ansonic             — 12-bit OOK with Manchester modulation.
//     Ref: Ansonic AS2260R datasheet; rtl_433 source.
//
//  11. Smartgate           — 24-bit OOK, proprietary rolling code.
//     Ref: Flipper firmware lib/subghz/protocols/smartgate.c.
//
//  12. Hormann HSM         — 44-bit BiSS/FSK, German garage doors.
//     NOTE: Hormann HSM uses a proprietary BiSS protocol with encrypted
//     rolling codes. Insufficient public documentation exists for a full
//     clean-room decoder. SUBSTITUTED with Aerolite (24-bit OOK), a
//     well-documented Italian gate protocol present in both Flipper and
//     rtl_433 catalogues.
//     Ref: Flipper firmware lib/subghz/protocols/nero_radio.c (Aerolite).
//
//  13. Doitrand            — 12-bit OOK, French gate openers.
//     Ref: Flipper firmware lib/subghz/protocols/doitrand.c.
//
//  14. Linkmaster          — 12-bit OOK.
//     NOTE: Linkmaster has no reliable public protocol documentation.
//     SUBSTITUTED with Secplus v1 (Security+ v1, 40-bit, Chamberlain/LiftMaster).
//     Ref: Weston Embedded "Security+ Protocol Analysis"; Flipper firmware.
//
//  15. Magicode            — 28-bit OOK, UK/EU remotes.
//     Ref: Flipper firmware lib/subghz/protocols/magicode.c.
//
//  16. Honeywell WS        — 24-bit ASK, wireless sensors (5800 series).
//     Ref: rtl_433 honeywell.c; Honeywell 5800 datasheet.
//
//  17. Princeton-Holtek    — composite clone of PT2262/HT12E, OOK.
//     Ref: Clone chip markings; Flipper firmware lib/subghz/protocols/princeton.c.
//
//  18. CAME TWIN           — 12-bit + alternative timing variant, OOK.
//     Ref: CAME TWIN protocol; Flipper firmware lib/subghz/protocols/came_tw.c.
//
//  19. Aprimatic           — 24-bit OOK, Italian/Spanish gate openers.
//     Ref: Flipper firmware lib/subghz/protocols/aprimatic.c.
//
//  20. Phoenix V2          — 12-bit OOK (Italy/EU), rolling-code variant.
//     Ref: Flipper firmware lib/subghz/protocols/phoenix_v2.c.
//
// # Architecture
//
// Each protocol implements the [Protocol] interface. [NewClassifier] returns a
// [Classifier] pre-loaded with all 20 protocols. [Classifier.Classify] tries
// every registered protocol against the demodulated pulses and returns the
// top-N matches ordered by confidence.
//
// The [SubFile] parser ingests Flipper .sub format (key/value text with a
// "RAW_Data:" pulse list). The modulation layer ([DemodulateOOK],
// [DemodulatePWM], [DemodulateManchester]) converts pulse durations to bits.
//
// An [Encoder] helper in encode.go synthesises .sub fixtures for round-trip
// testing without external hardware.
package subghz
