// Package defense provides passive RF / BLE detection helpers used to
// surface adversarial activity nearby — the blue-team complement to
// PromptZero's offensive capability set.
//
// The first capability is Wall-of-Flippers-style detection: classifying
// BLE advertisements that match the patterns produced by Flipper Zero
// devices, ESP32-Marauder-class boards running BLE-spam scripts, or any
// other Apple-Continuity-spam tooling. The detector is heuristic — false
// positives are documented per signature so an operator can adjust
// thresholds.
//
// # Architecture
//
// The package splits into:
//
//   - classifier.go        pure-Go advertisement parser + signature
//                          matcher. No I/O, easy to unit-test against
//                          fixture payloads.
//   - scanner.go           !darwin build — bridges tinygo.org/x/bluetooth
//                          BLE adapter to the classifier. Used on Linux
//                          (incl. when paired BLE access is available;
//                          WSL2 is excluded — see ble.go in
//                          internal/flipper/transport for the same
//                          rationale).
//   - scanner_darwin.go    darwin stub returning a friendly error so
//                          cross-build CI compiles cleanly. Real macOS
//                          BLE requires CGO_ENABLED=1 + native build.
//
// # Why heuristics, not signatures
//
// There is no "Flipper Zero" identifier in BLE advertisements during a
// spam attack — the Flipper deliberately rotates MAC, randomises payload
// fields, and impersonates Apple/Microsoft/Samsung devices. Detection
// works by spotting *protocol violations* in the impersonated payloads:
// the Flipper's BLE-spam library emits Apple Action types and lengths
// outside the spec's normal range, malformed Microsoft Swift Pair
// payloads with truncated UUIDs, and so on. Each [SignatureID] documents
// the exact violation it matches and cites the upstream report.
package defense
