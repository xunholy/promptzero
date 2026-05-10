// Package adversarial holds the cross-package adversarial test suite
// (roadmap P3-30). Each test seeds an attacker-shaped input — a
// prompt-injection payload inside an SSID, a malformed Marauder line,
// an ANSI escape sequence in a tool result — and asserts the agent's
// safety contract holds:
//
//   - structured parser fields (BSSID, MAC, RSSI, Channel) stay clean
//     even when the free-text fields they sit alongside (SSID, Probe,
//     Name) carry injection payloads;
//   - tool output that reaches the model is wrapped in
//     <untrusted-hardware-output> tags so the system-prompt clause can
//     route the content as data rather than instructions;
//   - control characters (ANSI CSI escapes, raw NULs, BEL/etc.) are
//     stripped before the wrapped output ever reaches the model.
//
// Existing per-package injection tests pin individual surfaces in
// isolation; this directory pins the *combined* contract — parser
// then quarantine then sanitiser — against a single attacker corpus
// so a regression in any layer surfaces as a centralised CI failure.
//
// The corpus deliberately overlaps the per-package tests rather than
// replacing them: belt-and-braces. A change that bypasses the parser
// guard but accidentally wraps the output correctly should still
// fail here, and vice versa.
//
// Complementary to the P0-06 quarantine layer + the parser-security
// parity sweep (CHANGELOG v0.51). Net new contribution is the unified
// corpus and the assertion that every named hardware tool routes
// through the wrapper before its output reaches the model.
package adversarial
