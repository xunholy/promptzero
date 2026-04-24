// Package containerbridge runs external CLI tools inside Docker containers
// and surfaces their output as Go values. It is the shared substrate for
// the urh_*, firmware_extract, and fap_build Spec families — any Spec
// that wants to hand work off to a maintained third-party CLI without
// reimplementing it in Go.
//
// # Why Docker
//
// Each external tool ships its own dependency graph (urh-ng wants Python +
// PyQt + scientific Python; ufbt wants the Flipper SDK + a pinned
// Python/clang chain; unblob wants ~30 extractor binaries). Pinning these
// on the host runs counter to PromptZero's "bring your own toolchain"
// posture. Docker images give a hermetic, version-pinned runtime that the
// operator can mirror to a private registry for air-gapped engagements.
//
// # Concurrency
//
// Each [Run] spawns a fresh container; multiple parallel calls are safe.
// The package keeps no shared state — config-by-call.
//
// # Failure modes
//
// Run returns:
//
//   - a *RunError with .ExitCode != 0 when the container ran but the
//     containerised tool exited non-zero (i.e. the Spec should report
//     a tool error to the agent);
//   - a wrapped error when Docker itself failed (binary missing, image
//     pull required network, daemon unreachable). Spec handlers should
//     surface these distinctly so the operator can fix the host
//     toolchain.
package containerbridge
