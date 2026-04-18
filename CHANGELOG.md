# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Flipper Zero capability-gap primitives (42 new operations) with mock-backed tests.
- Operator-mode persona registry and `/persona` slash command.
- Filesystem-triggered agent mode via repeatable `--watch` paths.
- Audit query DSL: `/audit find`, `/audit tail`, `/audit top`.
- Composite workflows: `hw_recon_blackbox_device`, `nfc_badge_pipeline`,
  `garage_door_triage`, `phys_pentest_badge_walk`, `badusb_target_profile`,
  `rolljam_lab_demo`, `wifi_target_to_hashcat`.
- Structural read/edit/diff for Flipper `.sub`, `.nfc`, `.ir`, `.rfid` files.
- Outbound HTTP webhooks covering tool, risk, workflow, and audit events.
- Publish-only MQTT bridge for state and event streams.
- Structured `slog` logging with correlation IDs across REPL, agent, and audit.
- `/debug` slash command and Prometheus `/metrics` endpoint.
- Token cost tracking with offline-mode detection.
- Reactive rules engine subscribed to the audit observer.
- BadUSB sandbox preflight validator surfacing Critical/Warn/Info findings.
- BLE transport scheme reserved as a Phase-B stub.
- `--marauder-port` flag for overriding the Marauder serial device.

### Changed

- Flipper package refactored onto a `Transport` interface with a concrete
  serial implementation.
- Pty-based mock migrated to the new `Transport` interface.

### Fixed

- CI green: resolved remaining `gofmt`, `staticcheck`, and `unused` findings
  surfaced by `golangci-lint`.

### Security

- Marauder CLI invocations now sanitise user-supplied strings before shelling
  out.
- BadUSB preflight flags unsafe payloads before execution.
