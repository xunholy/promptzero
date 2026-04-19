# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Removed

- **BREAKING:** MQTT bridge and the `mqtt:` config block. No surveyed
  competitor shipped an equivalent and every use case MQTT covered here
  is already handled by webhooks or audit consumers. Drops the
  `github.com/eclipse/paho.mqtt.golang` dependency, the `/mqtt` REPL
  command, the `promptzero_mqtt_publishes_total` metric, and the `mqtt`
  rule-action kind + `topic` field. Migrate any MQTT subscribers to
  webhook subscriptions (`webhooks:` in config) — same payloads, same
  lifecycle events.

### Added

- Bearer-token auth on `/api`, `/metrics`, and `/ws`. Set `web.token` in
  config or `PROMPTZERO_WEB_TOKEN` in the environment; HTTP callers send
  `Authorization: Bearer <token>` and the browser passes `?token=<token>`
  on the WebSocket URL. Leaving the token empty preserves the old
  no-auth behaviour; the server prints a red warning when that combines
  with a non-loopback bind.
- `web.cors_origins` allow-list for the WebSocket Origin header. Empty
  (default) means same-origin only — the previous `*` wildcard is gone.
- `GET /api/auth` — open endpoint reporting `{"required": bool}` so the
  browser shell knows whether to prompt for a token before opening the
  WebSocket.

### Changed

- Default Claude model bumped from `claude-sonnet-4-6` to `claude-opus-4-7`
  for the agent and the vision analyzer. Existing `model:` values in
  user config override the default; cost pricer already knew about
  opus-4-7 so no math surprises.

## [0.1.0] - 2026-04-18

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
- **License: MIT → AGPL-3.0-or-later.** Aligns with the offensive-security
  tooling norm (Metasploit, Nuclei, etc.) so downstream hosted services
  must publish modifications. No change for end users running locally.

### Fixed

- CI green: resolved remaining `gofmt`, `staticcheck`, and `unused` findings
  surfaced by `golangci-lint`.

### Security

- Marauder CLI invocations now sanitise user-supplied strings before shelling
  out.
- BadUSB preflight flags unsafe payloads before execution.

[Unreleased]: https://github.com/xunholy/promptzero/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/xunholy/promptzero/releases/tag/v0.1.0
