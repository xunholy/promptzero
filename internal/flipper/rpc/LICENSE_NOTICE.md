# Licensing notice — Flipper Zero protobuf RPC

The `.proto` files under `proto/` and the generated bindings under `pb/` derive
from <https://github.com/flipperdevices/flipperzero-protobuf>, which at the
pinned upstream commit (see `proto/UPSTREAM`) ships **without a LICENSE file
and without SPDX headers**. The licensing status is therefore unspecified.

## Position taken in this repository

- The `.proto` sources are vendored verbatim **as a build-time codegen
  reference**, not as a redistributable library.
- The `.pb.go` bindings are committed for contributor convenience (so
  `go build` works without `protoc`). They are a derivative work; their
  redistributability inherits the unresolved upstream status.
- This is a **best-effort interim**. PromptZero is AGPL-3.0-or-later and
  cannot grant downstream users rights it does not itself hold.

## What this means in practice

- Operators running PromptZero locally face no realistic risk — qFlipper
  (BSD-3) and other community projects vendor the same protos, and Flipper
  Devices has not, to date, asserted rights against any consumer.
- Anyone redistributing PromptZero binaries should review their own
  position. The cleanest mitigation is to delete `pb/` and regenerate
  with `task proto:gen` at build time, treating the bindings as transient
  artefacts of the build process.

## Resolution path

Open an issue with Flipper Devices requesting a SPDX header (Apache-2.0 or
BSD-3 would both work). When a license is published:

1. Copy the upstream `LICENSE` to `proto/LICENSE`.
2. Update `proto/UPSTREAM` to remove the licensing-note paragraph.
3. Delete this file.
