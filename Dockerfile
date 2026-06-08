# syntax=docker/dockerfile:1
#
# PromptZero web GUI container.
#
# Hosts the `--web` UI (internal/web): a self-contained Go HTTP server with its
# static assets compiled in via //go:embed, so the runtime image is a single
# static binary + CA certs — no Node, no asset volume, no shell.
#
# The image runs the GUI without any Flipper/Marauder attached (the web mode is
# explicitly allowed to start with no device). To drive real hardware, pass the
# USB device through at runtime, e.g. `docker run --device=/dev/ttyACM0 ...`.
#
# Required runtime env (the server fails closed without them):
#   ANTHROPIC_API_KEY    — the web UI drives Claude, so a key is required.
#   PROMPTZERO_WEB_TOKEN — the server refuses to bind non-loopback (0.0.0.0,
#                          the image default) without a bearer token.
#
# Build (multi-arch, from the repo root):
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     --build-arg VERSION=$(git describe --tags --always) \
#     --build-arg COMMIT=$(git rev-parse --short HEAD) -t promptzero:dev .

ARG GO_VERSION=1.25.11

# --- builder ----------------------------------------------------------------
# Pinned to the same Go toolchain as the Taskfile / release workflow. Built on
# $BUILDPLATFORM and cross-compiled to $TARGETPLATFORM so multi-arch builds run
# natively on the runner instead of under slow QEMU emulation.
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-bookworm AS builder

# buildx injects these per target platform.
ARG TARGETOS
ARG TARGETARCH

# Stamped into internal/version, matching release.yaml's ldflags.
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

WORKDIR /src

# Resolve modules in a cached layer separate from the source tree so code-only
# edits don't re-download the dependency graph.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

# CGO disabled: the linux build is pure Go (BLE/CoreBluetooth is darwin-only),
# yielding a static binary that runs on the distroless/scratch runtime. The
# build + module caches are mounted to keep rebuilds fast.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath \
      -ldflags="-s -w \
        -X github.com/xunholy/promptzero/internal/version.Version=${VERSION} \
        -X github.com/xunholy/promptzero/internal/version.Commit=${COMMIT} \
        -X github.com/xunholy/promptzero/internal/version.Date=${DATE}" \
      -o /out/promptzero ./cmd/promptzero

# --- runtime ----------------------------------------------------------------
# distroless/static: no shell, no package manager, no libc — minimal attack
# surface. The :nonroot variant runs as uid/gid 65532 and ships CA certificates
# (required for the Anthropic API over HTTPS) and tzdata. Digest-pinned (the
# tag is kept for readability and for Renovate to bump) so the base is
# reproducible and tamper-evident; bump the digest deliberately.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:d093aa3e30dbadd3efe1310db061a14da60299baff8450a17fe0ccc514a16639

# OCI metadata (overridden/augmented by docker/metadata-action in CI).
LABEL org.opencontainers.image.source="https://github.com/xunholy/promptzero" \
      org.opencontainers.image.description="PromptZero web GUI" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"

COPY --from=builder /out/promptzero /usr/local/bin/promptzero

# The distroless base leaves $HOME unset, so set it to the nonroot user's home
# (uid 65532, writable). PromptZero derives ~/.promptzero from $HOME — without
# this the audit DB (~/.promptzero/audit.db) and the config fallback path fail
# to resolve and the security audit trail silently no-ops. Mount a volume on
# /home/nonroot/.promptzero to persist the audit log (see docs/deploy/docker.md).
ENV HOME=/home/nonroot

# Bind to all interfaces inside the container (the host publishes the port).
# Combined with the server's fail-closed check this means the container will
# not start until PROMPTZERO_WEB_TOKEN is also set — secure by default.
ENV PROMPTZERO_WEB_HOST=0.0.0.0 \
    PROMPTZERO_WEB_PORT=8080
EXPOSE 8080

# Already nonroot via the base image; stated explicitly for auditability.
USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/promptzero", "--web"]
