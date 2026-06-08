# Hosting the PromptZero web GUI with Docker

The `--web` UI ships as a self-contained container image: a single static Go
binary with the web assets compiled in (`//go:embed`), on a digest-pinned
`distroless/static:nonroot` base — no shell, no package manager, no libc, runs
as uid 65532. Images are published to GHCR for every release with an SBOM, SLSA
provenance, a GitHub build-provenance attestation, and a keyless cosign
signature (see [Verify supply-chain metadata](#verify-supply-chain-metadata)).

```
ghcr.io/xunholy/promptzero:<version>   # immutable, e.g. v0.630.0  ← pin this in prod
ghcr.io/xunholy/promptzero:<major>.<minor>
ghcr.io/xunholy/promptzero:latest
ghcr.io/xunholy/promptzero:sha-<short>
```

Platforms: `linux/amd64`, `linux/arm64`.

## Contents

- [Quick start](#quick-start)
- [Configuration (env)](#configuration-env)
- [Persisting the audit log](#persisting-the-audit-log)
- [Hardened run](#hardened-run)
- [docker compose](#docker-compose)
- [Kubernetes](#kubernetes)
- [TLS / reverse proxy](#tls--reverse-proxy)
- [Driving real hardware](#driving-real-hardware)
- [Health probes](#health-probes)
- [Verify supply-chain metadata](#verify-supply-chain-metadata)
- [Build locally](#build-locally)
- [Troubleshooting](#troubleshooting)

## Quick start

The server is **secure by default**: the image binds `0.0.0.0`, and the server
*refuses to start* on a non-loopback interface without a bearer token. Both an
Anthropic API key and a web token are therefore required:

```bash
docker run --rm -p 8080:8080 \
  -e ANTHROPIC_API_KEY=sk-ant-... \
  -e PROMPTZERO_WEB_TOKEN="$(openssl rand -hex 32)" \
  ghcr.io/xunholy/promptzero:latest
```

Open `http://localhost:8080/#token=<your-token>` — the browser reads the token
from the URL fragment and caches it in `sessionStorage`.

> The token never leaves the fragment (`#…`), so it is not sent to the server in
> the URL path/query and stays out of server and proxy access logs.

## Configuration (env)

The container is configured entirely through environment variables — no config
file needs to be mounted.

| Variable | Default | Purpose |
| --- | --- | --- |
| `ANTHROPIC_API_KEY` | — | **Required.** The web UI drives Claude. |
| `PROMPTZERO_WEB_TOKEN` | — | **Required** for the default `0.0.0.0` bind. Bearer token gating every `/api` + `/ws` request. |
| `PROMPTZERO_WEB_HOST` | `0.0.0.0` (set in image) | Bind interface. |
| `PROMPTZERO_WEB_PORT` | `8080` | Listen port. |
| `OPENAI_API_KEY` | — | Optional; only for `--voice` transcription (not used by the web UI). |
| `HOME` | `/home/nonroot` (set in image) | Root of `~/.promptzero` (audit DB, config fallback). Leave as-is. |

These map onto the same config keys documented for the binary (`web.host`,
`web.token`, …); the env vars take precedence so you never need a config file.

## Persisting the audit log

PromptZero keeps an append-only audit trail at `~/.promptzero/audit.db`
(`$HOME` is `/home/nonroot` in the image). It is written inside the container's
writable layer by default, so **it is lost when the container is removed**. To
keep it across restarts/upgrades, mount a volume on the data directory:

```bash
docker run -d --name promptzero -p 8080:8080 \
  -e ANTHROPIC_API_KEY=sk-ant-... \
  -e PROMPTZERO_WEB_TOKEN="$(openssl rand -hex 32)" \
  -v promptzero-data:/home/nonroot/.promptzero \
  ghcr.io/xunholy/promptzero:latest
```

The volume is owned by uid 65532 (the image user), so the non-root process can
write to it without any `chown`.

## Hardened run

The image is already non-root and shell-less; you can lock it down further at
runtime. The process needs no Linux capabilities (it binds 8080, a non-
privileged port) and only writes under `~/.promptzero`:

```bash
docker run -d --name promptzero -p 8080:8080 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 256 \
  --memory 512m \
  -v promptzero-data:/home/nonroot/.promptzero \
  -e ANTHROPIC_API_KEY=sk-ant-... \
  -e PROMPTZERO_WEB_TOKEN="$(openssl rand -hex 32)" \
  ghcr.io/xunholy/promptzero:latest
```

With `--read-only` the rest of the filesystem is immutable; the mounted volume
keeps `~/.promptzero` writable. For an *ephemeral* audit log under `--read-only`
swap the volume for a tmpfs: `--tmpfs /home/nonroot/.promptzero:uid=65532`.

## docker compose

```yaml
services:
  promptzero:
    image: ghcr.io/xunholy/promptzero:latest
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      ANTHROPIC_API_KEY: ${ANTHROPIC_API_KEY:?set in .env}
      PROMPTZERO_WEB_TOKEN: ${PROMPTZERO_WEB_TOKEN:?set in .env}
    volumes:
      - promptzero-data:/home/nonroot/.promptzero
    read_only: true
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true
volumes:
  promptzero-data:
```

> No `healthcheck:` is set: Compose health tests run *inside* the container, and
> distroless has no shell, `wget`, or `curl` to run one. Probe `GET /` from
> outside instead — an external uptime monitor, the reverse proxy, or (under
> Kubernetes) the kubelet HTTP probe in the manifest below.

## Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: promptzero
spec:
  replicas: 1
  selector:
    matchLabels: { app: promptzero }
  template:
    metadata:
      labels: { app: promptzero }
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        seccompProfile: { type: RuntimeDefault }
      containers:
        - name: promptzero
          image: ghcr.io/xunholy/promptzero:latest   # pin a specific version or digest in prod
          ports:
            - containerPort: 8080
          env:
            - name: ANTHROPIC_API_KEY
              valueFrom: { secretKeyRef: { name: promptzero, key: anthropic-api-key } }
            - name: PROMPTZERO_WEB_TOKEN
              valueFrom: { secretKeyRef: { name: promptzero, key: web-token } }
          securityContext:
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            capabilities: { drop: ["ALL"] }
          readinessProbe:
            httpGet: { path: /, port: 8080 }
          livenessProbe:
            httpGet: { path: /, port: 8080 }
          volumeMounts:
            - name: data
              mountPath: /home/nonroot/.promptzero
      volumes:
        - name: data
          emptyDir: {}        # swap for a PVC to persist the audit log
```

Verify the image before rollout with the supply-chain commands below (e.g. an
admission policy that runs `cosign verify` / checks the GitHub attestation).

## TLS / reverse proxy

PromptZero speaks plain HTTP. Terminate TLS in front of it — Caddy, Traefik,
nginx, or a Tailscale / Cloudflare tunnel. Minimal Caddy example:

```caddy
pz.example.com {
    reverse_proxy promptzero:8080
}
```

Keep `PROMPTZERO_WEB_TOKEN` set even behind a proxy; it is the only
authentication on `/api` and `/ws`. If the browser connects from a different
origin than the server, also set the `web.cors_origins` allow-list.

## Driving real hardware

The web UI runs fine with no device attached. To control a Flipper / Marauder
from the container, pass the USB serial device through (this needs host access to
the device node, so it does not combine with a fully locked-down sandbox):

```bash
docker run --rm -p 8080:8080 \
  --device=/dev/ttyACM0 \
  -e ANTHROPIC_API_KEY=sk-ant-... \
  -e PROMPTZERO_WEB_TOKEN=... \
  ghcr.io/xunholy/promptzero:latest
```

## Health probes

distroless has no shell, so the image declares no `HEALTHCHECK`. Probe the HTTP
port directly — `GET /` serves the SPA without auth and returns `200`:

```yaml
# docker-compose / k8s readiness probe
httpGet: { path: /, port: 8080 }
```

## Verify supply-chain metadata

```bash
# GitHub build-provenance attestation
gh attestation verify oci://ghcr.io/xunholy/promptzero:latest -R xunholy/promptzero

# Keyless cosign signature
cosign verify ghcr.io/xunholy/promptzero:latest \
  --certificate-identity-regexp 'https://github.com/xunholy/promptzero/\.github/workflows/release\.yaml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# SBOM + SLSA provenance attestations attached by buildx
docker buildx imagetools inspect ghcr.io/xunholy/promptzero:latest \
  --format '{{ json .SBOM }}'
docker buildx imagetools inspect ghcr.io/xunholy/promptzero:latest \
  --format '{{ json .Provenance }}'
```

> The SBOM is a BuildKit in-toto attestation (from `sbom: true` in the release
> workflow), so it is read with `buildx imagetools` as above — `cosign download
> sbom` does **not** find it (that command only reads the legacy `cosign attach
> sbom` tag, which this pipeline does not use).

## Build locally

Single-platform image loaded into the local Docker store for testing:

```bash
docker buildx build --platform linux/amd64 \
  --build-arg VERSION="$(git describe --tags --always)" \
  --build-arg COMMIT="$(git rev-parse --short HEAD)" \
  -t promptzero:dev --load .
```

> Multi-arch (`--platform linux/amd64,linux/arm64`) **cannot** be combined with
> `--load` — the docker exporter can't load a manifest list. For multi-arch,
> `--push` to a registry or export with `-o type=oci,dest=image.tar`.

## Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| Container exits immediately, logs `refusing to bind … without an auth token` | `PROMPTZERO_WEB_TOKEN` is unset while bound to `0.0.0.0` (the default). Set a token. |
| Exits with an Anthropic API-key error | `ANTHROPIC_API_KEY` is required for `--web`. Set it. |
| UI loads but every `/api` call is 401 | Token mismatch — open `…/#token=<token>` so the browser caches the right one. |
| Audit log empty after restart | The audit DB is ephemeral without a volume — mount `…:/home/nonroot/.promptzero`. |
| `docker buildx build --platform …,… --load` errors on a manifest list | Use a single `--platform` with `--load`, or `--push` for multi-arch (see above). |
| WebSocket fails cross-origin | Set `web.cors_origins` to the browser's origin (env: mount a config, or use a same-origin reverse proxy). |
