#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# install.sh — install, upgrade, or remove the promptzero CLI.
#
# Usage:
#   sh install.sh                         Install the latest release.
#   sh install.sh upgrade                 Upgrade to the latest release.
#   sh install.sh uninstall               Remove promptzero from --prefix.
#   sh install.sh --version vX.Y.Z        Pin a specific release.
#   sh install.sh --prefix <dir>          Install directory (see below).
#   sh install.sh --help                  This text.
#
# Environment overrides:
#   PROMPTZERO_VERSION   Same effect as --version.
#   PROMPTZERO_PREFIX    Same effect as --prefix.
#
# Install directory resolution (first writable wins):
#   1. --prefix / PROMPTZERO_PREFIX
#   2. $XDG_BIN_HOME
#   3. $HOME/.local/bin
#   4. /usr/local/bin
#
# Supports Linux and macOS on amd64/arm64. Windows users should download
# the .zip from https://github.com/xunholy/promptzero/releases.
#
# Requires: sh, curl, tar, sha256sum (Linux) or shasum (macOS).

set -eu

REPO="xunholy/promptzero"
BINARY="promptzero"
CLEANUP_TMP=""

cleanup() {
  if [ -n "${CLEANUP_TMP:-}" ] && [ -d "${CLEANUP_TMP}" ]; then
    rm -rf "${CLEANUP_TMP}"
  fi
}
trap cleanup EXIT INT TERM

log()  { printf '%s\n' "$*" >&2; }
info() { printf '\033[36m▸\033[0m %s\n' "$*" >&2; }
ok()   { printf '\033[32m✓\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[33m!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m✗\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  # Print the doc banner (contiguous leading `#` lines after the SPDX
  # marker). Extracting from $0 keeps the help text and the source in
  # sync without a second heredoc to maintain.
  awk 'NR==1 {next}
       /^# SPDX/ {next}
       /^#!/ {next}
       /^#/ {sub(/^# ?/,""); print; next}
       {exit}' "$0"
}

# --- Argument parsing ---------------------------------------------------

CMD=""
VERSION="${PROMPTZERO_VERSION:-}"
PREFIX="${PROMPTZERO_PREFIX:-}"

while [ $# -gt 0 ]; do
  case "$1" in
    install|upgrade|uninstall)
      [ -n "$CMD" ] && die "multiple subcommands given (saw '$CMD' then '$1')"
      CMD="$1"
      ;;
    --version)
      shift
      [ $# -gt 0 ] || die "--version needs a value"
      VERSION="$1"
      ;;
    --version=*) VERSION="${1#--version=}" ;;
    --prefix)
      shift
      [ $# -gt 0 ] || die "--prefix needs a value"
      PREFIX="$1"
      ;;
    --prefix=*)  PREFIX="${1#--prefix=}" ;;
    -h|--help)   usage; exit 0 ;;
    *)           usage >&2; die "unknown argument: $1" ;;
  esac
  shift
done
CMD="${CMD:-install}"

# --- Dependencies & platform detection ---------------------------------

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

sha256_of() {
  # Portable SHA-256: GNU coreutils uses sha256sum, macOS uses shasum.
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    die "need sha256sum or shasum for checksum verification"
  fi
}

detect_platform() {
  os="$(uname -s 2>/dev/null | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m 2>/dev/null)"
  case "$os" in
    linux)  OS=linux ;;
    darwin) OS=darwin ;;
    mingw*|msys*|cygwin*)
      die "Windows is not supported by install.sh — download the .zip from https://github.com/${REPO}/releases"
      ;;
    *) die "unsupported OS: $os" ;;
  esac
  case "$arch" in
    x86_64|amd64)   ARCH=amd64 ;;
    aarch64|arm64)  ARCH=arm64 ;;
    *) die "unsupported architecture: $arch (expected amd64 or arm64)" ;;
  esac
}

# --- Install-dir resolution --------------------------------------------

# writable_dir checks whether a directory exists and is writable, or
# can be created under a writable parent. Returns 0 on match.
writable_dir() {
  d="$1"
  [ -z "$d" ] && return 1
  if [ -d "$d" ] && [ -w "$d" ]; then return 0; fi
  parent="$(dirname "$d")"
  [ -d "$parent" ] && [ -w "$parent" ]
}

resolve_prefix() {
  if [ -n "$PREFIX" ]; then
    printf '%s' "$PREFIX"
    return
  fi
  for d in "${XDG_BIN_HOME:-}" "$HOME/.local/bin" "/usr/local/bin"; do
    if writable_dir "$d"; then
      printf '%s' "$d"
      return
    fi
  done
  die "no writable install dir found — try: sh install.sh --prefix ~/bin"
}

# --- Version resolution -------------------------------------------------

normalise_version() {
  v="$1"
  case "$v" in
    v*) printf '%s' "$v" ;;
    *)  printf 'v%s' "$v" ;;
  esac
}

# latest_version follows the /releases/latest redirect on github.com and
# pulls the tag off the end of the final URL. Unauthenticated, no rate
# limit, no JSON parsing — unlike the REST API path.
latest_version() {
  url="$(curl -fsSIL -o /dev/null -w '%{url_effective}' \
         "https://github.com/${REPO}/releases/latest" 2>/dev/null)" \
    || die "failed to resolve latest version (network error)"
  tag="${url##*/}"
  case "$tag" in
    v*) printf '%s' "$tag" ;;
    *)  die "couldn't resolve latest release (redirect url: $url)" ;;
  esac
}

resolve_version() {
  if [ -n "$VERSION" ]; then
    normalise_version "$VERSION"
    return
  fi
  latest_version
}

# --- Installed-version introspection -----------------------------------

# current_version runs `promptzero --version` and extracts the leading
# token. Returns empty on any failure so callers can treat "not installed"
# and "broken install" the same way.
current_version() {
  bin="$1"
  [ -x "$bin" ] || return 0
  "$bin" --version 2>/dev/null | awk '{print $2; exit}'
}

# --- PATH hint ----------------------------------------------------------

check_path() {
  dir="$1"
  case ":${PATH:-}:" in
    *":${dir}:"*) return 0 ;;
  esac
  warn "${dir} is not on your PATH."
  log  ""
  log  "    Add this to your shell profile (~/.bashrc, ~/.zshrc, ~/.profile):"
  log  ""
  log  "        export PATH=\"${dir}:\$PATH\""
  log  ""
}

# --- Commands -----------------------------------------------------------

do_install() {
  detect_platform
  need_cmd curl
  need_cmd tar

  prefix="$(resolve_prefix)"
  target="$(resolve_version)"
  bin_path="${prefix}/${BINARY}"
  current="$(current_version "$bin_path" 2>/dev/null || true)"

  info "target : ${target}"
  info "host   : ${OS}/${ARCH}"
  info "prefix : ${prefix}"
  if [ -n "$current" ]; then
    info "current: ${current}"
  fi

  if [ "$CMD" = "upgrade" ] && [ -n "$current" ] && [ "$current" = "$target" ]; then
    ok "already at ${target} — nothing to do"
    return
  fi

  asset="${BINARY}-${OS}-${ARCH}.tar.gz"
  base="https://github.com/${REPO}/releases/download/${target}"

  CLEANUP_TMP="$(mktemp -d 2>/dev/null || mktemp -d -t promptzero)"

  info "downloading ${asset}"
  curl -fsSL -o "${CLEANUP_TMP}/${asset}" "${base}/${asset}" \
    || die "download failed: ${base}/${asset}"
  info "downloading checksums.txt"
  curl -fsSL -o "${CLEANUP_TMP}/checksums.txt" "${base}/checksums.txt" \
    || die "download failed: ${base}/checksums.txt"

  info "verifying sha256"
  expected="$(awk -v f="$asset" '$2 == f || $2 == "*"f {print $1; exit}' \
              "${CLEANUP_TMP}/checksums.txt")"
  [ -n "$expected" ] || die "no checksum entry for ${asset} in checksums.txt"
  got="$(sha256_of "${CLEANUP_TMP}/${asset}")"
  if [ "$got" != "$expected" ]; then
    die "checksum mismatch for ${asset}
  expected: ${expected}
  got:      ${got}"
  fi

  info "extracting"
  ( cd "${CLEANUP_TMP}" && tar xzf "${asset}" )
  src="${CLEANUP_TMP}/${BINARY}-${OS}-${ARCH}"
  [ -f "$src" ] || die "binary '${BINARY}-${OS}-${ARCH}' not found after extract"
  chmod +x "$src"

  info "installing to ${bin_path}"
  mkdir -p "$prefix"
  mv "$src" "$bin_path"

  # Sanity-check the freshly installed binary. A mismatch usually means
  # the release assets were built from the wrong commit — fail loudly.
  got_ver="$(current_version "$bin_path" 2>/dev/null || true)"
  if [ -n "$got_ver" ] && [ "$got_ver" != "$target" ]; then
    warn "installed binary reports ${got_ver}, expected ${target}"
  fi

  ok "installed ${BINARY} ${target} → ${bin_path}"
  check_path "$prefix"
}

do_uninstall() {
  prefix="$(resolve_prefix)"
  bin_path="${prefix}/${BINARY}"
  if [ ! -e "$bin_path" ]; then
    ok "${bin_path} not present — nothing to uninstall"
    return
  fi
  rm -f "$bin_path"
  ok "removed ${bin_path}"
}

case "$CMD" in
  install|upgrade) do_install ;;
  uninstall)       do_uninstall ;;
  *)               usage; exit 2 ;;
esac
