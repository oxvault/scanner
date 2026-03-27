#!/bin/sh
# Oxvault Scanner installer
# Usage: curl -fsSL https://oxvault.dev/install.sh | sh
#
# Detects OS/arch, downloads the latest release from GitHub, verifies the
# checksum, and installs the binary to /usr/local/bin (or ~/.local/bin).

set -e

REPO="oxvault/scanner"
BINARY="oxvault"
INSTALL_DIR="/usr/local/bin"

# ── Helpers ─────────────────────────────────────────────────────────────────

info()  { printf "\033[1;32m==> %s\033[0m\n" "$1"; }
warn()  { printf "\033[1;33m==> %s\033[0m\n" "$1"; }
error() { printf "\033[1;31mError: %s\033[0m\n" "$1" >&2; exit 1; }

need() {
  command -v "$1" >/dev/null 2>&1 || error "$1 is required but not installed"
}

# ── Detect platform ─────────────────────────────────────────────────────────

detect_os() {
  case "$(uname -s)" in
    Linux*)  echo "linux" ;;
    Darwin*) echo "darwin" ;;
    MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
    *) error "Unsupported OS: $(uname -s)" ;;
  esac
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)  echo "amd64" ;;
    aarch64|arm64)  echo "arm64" ;;
    *) error "Unsupported architecture: $(uname -m)" ;;
  esac
}

# ── Resolve latest version ──────────────────────────────────────────────────

get_latest_version() {
  need curl
  curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' \
    | head -1 \
    | sed 's/.*"v\([^"]*\)".*/\1/'
}

# ── Main ────────────────────────────────────────────────────────────────────

main() {
  need curl

  OS="$(detect_os)"
  ARCH="$(detect_arch)"
  VERSION="${OXVAULT_VERSION:-$(get_latest_version)}"

  if [ -z "$VERSION" ]; then
    error "Could not determine latest version. Set OXVAULT_VERSION=x.y.z to install a specific version."
  fi

  info "Installing oxvault v${VERSION} (${OS}/${ARCH})"

  # Build download URL
  if [ "$OS" = "windows" ]; then
    ARCHIVE="scanner_${VERSION}_${OS}_${ARCH}.zip"
  else
    ARCHIVE="scanner_${VERSION}_${OS}_${ARCH}.tar.gz"
  fi
  URL="https://github.com/${REPO}/releases/download/v${VERSION}/${ARCHIVE}"
  CHECKSUM_URL="https://github.com/${REPO}/releases/download/v${VERSION}/checksums.txt"

  # Create temp directory
  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' EXIT

  # Download archive and checksums
  info "Downloading ${ARCHIVE}..."
  curl -fsSL -o "${TMP}/${ARCHIVE}" "$URL" || error "Download failed. Check that v${VERSION} exists at ${URL}"
  curl -fsSL -o "${TMP}/checksums.txt" "$CHECKSUM_URL" || warn "Could not download checksums — skipping verification"

  # Verify checksum
  if [ -f "${TMP}/checksums.txt" ]; then
    EXPECTED="$(grep "${ARCHIVE}" "${TMP}/checksums.txt" | awk '{print $1}')"
    if [ -n "$EXPECTED" ]; then
      if command -v sha256sum >/dev/null 2>&1; then
        ACTUAL="$(sha256sum "${TMP}/${ARCHIVE}" | awk '{print $1}')"
      elif command -v shasum >/dev/null 2>&1; then
        ACTUAL="$(shasum -a 256 "${TMP}/${ARCHIVE}" | awk '{print $1}')"
      else
        warn "No sha256sum or shasum found — skipping checksum verification"
        ACTUAL="$EXPECTED"
      fi

      if [ "$ACTUAL" != "$EXPECTED" ]; then
        error "Checksum mismatch! Expected ${EXPECTED}, got ${ACTUAL}"
      fi
      info "Checksum verified"
    fi
  fi

  # Extract
  info "Extracting..."
  if [ "$OS" = "windows" ]; then
    need unzip
    unzip -q "${TMP}/${ARCHIVE}" -d "${TMP}/extracted"
  else
    tar -xzf "${TMP}/${ARCHIVE}" -C "${TMP}"
  fi

  # Find the binary
  BIN_PATH="${TMP}/${BINARY}"
  if [ ! -f "$BIN_PATH" ]; then
    # Some archives nest in a directory
    BIN_PATH="$(find "${TMP}" -name "${BINARY}" -type f | head -1)"
  fi

  if [ ! -f "$BIN_PATH" ]; then
    error "Could not find ${BINARY} binary in archive"
  fi

  chmod +x "$BIN_PATH"

  # Install — try /usr/local/bin first, fall back to ~/.local/bin
  if [ -w "$INSTALL_DIR" ] || [ "$(id -u)" = "0" ]; then
    mv "$BIN_PATH" "${INSTALL_DIR}/${BINARY}"
    info "Installed to ${INSTALL_DIR}/${BINARY}"
  elif command -v sudo >/dev/null 2>&1; then
    sudo mv "$BIN_PATH" "${INSTALL_DIR}/${BINARY}"
    info "Installed to ${INSTALL_DIR}/${BINARY} (via sudo)"
  else
    INSTALL_DIR="${HOME}/.local/bin"
    mkdir -p "$INSTALL_DIR"
    mv "$BIN_PATH" "${INSTALL_DIR}/${BINARY}"
    info "Installed to ${INSTALL_DIR}/${BINARY}"
    case ":$PATH:" in
      *":${INSTALL_DIR}:"*) ;;
      *) warn "Add ${INSTALL_DIR} to your PATH: export PATH=\"${INSTALL_DIR}:\$PATH\"" ;;
    esac
  fi

  # Verify
  if command -v "$BINARY" >/dev/null 2>&1; then
    info "Done! Run 'oxvault scan github:owner/repo' to get started."
  else
    info "Done! Binary at ${INSTALL_DIR}/${BINARY}"
  fi
}

main
