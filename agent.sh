#!/usr/bin/env bash
set -euo pipefail

REPO="DragonSecurity/drill"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
CMD_NAME="drill"

# Detect OS
uname_s="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$uname_s" in
  linux)   os="linux" ;;
  darwin)  os="darwin" ;;
  freebsd) os="freebsd" ;;
  *) echo "Unsupported OS: $uname_s"; exit 1 ;;
esac

# Detect ARCH
uname_m="$(uname -m)"
case "$uname_m" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  armv7l|armv7|armv6l|armv6) arch="arm" ;;
  *) echo "Unsupported architecture: $uname_m"; exit 1 ;;
esac

asset="drill_${os}_${arch}"
url="https://github.com/${REPO}/releases/latest/download/${asset}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "Downloading ${asset}..."
curl -fsSL -o "${tmp}/${CMD_NAME}" "$url"

chmod +x "${tmp}/${CMD_NAME}"
sudo install -m 0755 "${tmp}/${CMD_NAME}" "${INSTALL_DIR}/${CMD_NAME}"

echo "Installed ${CMD_NAME} to ${INSTALL_DIR}/${CMD_NAME}"
"${INSTALL_DIR}/${CMD_NAME}" -h || true
