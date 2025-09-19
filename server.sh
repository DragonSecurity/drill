#!/usr/bin/env bash
set -euo pipefail

REPO="DragonSecurity/drill"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
CMD_NAME="drill-server"

# Optional quick config envs (used only if you enable systemd below)
DRILL_DOMAIN="${DRILL_DOMAIN:-example.com}"
DRILL_HTTPADDR="${DRILL_HTTPADDR:-0.0.0.0:80}"
DRILL_SSHADDR="${DRILL_SSHADDR:-0.0.0.0:2200}"
DRILL_PASSWORD="${DRILL_PASSWORD:-}"

WITH_SYSTEMD="${WITH_SYSTEMD:-0}"   # set to 1 to create a systemd service on Linux

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

asset="drill-server_${os}_${arch}"
url="https://github.com/${REPO}/releases/latest/download/${asset}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "Downloading ${asset}..."
curl -fsSL -o "${tmp}/${CMD_NAME}" "$url"

chmod +x "${tmp}/${CMD_NAME}"
sudo install -m 0755 "${tmp}/${CMD_NAME}" "${INSTALL_DIR}/${CMD_NAME}"

echo "Installed ${CMD_NAME} to ${INSTALL_DIR}/${CMD_NAME}"

# Optional: create minimal config + systemd unit on Linux
if [ "$WITH_SYSTEMD" = "1" ] && [ "$os" = "linux" ]; then
  echo "Configuring systemd service..."
  sudo mkdir -p /etc/drill /var/lib/drill /var/log/drill
  if ! id drill >/dev/null 2>&1; then
    sudo useradd --system --home /var/lib/drill --shell /usr/sbin/nologin drill
  fi
  sudo chown -R drill:drill /etc/drill /var/lib/drill /var/log/drill

  cat <<YAML | sudo tee /etc/drill/drill-server.yaml >/dev/null
domain: ${DRILL_DOMAIN}
httpaddr: ${DRILL_HTTPADDR}
sshaddr: ${DRILL_SSHADDR}
log:
  filename: /var/log/drill/drill-server.log
  level: info
  max_age: 3
  max_backups: 3
  max_size: 200
  stdout: true
privatekey: /etc/drill/id_rsa
publickey: /etc/drill/id_rsa.pub
$( [ -n "$DRILL_PASSWORD" ] && echo "password: \"${DRILL_PASSWORD}\"" )
YAML

  sudo ssh-keygen -t rsa -b 4096 -N "" -f /etc/drill/id_rsa >/dev/null 2>&1 || true
  sudo chown drill:drill /etc/drill/id_rsa /etc/drill/id_rsa.pub

  cat <<'UNIT' | sudo tee /etc/systemd/system/drill-server.service >/dev/null
[Unit]
Description=Drill Tunnel Relay Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=drill
Group=drill
WorkingDirectory=/var/lib/drill
ExecStart=/usr/local/bin/drill-server -config /etc/drill/drill-server.yaml
Restart=always
RestartSec=2
LimitNOFILE=65536
Environment=GOTRACEBACK=all
StandardOutput=journal
StandardError=journal
SyslogIdentifier=drill-server

[Install]
WantedBy=multi-user.target
UNIT

  sudo systemctl daemon-reload
  sudo systemctl enable --now drill-server
  echo "drill-server systemd unit installed and started."
fi

"${INSTALL_DIR}/${CMD_NAME}" -h || true
