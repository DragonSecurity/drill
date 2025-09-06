#!/usr/bin/env bash
set -euo pipefail
BIN_NAME="drill"
BIN_SRC="$(dirname "$0")/../${BIN_NAME}"
[[ -x "${BIN_SRC}" ]] || BIN_SRC="$(pwd)/${BIN_NAME}"
if [[ ! -x "${BIN_SRC}" ]]; then
  echo "Cannot find built binary next to this script. Run this from an extracted release archive where './drill' exists." >&2
  exit 1
fi
id -u drill >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin drill
install -Dm0755 "${BIN_SRC}" /usr/local/bin/${BIN_NAME}
if command -v setcap >/dev/null 2>&1; then setcap 'cap_net_bind_service=+ep' /usr/local/bin/${BIN_NAME} || true; fi
install -d -m 0755 /etc/drill
install -d -m 0755 /var/lib/drill
install -d -m 0755 /var/log/drill
if [[ -f "$(dirname "$0")/../configs/server.yaml" && ! -f /etc/drill/server.yaml ]]; then
  install -m 0644 "$(dirname "$0")/../configs/server.yaml" /etc/drill/server.yaml
fi
if [[ -f "$(dirname "$0")/../configs/tenants.sample.json" && ! -f /etc/drill/tenants.json ]]; then
  install -m 0640 "$(dirname "$0")/../configs/tenants.sample.json" /etc/drill/tenants.json
  chown drill:drill /etc/drill/tenants.json || true
fi
if [[ -f "$(dirname "$0")/../configs/agent.yaml" && ! -f /etc/drill/agent.yaml ]]; then
  install -m 0644 "$(dirname "$0")/../configs/agent.yaml" /etc/drill/agent.yaml
fi
if [[ ! -f /etc/drill/drill.env ]]; then
  cat >/etc/drill/drill.env <<'EOF'
# Example environment for DNS-01
#CLOUDFLARE_API_TOKEN=your-token-here
#AWS_ACCESS_KEY_ID=...
#AWS_SECRET_ACCESS_KEY=...
#AWS_REGION=us-east-1
EOF
  chmod 0640 /etc/drill/drill.env
fi
install -Dm0644 "$(dirname "$0")/drill.service" /etc/systemd/system/drill.service
systemctl daemon-reload
systemctl enable drill
systemctl restart drill
echo "✅ drill installed and started. Edit /etc/drill/server.yaml and /etc/drill/drill.env as needed."
